"""Central job scheduler (spec: JOB SCHEDULER).

A worker thread picks the highest-priority QUEUED job (up to
``max_concurrent_jobs``), builds the validated command via the adapter,
executes it, parses the output and stores the structured result.

In-flight processes are tracked so they can be paused (SIGSTOP), resumed
(SIGCONT) and cancelled (SIGKILL), and jobs interrupted by a crash are
marked FAILED on recovery (never blindly resumed).
"""
from __future__ import annotations

import signal
import subprocess
import threading
import time
from typing import Optional

from ksec.adapters.base import CommandRequest
from ksec.adapters.registry import AdapterRegistry
from ksec.config.loader import KsecConfig
from ksec.audit.service import AuditService
from ksec.core.errors import KSECError
from ksec.db.connection import Database
from ksec.jobs.models import Job, JobRepository
from ksec.identity.users import now_utc
from ksec.scheduler.schedules import ScheduleStore, cron_matches

_STDOUT_LIMIT = 100_000
_STDERR_LIMIT = 10_000
_RATE_WINDOW_SECONDS = 60.0


class Scheduler:
    def __init__(
        self,
        db: Database,
        config: KsecConfig,
        adapters: AdapterRegistry | None = None,
        plugin_manager=None,
        audit: AuditService | None = None,
    ):
        self.db = db
        self.config = config
        self.audit = audit
        self.adapters = adapters or AdapterRegistry()
        self.plugin_manager = plugin_manager
        self.jobs = JobRepository(db)
        self.schedules = ScheduleStore(db)
        # Optional hook for automatic IOC extraction from job evidence.
        # Assigned by bootstrap after the threat-intel service exists.
        self.intel_service = None
        self._threads: dict[str, threading.Thread] = {}
        self._procs: dict[str, subprocess.Popen] = {}
        self._cancel_flags: dict[str, bool] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._worker: threading.Thread | None = None
        # Emergency stop (spec 06#32, 07#79): when set, no new jobs may be
        # submitted and all non-terminal jobs are cancelled. The flag is
        # persisted in system_state so it survives process restarts.
        self._emergency_stop = threading.Event()
        self._restore_stop()
        # Sliding-window rate limiting (spec 06#34): timestamps of recent
        # submissions, global and per-user.
        self._submit_times: list[float] = []
        self._user_submit_times: dict[str, list[float]] = {}
        self._rate_blocked: dict[str, float] = {}  # user -> blocked-until (epoch)

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._worker is None or not self._worker.is_alive():
            self._stop.clear()
            self._worker = threading.Thread(target=self._loop, daemon=True)
            self._worker.start()

    def stop(self, join_timeout: float = 10.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._worker is not None:
            self._worker.join(timeout=join_timeout)
            self._worker = None

    # -- emergency stop ---------------------------------------------------

    def _persist_stop(self, active: bool) -> None:
        """Persist the emergency-stop flag so it survives process restarts."""
        try:
            row = self.db.query_one("SELECT name FROM sqlite_master WHERE type='table' AND name='system_state'")
            if row is None:
                return
            if active:
                self.db.execute(
                    "INSERT OR REPLACE INTO system_state (key, value) VALUES ('emergency_stop', '1')"
                )
            else:
                self.db.execute("DELETE FROM system_state WHERE key = 'emergency_stop'")
        except Exception:  # noqa: BLE001 - persistence must never break a stop
            pass

    def _restore_stop(self) -> None:
        """Load a persisted emergency-stop flag at startup (spec 06#32)."""
        try:
            row = self.db.query_one(
                "SELECT value FROM system_state WHERE key = 'emergency_stop'"
            )
            if row is not None and row["value"] == "1":
                self._emergency_stop.set()
        except Exception:  # noqa: BLE001
            pass

    def emergency_stop(self, actor: str | None = None) -> dict:
        """Global stop (spec: EMERGENCY STOP / ksec stop --all).

        Cancels every non-terminal job across all sessions, blocks new
        submissions (persistently, across process restarts) and records the
        event in the audit log. Evidence and job state are preserved (jobs
        move to CANCELLED, never deleted).
        """
        cancelled: list[str] = []
        with self._lock:
            self._emergency_stop.set()
            for job in self.jobs.list():
                if not job.is_terminal:
                    try:
                        self.cancel(job.id)
                        cancelled.append(job.id)
                    except KSECError:
                        continue
        self._persist_stop(True)
        if self.audit:
            self.audit.record(
                event_type="emergency_stop",
                actor=actor or "system",
                action="emergency_stop",
                target="all",
                payload={"cancelled_jobs": cancelled},
            )
        return {"stopped": True, "cancelled_jobs": cancelled}

    def emergency_stop_clear(self, actor: str | None = None) -> None:
        """Clear the emergency-stop flag so new jobs may be submitted again."""
        self._emergency_stop.clear()
        self._persist_stop(False)
        with self._lock:
            self._submit_times.clear()
            self._user_submit_times.clear()
            self._rate_blocked.clear()
        if self.audit:
            self.audit.record(
                event_type="emergency_stop_clear",
                actor=actor or "system",
                action="emergency_stop_clear",
            )

    def is_emergency_stopped(self) -> bool:
        return self._emergency_stop.is_set()

    def health(self) -> dict:
        """Live scheduler state: worker, queue, threads and rate window."""
        with self._lock:
            threads = dict(self._threads)
            procs = dict(self._procs)
        row = self.db.query_one("SELECT COUNT(*) AS c FROM jobs WHERE state = 'QUEUED'")
        queued = int(row["c"]) if row else 0
        running_row = self.db.query_one("SELECT COUNT(*) AS c FROM jobs WHERE state = 'RUNNING'")
        running = int(running_row["c"]) if running_row else 0
        return {
            "worker_alive": bool(self._worker is not None and self._worker.is_alive()),
            "emergency_stop": self._emergency_stop.is_set(),
            "queued_jobs": queued,
            "running_jobs": running,
            "active_threads": len(threads),
            "active_processes": len(procs),
            "max_concurrent": self.config.max_concurrent_jobs,
            "rate_limit_per_minute": self.config.rate_limit_per_minute,
            "rate_limit_per_user": self.config.rate_limit_per_user,
        }

    def retry(self, job_id: str) -> Job:
        """Resubmit a terminal job as a fresh QUEUED job with the same spec.

        Only FAILED, CANCELLED and COMPLETED jobs can be retried; a retried
        run is a brand-new job (never re-executes the original record).
        """
        job = self.jobs.get(job_id)
        if job is None:
            raise KSECError(f"Unknown job: {job_id}")
        if not job.is_terminal:
            raise KSECError(f"Cannot retry job in state {job.state}")
        new_job = self.submit(
            capability=job.capability,
            target=job.target,
            options=job.options,
            session_id=job.session_id,
            user_id=job.user_id,
            workspace=job.workspace,
            workflow=f"retry:{job_id}",
            priority=job.priority,
        )
        if self.audit:
            self.audit.record(
                event_type="job.retry",
                actor=None,
                session_id=job.session_id,
                action=f"job.retry:{job.capability}",
                target=job.target or None,
                payload={"original_job": job_id, "new_job": new_job.id},
            )
        return new_job

    # -- rate limiting ----------------------------------------------------

    def _rate_allowed(self, user_id: int | None) -> tuple[bool, str]:
        """Sliding-window rate limit on submissions (global + per-user)."""
        now = time.monotonic()
        window_start = now - _RATE_WINDOW_SECONDS
        with self._lock:
            self._submit_times = [t for t in self._submit_times if t > window_start]
            key = f"u{user_id}" if user_id is not None else "anon"
            times = self._user_submit_times.setdefault(key, [])
            self._user_submit_times[key] = [t for t in times if t > window_start]
            blocked_until = self._rate_blocked.get(key, 0.0)
            if blocked_until > now:
                return False, "rate limited (per-user)"
            limit = self.config.rate_limit_per_minute
            if limit and len(self._submit_times) >= limit:
                self._rate_blocked[key] = now + _RATE_WINDOW_SECONDS
                return False, f"global rate limit reached ({limit}/min)"
            user_limit = self.config.rate_limit_per_user
            if user_limit and len(self._user_submit_times[key]) >= user_limit:
                self._rate_blocked[key] = now + _RATE_WINDOW_SECONDS
                return False, f"per-user rate limit reached ({user_limit}/min)"
            return True, ""

    def recover(self) -> list[str]:
        """Mark jobs left RUNNING by a previous process as FAILED."""
        return self.jobs.mark_interrupted()

    # -- submission --------------------------------------------------------

    def submit(
        self,
        *,
        capability: str,
        target: str = "",
        options: dict | None = None,
        session_id: str | None = None,
        user_id: int | None = None,
        workspace: str = "",
        workflow: str = "",
        priority: int = 0,
    ) -> Job:
        if self._emergency_stop.is_set():
            raise KSECError(
                "Emergency stop is active — no new jobs may be submitted "
                "(use `ksec stop --reset` after resolving the situation)"
            )
        allowed, reason = self._rate_allowed(user_id)
        if not allowed:
            if self.audit:
                self.audit.record(
                    event_type="policy.rate_limited",
                    action=f"job.submit:{capability}",
                    target=target or None,
                    outcome="denied",
                    payload={"reason": reason, "user_id": user_id},
                )
            raise KSECError(f"Submission denied: {reason}")
        with self._lock:
            self._submit_times.append(time.monotonic())
            key = f"u{user_id}" if user_id is not None else "anon"
            self._user_submit_times.setdefault(key, []).append(time.monotonic())
        job = self.jobs.create(
            capability=capability,
            target=target,
            options=options,
            session_id=session_id,
            user_id=user_id,
            workspace=workspace,
            workflow=workflow,
            priority=priority,
        )
        if self.audit:
            actor = None
            if user_id is not None:
                row = self.db.query_one(
                    "SELECT username FROM users WHERE id = ?", (user_id,)
                )
                actor = row["username"] if row else None
            self.audit.record(
                event_type="job.submit",
                actor=actor,
                session_id=session_id,
                workspace=workspace or None,
                action=f"job.submit:{capability}",
                target=target or None,
                payload={"job_id": job.id, "workflow": workflow or None},
            )
        self.start()
        self._wake.set()
        return job

    # -- control -----------------------------------------------------------

    def pause(self, job_id: str) -> Job:
        job = self.jobs.get(job_id)
        if job is None:
            raise KSECError(f"Unknown job: {job_id}")
        if job.state == "RUNNING":
            proc = self._procs.get(job_id)
            if proc is not None and proc.poll() is None:
                proc.send_signal(signal.SIGSTOP)
            return self.jobs.set_state(job_id, "PAUSED")
        if job.state in ("QUEUED", "READY", "VALIDATING"):
            return self.jobs.set_state(job_id, "PAUSED")
        raise KSECError(f"Cannot pause job in state {job.state}")

    def resume(self, job_id: str) -> Job:
        job = self.jobs.get(job_id)
        if job is None:
            raise KSECError(f"Unknown job: {job_id}")
        if job.state != "PAUSED":
            raise KSECError(f"Cannot resume job in state {job.state}")
        proc = self._procs.get(job_id)
        if proc is not None and proc.poll() is None:
            proc.send_signal(signal.SIGCONT)
        updated = self.jobs.set_state(job_id, "QUEUED")
        self._wake.set()
        return updated

    def cancel(self, job_id: str) -> Job:
        job = self.jobs.get(job_id)
        if job is None:
            raise KSECError(f"Unknown job: {job_id}")
        if job.is_terminal:
            return job
        if job.state == "RUNNING":
            with self._lock:
                self._cancel_flags[job_id] = True
            self.jobs.set_state(job_id, "CANCELLING")
            proc = self._procs.get(job_id)
            if proc is not None and proc.poll() is None:
                proc.kill()
            return self.jobs.get(job_id)
        return self.jobs.set_state(job_id, "CANCELLED", completed_at=now_utc())

    def wait_for(self, job_id: str, timeout: float = 300.0) -> Job:
        """Block until the job reaches a terminal state."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            job = self.jobs.get(job_id)
            if job is None:
                raise KSECError(f"Unknown job: {job_id}")
            if job.is_terminal:
                return job
            time.sleep(0.05)
        raise KSECError(f"Timed out waiting for job {job_id}")

    # -- internals ---------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=0.2)
            self._wake.clear()
            self._reap()
            self._run_due_schedules()
            with self._lock:
                if len(self._threads) >= self.config.max_concurrent_jobs:
                    continue
                row = self.db.query_one(
                    "SELECT id FROM jobs WHERE state = 'QUEUED'"
                    " ORDER BY priority DESC, created_at ASC LIMIT 1"
                )
                job_id = row["id"] if row else None
            if job_id is None:
                continue
            thread = threading.Thread(target=self._execute, args=(job_id,), daemon=True)
            with self._lock:
                self._threads[job_id] = thread
            thread.start()

    def _reap(self) -> None:
        with self._lock:
            done = [jid for jid, t in self._threads.items() if not t.is_alive()]
            for jid in done:
                self._threads[jid].join()
                del self._threads[jid]
                self._procs.pop(jid, None)
                self._cancel_flags.pop(jid, None)

    def _execute(self, job_id: str) -> None:
        job = self.jobs.get(job_id)
        if job is None:
            return
        # Cancellation requested before start.
        if self._is_cancelled(job_id):
            self.jobs.set_state(job_id, "CANCELLED", completed_at=now_utc())
            return
        self.jobs.set_state(job_id, "RUNNING", started_at=now_utc())

        adapter = self.adapters.get(job.capability)
        if adapter is None:
            self.jobs.fail(job_id, f"No adapter for capability {job.capability}")
            return
        # Plugin permission gate: plugin-provided capabilities only run when
        # the owning plugin is enabled, trusted and has declared tool.execute.
        if self.plugin_manager is not None:
            try:
                self.plugin_manager.assert_capability_allowed(job.capability)
            except KSECError as exc:
                self.jobs.fail(job_id, exc.message)
                return
        try:
            command = adapter.build_command(
                CommandRequest(
                    capability=job.capability,
                    target=job.target,
                    options=job.options,
                    timeout=self.config.default_timeout_seconds,
                )
            )
        except KSECError as exc:
            self.jobs.fail(job_id, exc.message)
            return
        if not command:
            self.jobs.fail(job_id, "Adapter produced an empty command")
            return

        executable, *args = command
        started = time.monotonic()
        try:
            proc = subprocess.Popen(
                [executable, *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as exc:
            self.jobs.fail(job_id, f"Failed to start {executable}: {exc}")
            return
        with self._lock:
            self._procs[job_id] = proc

        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []
        timed_out = False
        cancelled = False
        deadline = time.monotonic() + self.config.default_timeout_seconds
        try:
            while time.monotonic() < deadline:
                if self._is_cancelled(job_id):
                    cancelled = True
                    proc.kill()
                    proc.wait()
                    break
                try:
                    out, err = proc.communicate(timeout=0.2)
                    if out:
                        stdout_chunks.append(out)
                    if err:
                        stderr_chunks.append(err)
                    break
                except subprocess.TimeoutExpired:
                    continue
            else:
                timed_out = True
                proc.kill()
                proc.wait()
            # A cancel may have raced with communicate() returning; re-check.
            if not cancelled and self._is_cancelled(job_id):
                cancelled = True
        finally:
            with self._lock:
                self._procs.pop(job_id, None)

        duration = time.monotonic() - started
        stdout = "".join(stdout_chunks)[:_STDOUT_LIMIT]
        stderr = "".join(stderr_chunks)[:_STDERR_LIMIT]

        if cancelled:
            self.jobs.set_state(job_id, "CANCELLED", completed_at=now_utc())
            return
        if timed_out:
            self.jobs.fail(job_id, f"Timed out after {self.config.default_timeout_seconds}s", exit_code=None)
            return

        parsed_stream = stderr if adapter.output_stream == "stderr" else stdout
        parsed = adapter.parse_output(parsed_stream) if proc.returncode == 0 else None
        outcome = {
            "exit_code": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "duration_seconds": round(duration, 3),
            "timed_out": False,
            "entities": parsed.entities if parsed else [],
            "entity_count": len(parsed.entities) if parsed else 0,
        }
        if proc.returncode == 0:
            self.jobs.complete(job_id, outcome)
            self._auto_extract_iocs(job, outcome)
        else:
            message = (stderr.strip() or f"exit code {proc.returncode}")[:2000]
            self.jobs.fail(job_id, message, exit_code=proc.returncode)

    def _run_due_schedules(self) -> None:
        """Submit a job for every enabled schedule whose cron matches now."""
        import datetime as _dt

        now = _dt.datetime.utcnow().replace(second=0, microsecond=0)
        for schedule in self.schedules.list(enabled_only=True):
            if not cron_matches(schedule.cron, now):
                continue
            last = schedule.last_run_at
            if last and last[:16] == now.strftime("%Y-%m-%dT%H:%M"):
                continue  # already fired this minute
            try:
                self.submit(
                    capability=schedule.capability,
                    target=schedule.target,
                    options=schedule.options,
                    session_id=None,
                    user_id=schedule.user_id,
                    workspace=schedule.workspace,
                    workflow=f"schedule:{schedule.id}",
                )
                self.schedules.mark_run(schedule.id)
            except KSECError:
                continue

    def _auto_extract_iocs(self, job, outcome: dict) -> None:
        """Auto-register IOCs from a completed job's parsed entities and raw
        output (spec: IOC extraction / auto-registration from scan results)."""
        if self.intel_service is None:
            return
        if not outcome.get("entities") and not (outcome.get("stdout") or "").strip():
            return
        try:
            self.intel_service.extract_and_register(
                outcome.get("entities") or [],
                outcome.get("stdout") or "",
                source=f"job:{job.id}:{job.capability}",
            )
        except Exception:
            # Auto-registration must never fail the job itself.
            pass

    def _is_cancelled(self, job_id: str) -> bool:
        with self._lock:
            return self._cancel_flags.get(job_id, False)