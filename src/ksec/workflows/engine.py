"""Workflow engine (spec: WORKFLOW ENGINE / CORE ORCHESTRATION PIPELINE).

Each workflow step is policy-checked (permission + scope) before a job is
submitted to the scheduler. Blocked steps fail the run: out-of-scope targets
are never touched.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass, field

from ksec.capabilities.catalog import capability_permission
from ksec.correlation.service import CorrelationService
from ksec.db.connection import Database
from ksec.identity.users import User, now_utc
from ksec.jobs.models import JobRepository
from ksec.policies.engine import Decision, PolicyEngine
from ksec.scheduler.service import Scheduler
from ksec.sessions.manager import Session
from ksec.workflows.definitions import WorkflowDefinition


@dataclass(frozen=True)
class StepOutcome:
    capability: str
    policy_decision: str
    policy_reason: str
    job_id: str | None = None
    state: str = "planned"
    error: str = ""
    entities: int = 0


@dataclass(frozen=True)
class WorkflowRun:
    run_id: str
    workflow: str
    target: str
    status: str
    steps: list[StepOutcome] = field(default_factory=list)
    error: str = ""


class WorkflowEngine:
    def __init__(
        self,
        db: Database,
        policy: PolicyEngine,
        scheduler: Scheduler,
        jobs: JobRepository,
        correlation: CorrelationService | None = None,
    ):
        self.db = db
        self.policy = policy
        self.scheduler = scheduler
        self.jobs = jobs
        self.correlation = correlation

    def plan(
        self,
        definition: WorkflowDefinition,
        *,
        user: User,
        session: Session | None = None,
        target: str,
        engagement_id: int | None = None,
    ) -> list[StepOutcome]:
        """Policy-check each step without executing (dry run)."""
        outcomes: list[StepOutcome] = []
        for step in definition.steps:
            result = self.policy.evaluate(
                user=user,
                action=capability_permission(step.capability),
                session=session,
                target=target,
                engagement_id=engagement_id,
            )
            outcomes.append(
                StepOutcome(
                    capability=step.capability,
                    policy_decision=result.decision.value,
                    policy_reason=result.reason,
                    state="planned",
                )
            )
        return outcomes

    def run(
        self,
        definition: WorkflowDefinition,
        *,
        user: User,
        session: Session | None = None,
        target: str,
        engagement_id: int | None = None,
    ) -> WorkflowRun:
        run_id = uuid.uuid4().hex
        created = now_utc()
        self.db.execute(
            "INSERT INTO workflow_runs (id, workflow, target, engagement_id, session_id,"
            " user_id, status, steps_total, created_at, definition_version,"
            " definition_snapshot) VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?, ?, ?)",
            (
                run_id,
                definition.name,
                target,
                engagement_id,
                session.id if session else None,
                user.id,
                len(definition.steps),
                created,
                definition.version,
                json.dumps(definition.as_snapshot()),
            ),
        )

        outcomes: list[StepOutcome] = []
        try:
            ordered = self._topological_order(definition)
            for index, step in ordered:
                result = self.policy.evaluate(
                    user=user,
                    action=capability_permission(step.capability),
                    session=session,
                    target=target,
                    engagement_id=engagement_id,
                )
                if result.decision != Decision.ALLOW:
                    outcome = StepOutcome(
                        capability=step.capability,
                        policy_decision=result.decision.value,
                        policy_reason=result.reason,
                        state="blocked",
                        error=result.reason,
                    )
                    outcomes.append(outcome)
                    return self._finish(
                        run_id, definition.name, target, "failed", outcomes, result.reason
                    )

                job, completed = self._submit_with_retry(
                    definition, index, step, user, session, target, engagement_id
                )
                entity_count = completed.result.get("entity_count", 0)
                # Correlate parsed observations into assets.
                if completed.state == "COMPLETED" and self.correlation is not None:
                    self.correlation.ingest_entities(
                        completed.result.get("entities", []),
                        tool=completed.capability,
                        engagement_id=engagement_id,
                        source=completed.capability,
                    )
                outcomes.append(
                    StepOutcome(
                        capability=step.capability,
                        policy_decision=Decision.ALLOW.value,
                        policy_reason=result.reason,
                        job_id=job.id,
                        state=completed.state.lower(),
                        error=completed.error,
                        entities=entity_count,
                    )
                )
                if completed.state != "COMPLETED":
                    return self._finish(
                        run_id, definition.name, target, "failed", outcomes, completed.error
                    )
            return self._finish(run_id, definition.name, target, "completed", outcomes, "")
        except Exception as exc:  # pragma: no cover - defensive
            return self._finish(run_id, definition.name, target, "failed", outcomes, str(exc))

    @staticmethod
    def _topological_order(
        definition: WorkflowDefinition,
    ) -> list[tuple[int, object]]:
        """Order steps so every step runs after its ``depends_on`` steps.

        Steps without dependencies keep their original relative order; the
        result is a valid dependency-respecting sequence (spec 07: DAG).
        """
        steps = list(definition.steps)
        names = [definition.step_name(i, s) for i, s in enumerate(steps)]
        by_name = {name: i for i, name in enumerate(names)}
        indegree = [0] * len(steps)
        edges: dict[int, list[int]] = {i: [] for i in range(len(steps))}
        for i, step in enumerate(steps):
            for dep in step.depends_on:
                if dep in by_name:
                    edges[by_name[dep]].append(i)
                    indegree[i] += 1
        ready = [i for i, d in enumerate(indegree) if d == 0]
        ordered: list[tuple[int, object]] = []
        while ready:
            i = ready.pop(0)
            ordered.append((i, steps[i]))
            for nxt in edges[i]:
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    ready.append(nxt)
        # Any remaining steps are only reachable via unknown deps — validation
        # already rejects those, but keep a safe fallback so nothing is skipped.
        executed = {i for i, _ in ordered}
        for i in range(len(steps)):
            if i not in executed:
                ordered.append((i, steps[i]))
        return ordered

    def _submit_with_retry(
        self,
        definition: WorkflowDefinition,
        index: int,
        step,
        user: User,
        session: Session | None,
        target: str,
        engagement_id: int | None,
    ):
        """Submit a step job with exponential-backoff retries (spec 07)."""
        attempts = 0
        max_retries = max(0, int(getattr(step, "retry", 0) or 0))
        delay = float(getattr(step, "retry_delay", 1.0) or 1.0)
        last_job = None
        last_completed = None
        while True:
            job = self.scheduler.submit(
                capability=step.capability,
                target=target,
                options=step.options,
                session_id=session.id if session else None,
                user_id=user.id,
                workspace=session.workspace if session else "",
                workflow=definition.name,
            )
            last_job = job
            last_completed = self.scheduler.wait_for(job.id)
            if last_completed.state == "COMPLETED" or attempts >= max_retries:
                return last_job, last_completed
            attempts += 1
            time.sleep(delay * (2 ** (attempts - 1)))
        return last_job, last_completed

    def runs(self, workflow: str | None = None, limit: int = 20) -> list[sqlite3.Row]:
        """Workflow run history (spec: ``ksec workflow history``)."""
        sql = (
            "SELECT id, workflow, target, engagement_id, status, steps_total,"
            " steps_completed, created_at, completed_at, error, definition_version,"
            " definition_snapshot FROM workflow_runs"
        )
        params: list = []
        if workflow:
            sql += " WHERE workflow = ?"
            params.append(workflow)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return self.db.query_all(sql, params)

    def _finish(
        self,
        run_id: str,
        workflow_name: str,
        target: str,
        status: str,
        outcomes: list[StepOutcome],
        error: str,
    ) -> WorkflowRun:
        self.db.execute(
            "UPDATE workflow_runs SET status = ?, steps_completed = ?, completed_at = ?,"
            " error = ? WHERE id = ?",
            (
                status,
                sum(1 for o in outcomes if o.state == "completed"),
                now_utc(),
                error[:2000],
                run_id,
            ),
        )
        run = WorkflowRun(
            run_id=run_id,
            workflow=workflow_name,
            target=target,
            status=status,
            steps=outcomes,
            error=error,
        )
        return run