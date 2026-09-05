"""CLI: ``ksec job ...`` — job lifecycle + recurring schedules."""
from __future__ import annotations

import json

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository
from ksec.workflows.definitions import list_workflows


def _job_dict(job) -> dict:
    return {
        "id": job.id,
        "capability": job.capability,
        "target": job.target,
        "workspace": job.workspace,
        "workflow": job.workflow,
        "state": job.state,
        "priority": job.priority,
        "exit_code": job.exit_code,
        "error": job.error,
        "entity_count": job.result.get("entity_count", 0),
        "created_at": job.created_at,
        "completed_at": job.completed_at,
    }


def cmd_job_list(ctx: KsecContext, args) -> int:
    jobs = ctx.jobs.list(state=args.state or None)
    data = [_job_dict(j) for j in jobs]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for j in jobs:
            print(j.id)
    else:
        if not data:
            print("no jobs")
        for d in data:
            print(f"{d['id'][:12]:<12} {d['state']:<10} {d['capability']:<16} {d['target']:<20} exit={d['exit_code']}")
    return 0


def cmd_job_status(ctx: KsecContext, args) -> int:
    job = ctx.jobs.get(args.id)
    if job is None:
        emit(f"unknown job: {args.id}", args.json, args.quiet)
        return 1
    emit(_job_dict(job), args.json, args.quiet)
    return 0


def _check_schedule_target(ctx, args, user) -> bool:
    """Policy gate: a schedule may only target an authorized host."""
    definition = ctx.workflow_store.resolve(args.capability)
    if definition is None:
        builtin = [w.name for w in list_workflows()]
        custom = [w.name for w in ctx.workflow_store.list()]
        emit(
            f"unknown capability {args.capability!r}; available: {', '.join(builtin + custom)}",
            args.json,
            args.quiet,
        )
        return False
    session = ctx.sessions.open(user, args.workspace or "RED_TEAM", role_name=args.role)
    outcomes = ctx.workflows.plan(
        definition,
        user=user,
        session=session,
        target=args.target,
        engagement_id=args.engagement,
    )
    blocked = [o for o in outcomes if o.policy_decision != "ALLOW"]
    if blocked:
        reason = blocked[0].policy_reason
        emit(
            f"schedule refused: target not authorized ({reason})",
            args.json,
            args.quiet,
        )
        return False
    return True


def _authenticated_user(ctx, args):
    if not args.user:
        raise KSECError("--user is required")
    return UserRepository(ctx.db).authenticate(args.user, args.password)


def cmd_job_schedule_add(ctx: KsecContext, args) -> int:
    if ctx.scheduler.is_emergency_stopped():
        emit(
            "schedule refused: emergency stop is active "
            "(use `ksec stop --reset` to accept new work)",
            args.json,
            args.quiet,
        )
        return 1
    try:
        user = _authenticated_user(ctx, args)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    if not _check_schedule_target(ctx, args, user):
        return 1
    options: dict | None = None
    if getattr(args, "options", None):
        try:
            parsed = json.loads(args.options)
        except json.JSONDecodeError as exc:
            emit(f"invalid --options JSON: {exc}", args.json, args.quiet)
            return 1
        if not isinstance(parsed, dict):
            emit("--options must be a JSON object", args.json, args.quiet)
            return 1
        options = parsed
    try:
        schedule = ctx.scheduler.schedules.create(
            capability=args.capability,
            target=args.target,
            cron=args.cron,
            options=options,
            workspace=args.workspace or "RED_TEAM",
            user_id=user.id,
            engagement_id=args.engagement,
        )
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(schedule.to_dict(), args.json, args.quiet)
    return 0


def cmd_job_schedule_list(ctx: KsecContext, args) -> int:
    schedules = ctx.scheduler.schedules.list()
    data = [s.to_dict() for s in schedules]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for s in schedules:
            print(s.id)
    else:
        if not data:
            print("no schedules")
        for s in data:
            flag = "on " if s["enabled"] else "off"
            print(
                f"{s['id']:>3}  [{flag}] cron={s['cron']:<14} {s['capability']:<16}"
                f" {s['target']:<20} last={s['last_run_at'] or '-'}"
            )
    return 0


def cmd_job_schedule_remove(ctx: KsecContext, args) -> int:
    removed = ctx.scheduler.schedules.remove(args.id)
    if not removed:
        emit(f"unknown schedule: {args.id}", args.json, args.quiet)
        return 1
    emit({"removed": True, "id": args.id}, args.json, args.quiet)
    return 0


def cmd_job_schedule_run(ctx: KsecContext, args) -> int:
    """Run a schedule now (re-validating scope before submit)."""
    schedule = ctx.scheduler.schedules.get(args.id)
    if schedule is None:
        emit(f"unknown schedule: {args.id}", args.json, args.quiet)
        return 1
    users = UserRepository(ctx.db)
    user = users.get(schedule.user_id) if schedule.user_id else None
    if user is None:
        emit(f"schedule has no valid owner; recreate it", args.json, args.quiet)
        return 1
    namespace = type("Args", (), {
        "capability": schedule.capability,
        "target": schedule.target,
        "workspace": schedule.workspace,
        "engagement": schedule.engagement_id,
        "role": None,
        "json": args.json,
        "quiet": args.quiet,
        "user": None,
        "password": None,
    })()
    if not _check_schedule_target(ctx, namespace, user):
        return 1
    job = ctx.scheduler.submit(
        capability=schedule.capability,
        target=schedule.target,
        options=schedule.options,
        user_id=schedule.user_id,
        workspace=schedule.workspace,
        workflow=f"schedule:{schedule.id}:manual",
    )
    ctx.scheduler.schedules.mark_run(schedule.id)
    try:
        # Wait for the terminal state so the job is not mistaken for an
        # interrupted run when this CLI process exits.
        completed = ctx.scheduler.wait_for(job.id, timeout=ctx.config.default_timeout_seconds + 30)
    except KSECError as exc:
        emit({"submitted": True, "job_id": job.id, "error": exc.message}, args.json, args.quiet)
        return 1
    result = completed.result or {}
    emit(
        {
            "submitted": True,
            "job_id": job.id,
            "schedule_id": schedule.id,
            "state": completed.state,
            "exit_code": completed.exit_code,
            "entity_count": result.get("entity_count", 0),
        },
        args.json,
        args.quiet,
    )
    return 0 if completed.state == "COMPLETED" else 1


def cmd_job_pause(ctx: KsecContext, args) -> int:
    try:
        job = ctx.scheduler.pause(args.id)
    except Exception as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(_job_dict(job), args.json, args.quiet)
    return 0


def cmd_job_resume(ctx: KsecContext, args) -> int:
    try:
        job = ctx.scheduler.resume(args.id)
    except Exception as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(_job_dict(job), args.json, args.quiet)
    return 0


def cmd_job_cancel(ctx: KsecContext, args) -> int:
    try:
        job = ctx.scheduler.cancel(args.id)
    except Exception as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(_job_dict(job), args.json, args.quiet)
    return 0


def cmd_job_logs(ctx: KsecContext, args) -> int:
    """Show a completed job's stored stdout/stderr (spec: job logs)."""
    job = ctx.jobs.get(args.id)
    if job is None:
        emit(f"unknown job: {args.id}", args.json, args.quiet)
        return 1
    result = job.result or {}
    if args.json:
        emit(
            {
                "id": job.id,
                "state": job.state,
                "exit_code": job.exit_code,
                "error": job.error,
                "stdout": (result.get("stdout") or "")[:20000],
                "stderr": (result.get("stderr") or "")[:5000],
                "duration_seconds": result.get("duration_seconds"),
            },
            True,
            False,
        )
        return 0
    print(f"job {job.id} [{job.state}] exit={job.exit_code}")
    if job.error:
        print(f"error: {job.error}")
    stdout = (result.get("stdout") or "").strip()
    stderr = (result.get("stderr") or "").strip()
    if stdout:
        print("--- stdout ---")
        print(stdout[:20000])
    if stderr:
        print("--- stderr ---")
        print(stderr[:5000])
    if not stdout and not stderr:
        print("(no output captured)")
    return 0


def cmd_job_retry(ctx: KsecContext, args) -> int:
    """Resubmit a terminal job as a fresh job (never re-runs the record)."""
    try:
        new_job = ctx.scheduler.retry(args.id)
    except KSECError as exc:
        emit(exc.message, args.json, args.quiet)
        return 1
    emit(
        {
            "retried": True,
            "original": args.id,
            "job_id": new_job.id,
            "capability": new_job.capability,
            "target": new_job.target,
            "state": new_job.state,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_job_trace(ctx: KsecContext, args) -> int:
    """Trace a job's lineage: spec, session, schedule and related audit events."""
    job = ctx.jobs.get(args.id)
    if job is None:
        emit(f"unknown job: {args.id}", args.json, args.quiet)
        return 1
    trace: dict = {"job": _job_dict(job), "options": job.options}
    if job.session_id:
        session = ctx.sessions.get(job.session_id)
        trace["session"] = (
            {
                "id": session.id,
                "user": session.username,
                "workspace": session.workspace,
                "role": session.role,
                "state": session.state,
            }
            if session
            else None
        )
    if job.workflow.startswith("schedule:") or job.workflow.startswith("retry:") or job.workflow:
        trace["workflow"] = job.workflow
    if job.workflow.startswith("schedule:") and not job.workflow.endswith(":manual"):
        schedule_id = job.workflow.split(":")[1]
        try:
            schedule = ctx.scheduler.schedules.get(int(schedule_id))
            if schedule:
                trace["schedule"] = schedule.to_dict()
        except (ValueError, TypeError):
            pass
    related = ctx.audit.list(limit=200)
    events = [
        {
            "event_type": row["event_type"],
            "actor": row["actor"],
            "action": row["action"],
            "created_at": row["created_at"],
        }
        for row in related
        if row["action"] and (
            f"job:{job.id}" in str(row["action"])
            or f'"job_id": "{job.id}"' in (row["payload"] or "")
            or f'"job_id": "{job.id[:12]}' in (row["payload"] or "")
        )
    ]
    trace["audit_events"] = events[:25]
    emit(trace, args.json, args.quiet)
    return 0


def cmd_job_health(ctx: KsecContext, args) -> int:
    """Show live scheduler health (worker, queue, threads, rate limits)."""
    data = ctx.scheduler.health()
    emit(data, args.json, args.quiet)
    return 0