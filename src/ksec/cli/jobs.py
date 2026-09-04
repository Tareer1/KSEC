"""CLI: ``ksec job ...`` — job lifecycle."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


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