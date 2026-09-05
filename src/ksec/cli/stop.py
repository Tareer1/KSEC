"""CLI: ``ksec stop`` — global emergency stop (spec 06#32, 07#79)."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_stop(ctx: KsecContext, args) -> int:
    if getattr(args, "status", False):
        emit(
            {"emergency_stop_active": ctx.scheduler.is_emergency_stopped()},
            args.json,
            args.quiet,
        )
        return 0
    if args.reset:
        ctx.scheduler.emergency_stop_clear(actor="cli")
        emit(
            {"stopped": False, "reset": True, "message": "Emergency stop cleared; new jobs accepted"},
            args.json,
            args.quiet,
        )
        return 0
    result = ctx.scheduler.emergency_stop(actor="cli")
    emit(result, args.json, args.quiet)
    return 0