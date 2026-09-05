"""CLI: ``ksec purple exercise ...`` — coordinated purple-team exercises."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_purple_exercise_new(ctx: KsecContext, args) -> int:
    try:
        exercise = ctx.purple.create(
            name=args.name,
            description=args.description or "",
            engagement_id=args.engagement,
            created_by=getattr(args, "user", None) or "",
        )
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(
        {
            "created": True,
            "id": exercise.id,
            "name": exercise.name,
            "status": exercise.status,
            "engagement_id": exercise.engagement_id,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_purple_exercise_list(ctx: KsecContext, args) -> int:
    exercises = ctx.purple.list()
    if args.json:
        emit(
            [
                {
                    "id": e.id,
                    "name": e.name,
                    "status": e.status,
                    "engagement_id": e.engagement_id,
                    "red_findings": e.red_findings,
                    "blue_alerts": e.blue_alerts,
                    "detections_fired": e.detections_fired,
                    "created_at": e.created_at,
                }
                for e in exercises
            ],
            True,
            False,
        )
    elif args.quiet:
        for e in exercises:
            print(e.id)
    else:
        if not exercises:
            print("no purple exercises")
        for e in exercises:
            print(
                f"#{e.id:<3} {e.status:<10} {e.name}"
            )
    return 0


def cmd_purple_exercise_start(ctx: KsecContext, args) -> int:
    try:
        exercise = ctx.purple.start(args.id)
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit({"id": exercise.id, "status": exercise.status}, args.json, args.quiet)
    return 0


def cmd_purple_exercise_complete(ctx: KsecContext, args) -> int:
    try:
        exercise = ctx.purple.complete(args.id)
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(
        {
            "id": exercise.id,
            "status": exercise.status,
            "red_findings": exercise.red_findings,
            "blue_alerts": exercise.blue_alerts,
            "detections_fired": exercise.detections_fired,
            "completed_at": exercise.completed_at,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_purple_exercise_show(ctx: KsecContext, args) -> int:
    data = ctx.purple.summary(args.id)
    if data is None:
        emit(f"unknown purple exercise: {args.id}", args.json, args.quiet)
        return 1
    emit(data, args.json, args.quiet)
    return 0


def cmd_purple_exercise_delete(ctx: KsecContext, args) -> int:
    if not ctx.purple.remove(args.id):
        emit(f"unknown purple exercise: {args.id}", args.json, args.quiet)
        return 1
    emit({"removed": True, "id": args.id}, args.json, args.quiet)
    return 0
