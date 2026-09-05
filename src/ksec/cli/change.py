"""CLI: ``ksec change ...`` — baseline snapshots and drift scans."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_change_baseline_create(ctx: KsecContext, args) -> int:
    try:
        baseline = ctx.change.create_baseline(
            name=args.name,
            scope=args.scope,
            target=getattr(args, "target", None) or "*",
            created_by=getattr(args, "user", None) or "",
        )
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(
        {
            "created": True,
            "id": baseline.id,
            "name": baseline.name,
            "scope": baseline.scope,
            "target": baseline.target,
            "entities_snapshot": sum(
                len(v) for v in baseline.snapshot.values() if isinstance(v, list)
            ),
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_change_baseline_list(ctx: KsecContext, args) -> int:
    baselines = ctx.change.list_baselines()
    if args.json:
        emit(
            [
                {
                    "id": b.id,
                    "name": b.name,
                    "scope": b.scope,
                    "target": b.target,
                    "created_by": b.created_by,
                    "created_at": b.created_at,
                }
                for b in baselines
            ],
            True,
            False,
        )
    elif args.quiet:
        for b in baselines:
            print(b.id)
    else:
        if not baselines:
            print("no baselines")
        for b in baselines:
            print(f"#{b.id:<3} scope={b.scope:<8} target={b.target:<20} {b.name}")
    return 0


def cmd_change_baseline_delete(ctx: KsecContext, args) -> int:
    if not ctx.change.remove_baseline(args.id):
        emit(f"unknown baseline: {args.id}", args.json, args.quiet)
        return 1
    emit({"removed": True, "id": args.id}, args.json, args.quiet)
    return 0


def cmd_change_scan(ctx: KsecContext, args) -> int:
    try:
        scan = ctx.change.scan(args.id, actor=getattr(args, "user", None) or "")
    except ValueError as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(
        {
            "scan_id": scan.id,
            "baseline_id": scan.baseline_id,
            "status": scan.status,
            "drift_count": len(scan.drift),
            "drift": scan.drift[:50],
            "created_at": scan.created_at,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_change_scan_list(ctx: KsecContext, args) -> int:
    scans = ctx.change.list_scans(getattr(args, "baseline", None))
    if args.json:
        emit(
            [
                {
                    "id": s.id,
                    "baseline_id": s.baseline_id,
                    "status": s.status,
                    "drift_count": len(s.drift),
                    "created_at": s.created_at,
                }
                for s in scans
            ],
            True,
            False,
        )
    elif args.quiet:
        for s in scans:
            print(s.id)
    else:
        if not scans:
            print("no scans")
        for s in scans:
            print(
                f"#{s.id:<3} baseline={s.baseline_id:<3} {s.status:<6}"
                f" drift={len(s.drift):<3} {s.created_at}"
            )
    return 0
