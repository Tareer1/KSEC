"""CLI: ``ksec backup create|list|verify|restore``."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit


def cmd_backup_create(ctx: KsecContext, args) -> int:
    backup = ctx.backups.create()
    emit(
        {
            "created": True,
            "id": backup.id,
            "backup_id": backup.backup_id,
            "path": backup.path,
            "sha256": backup.sha256,
            "size_bytes": backup.size_bytes,
        },
        args.json,
        args.quiet,
    )
    return 0


def cmd_backup_list(ctx: KsecContext, args) -> int:
    backups = ctx.backups.list()
    data = [
        {
            "id": b.id,
            "backup_id": b.backup_id,
            "path": b.path,
            "size_bytes": b.size_bytes,
            "sha256": b.sha256[:16],
            "created_at": b.created_at,
        }
        for b in backups
    ]
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for b in backups:
            print(b.backup_id)
    else:
        if not data:
            print("no backups")
        for d in data:
            print(f"{d['id']:>3}  {d['backup_id']:<24} {d['size_bytes']:>8} bytes  {d['sha256']}…")
    return 0


def cmd_backup_verify(ctx: KsecContext, args) -> int:
    ok, reason = ctx.backups.verify(args.id)
    emit({"id": args.id, "verified": ok, "reason": reason}, args.json, args.quiet)
    return 0 if ok else 1


def cmd_backup_restore(ctx: KsecContext, args) -> int:
    if not args.yes:
        emit(
            {
                "error": "approval required",
                "message": "restoring overwrites the current database; rerun with --yes",
            },
            args.json,
            args.quiet,
        )
        return 1
    try:
        destination = ctx.backups.restore(args.id, approve=True)
    except (ValueError, FileNotFoundError) as exc:
        emit(str(exc), args.json, args.quiet)
        return 1
    emit(
        {"restored": True, "id": args.id, "destination": destination},
        args.json,
        args.quiet,
    )
    return 0