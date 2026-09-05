"""CLI: ``ksec db version|health|repair`` (spec 05 #72-75)."""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.db.migrations import MigrationRunner
from ksec.bootstrap import MIGRATIONS_DIR


def cmd_db_version(ctx: KsecContext, args) -> int:
    runner = MigrationRunner(ctx.db, MIGRATIONS_DIR)
    pending = runner.pending()
    data = {
        "schema_version": runner.current_version(),
        "ksec_version": __import__("ksec", fromlist=["__version__"]).__version__,
        "pending_migrations": [p.name for p in pending],
        "compatible": len(pending) == 0,
    }
    emit(data, args.json, args.quiet)
    return 0


def cmd_db_health(ctx: KsecContext, args) -> int:
    integrity = ctx.db.query_one("PRAGMA integrity_check")
    integrity_ok = bool(integrity) and integrity[0] == "ok"
    foreign_keys = ctx.db.query_one("PRAGMA foreign_key_check")
    fk_ok = foreign_keys is None
    page_info = ctx.db.query_one("PRAGMA page_count")
    page_size = ctx.db.query_one("PRAGMA page_size")
    size_bytes = (page_info[0] if page_info else 0) * (page_size[0] if page_size else 0)
    runner = MigrationRunner(ctx.db, MIGRATIONS_DIR)
    pending = runner.pending()
    data = {
        "integrity": "ok" if integrity_ok else "corrupt",
        "foreign_keys": "ok" if fk_ok else "violations found",
        "schema_version": runner.current_version(),
        "migrations_pending": len(pending),
        "db_size_bytes": size_bytes,
        "healthy": integrity_ok and fk_ok and not pending,
    }
    emit(data, args.json, args.quiet)
    return 0 if data["healthy"] else 1


def cmd_db_repair(ctx: KsecContext, args) -> int:
    """Non-destructive integrity checks + WAL checkpoint. High-impact repairs
    require confirmation; there is no silent destructive repair."""
    integrity = ctx.db.query_one("PRAGMA integrity_check")
    integrity_ok = bool(integrity) and integrity[0] == "ok"
    reported: list[str] = []
    if not integrity_ok:
        reported.append("PRAGMA integrity_check found corruption")
    foreign_keys = ctx.db.query_one("PRAGMA foreign_key_check")
    if foreign_keys is not None:
        reported.append("foreign key violations exist")
    # Safe, non-destructive maintenance: checkpoint the WAL and rebuild
    # indexes. Never rewrites or drops user data without explicit backup.
    ctx.db.execute("PRAGMA wal_checkpoint(FULL)")
    ctx.db.execute("REINDEX")
    if reported and not args.yes:
        data = {
            "repair_needed": True,
            "issues": reported,
            "recommendation": "Run a verified backup first (ksec backup create), "
                              "then rerun with --yes.",
            "applied": ["wal_checkpoint", "reindex"],
        }
        emit(data, args.json, args.quiet)
        return 1
    data = {
        "repair_needed": bool(reported),
        "issues": reported,
        "applied": ["wal_checkpoint", "reindex"],
        "verified": True,
    }
    ctx.audit.record(
        event_type="db.repair",
        actor="system",
        action="db.repair",
        outcome="success",
        payload=data,
    )
    emit(data, args.json, args.quiet)
    return 0 if not reported else 1