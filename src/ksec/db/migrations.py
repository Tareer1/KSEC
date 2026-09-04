"""Sequential SQL migrations for KSEC.

Migration files live in ``migrations/NNN_description.sql`` and are applied in
numeric order. Applied versions are recorded in ``schema_migrations``.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ksec.core.errors import DatabaseError
from ksec.db.connection import Database


class MigrationRunner:
    def __init__(self, db: Database, migrations_dir: Path):
        self.db = db
        self.migrations_dir = Path(migrations_dir)
        self._files = sorted(self.migrations_dir.glob("[0-9][0-9][0-9]_*.sql"))

    def ensure_schema(self) -> None:
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version INTEGER PRIMARY KEY,"
            "name TEXT NOT NULL,"
            "applied_at TEXT NOT NULL)"
        )

    def current_version(self) -> int:
        row = self.db.query_one("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations")
        return int(row["v"]) if row else 0

    def pending(self) -> list[Path]:
        current = self.current_version()
        return [f for f in self._files if int(f.name.split("_")[0]) > current]

    def apply(self) -> list[str]:
        """Apply all pending migrations; returns the names applied."""
        self.ensure_schema()
        applied: list[str] = []
        for file in self.pending():
            version = int(file.name.split("_")[0])
            name = file.name
            try:
                sql = file.read_text(encoding="utf-8")
            except OSError as exc:
                raise DatabaseError(f"Cannot read migration {name}: {exc}") from exc
            try:
                # executescript performs its own statement handling; the
                # connection runs in autocommit mode so each statement is
                # applied independently (all DDL uses IF NOT EXISTS).
                self.db.conn.executescript(sql)
                self.db.execute(
                    "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                    (version, name, datetime.now(timezone.utc).isoformat()),
                )
                applied.append(name)
            except Exception as exc:
                raise DatabaseError(f"Migration {name} failed: {exc}") from exc
        return applied