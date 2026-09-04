"""Backup and recovery (spec: BACKUP AND RECOVERY).

Creates hashed, timestamped local backups of the KSEC database, verifies
integrity, and restores from a verified backup.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from ksec.audit.service import AuditService
from ksec.config.loader import KsecConfig
from ksec.db.connection import Database
from ksec.identity.users import now_utc


@dataclass(frozen=True)
class Backup:
    id: int
    backup_id: str
    path: str
    kind: str
    size_bytes: int
    sha256: str
    created_at: str


def _hash_file(path: str, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


class BackupService:
    def __init__(self, db: Database, config: KsecConfig, audit: AuditService):
        self.db = db
        self.config = config
        self.audit = audit

    def backups_dir(self):
        path = self.config.data_dir / "backups"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def create(self, kind: str = "full") -> Backup:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        backup_id = f"{timestamp}-{uuid.uuid4().hex[:6]}"
        target = self.backups_dir() / f"ksec-{backup_id}.db"
        source = self.config.db_path
        if not source.exists():
            raise FileNotFoundError(f"Database not found at {source}")
        # Use the SQLite online backup API so the copy is consistent even
        # when the live database is in WAL mode (a plain file copy would
        # miss transactions still sitting in the WAL).
        try:
            source_conn = sqlite3.connect(str(source))
            target_conn = sqlite3.connect(str(target))
            source_conn.backup(target_conn)
        except sqlite3.Error as exc:
            raise RuntimeError(f"Database backup failed: {exc}") from exc
        finally:
            target_conn.close()
            source_conn.close()
        sha = _hash_file(str(target))
        size = target.stat().st_size
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO backups (backup_id, path, kind, size_bytes, sha256, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (backup_id, str(target), kind, size, sha, now_utc()),
            )
        self.audit.record(
            event_type="backup.create",
            actor="system",
            action="backup.create",
            target=str(target),
            outcome="success",
            payload={"backup_id": backup_id, "sha256": sha},
        )
        return self.get(cursor.lastrowid)

    def get(self, backup_id: int) -> Backup | None:
        row = self.db.query_one("SELECT * FROM backups WHERE id = ?", (backup_id,))
        return self._from_row(row) if row else None

    def get_by_uuid(self, backup_uuid: str) -> Backup | None:
        row = self.db.query_one("SELECT * FROM backups WHERE backup_id = ?", (backup_uuid,))
        return self._from_row(row) if row else None

    def list(self) -> list[Backup]:
        rows = self.db.query_all("SELECT * FROM backups ORDER BY id DESC")
        return [self._from_row(row) for row in rows]

    def verify(self, backup_id: int) -> tuple[bool, str]:
        backup = self.get(backup_id)
        if backup is None:
            return False, "unknown backup"
        path = backup.path
        if not os.path.exists(path):
            return False, "backup file missing"
        current = _hash_file(path)
        if current == backup.sha256:
            return True, "backup integrity verified"
        return False, "backup hash mismatch — file altered"

    def restore(self, backup_id: int, approve: bool = False, target_path: str | None = None) -> str:
        """Restore a verified backup to ``target_path`` (default: live DB path)."""
        backup = self.get(backup_id)
        if backup is None:
            raise ValueError(f"Unknown backup: {backup_id}")
        if not approve:
            raise ValueError("approval required — rerun with approval")
        ok, reason = self.verify(backup_id)
        if not ok:
            raise ValueError(f"refusing to restore unverified backup: {reason}")
        if not os.path.exists(backup.path):
            raise FileNotFoundError(f"Backup file missing: {backup.path}")
        destination = target_path or str(self.config.db_path)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        # Validate the file is a real SQLite database before overwriting.
        try:
            conn = sqlite3.connect(backup.path)
            conn.execute("PRAGMA integrity_check").fetchone()
            conn.close()
        except sqlite3.Error as exc:
            raise ValueError(f"backup is not a valid database: {exc}") from exc
        tmp = destination + ".restore-tmp"
        shutil.copy2(backup.path, tmp)
        os.replace(tmp, destination)
        self.audit.record(
            event_type="backup.restore",
            actor="system",
            action="backup.restore",
            target=destination,
            outcome="success",
            payload={"backup_id": backup.backup_id},
        )
        return destination

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Backup:
        return Backup(
            id=row["id"],
            backup_id=row["backup_id"],
            path=row["path"],
            kind=row["kind"],
            size_bytes=row["size_bytes"],
            sha256=row["sha256"],
            created_at=row["created_at"],
        )