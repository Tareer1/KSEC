"""Evidence management (spec: EVIDENCE MANAGEMENT).

Evidence is hashed (SHA-256) at collection time. Verification recomputes the
hash from the stored content — evidence must never silently change.
"""
from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass

from ksec.db.connection import Database
from ksec.identity.users import now_utc


def hash_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Evidence:
    id: int
    engagement_id: int | None
    session_id: str | None
    tool: str
    tool_version: str
    operator: str
    collection_method: str
    source: str
    sha256: str
    content: str
    created_at: str


class EvidenceService:
    def __init__(self, db: Database):
        self.db = db

    def add(
        self,
        content: str,
        *,
        tool: str = "",
        tool_version: str = "",
        operator: str = "",
        collection_method: str = "",
        source: str = "",
        session_id: str | None = None,
        engagement_id: int | None = None,
    ) -> Evidence:
        digest = hash_content(content)
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO evidence (engagement_id, session_id, tool, tool_version, operator,"
                " collection_method, source, content_hash, content, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    engagement_id,
                    session_id,
                    tool,
                    tool_version,
                    operator,
                    collection_method,
                    source,
                    digest,
                    content,
                    now_utc(),
                ),
            )
        return self.get(cursor.lastrowid)

    def get(self, evidence_id: int) -> Evidence | None:
        row = self.db.query_one("SELECT * FROM evidence WHERE id = ?", (evidence_id,))
        return self._from_row(row) if row else None

    def list(self, engagement_id: int | None = None) -> list[Evidence]:
        if engagement_id is not None:
            rows = self.db.query_all(
                "SELECT * FROM evidence WHERE engagement_id = ? ORDER BY id",
                (engagement_id,),
            )
        else:
            rows = self.db.query_all("SELECT * FROM evidence ORDER BY id")
        return [self._from_row(row) for row in rows]

    def verify(self, evidence_id: int) -> tuple[bool, str]:
        """Recompute the hash from stored content and compare."""
        evidence = self.get(evidence_id)
        if evidence is None:
            return False, "unknown evidence"
        current = hash_content(evidence.content)
        if current == evidence.sha256:
            return True, "integrity verified"
        return False, "content hash mismatch — evidence was altered"

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Evidence:
        return Evidence(
            id=row["id"],
            engagement_id=row["engagement_id"],
            session_id=row["session_id"],
            tool=row["tool"],
            tool_version=row["tool_version"],
            operator=row["operator"],
            collection_method=row["collection_method"],
            source=row["source"],
            sha256=row["content_hash"],
            content=row["content"],
            created_at=row["created_at"],
        )