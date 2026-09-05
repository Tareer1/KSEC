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


@dataclass(frozen=True)
class CustodyEvent:
    id: int
    evidence_id: int
    action: str
    actor: str
    previous_state: str
    new_state: str
    reason: str
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
        evidence = self.get(cursor.lastrowid)
        assert evidence is not None
        self.record_custody(
            evidence.id,
            action="CAPTURED",
            actor=operator or "system",
            new_state="captured",
            reason=f"collected by {tool or 'manual'}",
        )
        return evidence

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
            self.record_custody(
                evidence_id,
                action="VERIFIED",
                actor="system",
                previous_state="captured",
                new_state="verified",
                reason="hash match",
            )
            return True, "integrity verified"
        self.record_custody(
            evidence_id,
            action="VERIFIED",
            actor="system",
            previous_state="captured",
            new_state="integrity_failure",
            reason="content hash mismatch — evidence was altered",
        )
        return False, "content hash mismatch — evidence was altered"

    def record_custody(
        self,
        evidence_id: int,
        *,
        action: str,
        actor: str = "system",
        previous_state: str = "",
        new_state: str = "",
        reason: str = "",
    ) -> CustodyEvent:
        """Append a chain-of-custody event (spec 05 #30)."""
        now = now_utc()
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO evidence_custody (evidence_id, action, actor, previous_state,"
                " new_state, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (evidence_id, action.upper(), actor, previous_state, new_state, reason, now),
            )
        row = self.db.query_one(
            "SELECT * FROM evidence_custody WHERE id = ?", (cursor.lastrowid,)
        )
        assert row is not None
        return CustodyEvent(
            id=row["id"],
            evidence_id=row["evidence_id"],
            action=row["action"],
            actor=row["actor"],
            previous_state=row["previous_state"],
            new_state=row["new_state"],
            reason=row["reason"],
            created_at=row["created_at"],
        )

    def custody_log(self, evidence_id: int) -> list[CustodyEvent]:
        """Full chain of custody for one evidence object, oldest first."""
        rows = self.db.query_all(
            "SELECT * FROM evidence_custody WHERE evidence_id = ? ORDER BY id",
            (evidence_id,),
        )
        return [
            CustodyEvent(
                id=r["id"],
                evidence_id=r["evidence_id"],
                action=r["action"],
                actor=r["actor"],
                previous_state=r["previous_state"],
                new_state=r["new_state"],
                reason=r["reason"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

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