"""Case engine (spec: CASE MANAGEMENT).

Cases tie together findings, evidence, assets, notes and a status lifecycle.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from ksec.db.connection import Database
from ksec.identity.users import now_utc

VALID_STATUS = ("open", "in_progress", "resolved", "closed")
VALID_SEVERITY = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Case:
    id: int
    engagement_id: int | None
    title: str
    description: str
    severity: str
    status: str
    owner: str
    created_at: str
    updated_at: str


class CaseService:
    def __init__(self, db: Database):
        self.db = db

    def create(
        self,
        *,
        title: str,
        description: str = "",
        severity: str = "info",
        owner: str = "",
        engagement_id: int | None = None,
    ) -> Case:
        if not title or not title.strip():
            raise ValueError("Case title must not be empty")
        if severity not in VALID_SEVERITY:
            raise ValueError(f"Invalid severity: {severity}")
        now = now_utc()
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO cases (engagement_id, title, description, severity, status,"
                " owner, created_at, updated_at) VALUES (?, ?, ?, ?, 'open', ?, ?, ?)",
                (engagement_id, title.strip(), description, severity, owner, now, now),
            )
        return self.get(cursor.lastrowid)

    def get(self, case_id: int) -> Case | None:
        row = self.db.query_one("SELECT * FROM cases WHERE id = ?", (case_id,))
        return self._from_row(row) if row else None

    def list(self) -> list[Case]:
        rows = self.db.query_all("SELECT * FROM cases ORDER BY id DESC")
        return [self._from_row(row) for row in rows]

    def add_finding(self, case_id: int, finding_id: int) -> None:
        if self.get(case_id) is None:
            raise ValueError(f"Unknown case: {case_id}")
        self.db.execute(
            "INSERT OR IGNORE INTO case_findings (case_id, finding_id) VALUES (?, ?)",
            (case_id, finding_id),
        )

    def findings(self, case_id: int) -> list[sqlite3.Row]:
        return self.db.query_all(
            "SELECT f.* FROM findings f JOIN case_findings cf ON cf.finding_id = f.id"
            " WHERE cf.case_id = ? ORDER BY f.id",
            (case_id,),
        )

    def set_status(self, case_id: int, status: str) -> Case:
        if status not in VALID_STATUS:
            raise ValueError(f"Invalid status: {status}")
        self.db.execute(
            "UPDATE cases SET status = ?, updated_at = ? WHERE id = ?",
            (status, now_utc(), case_id),
        )
        case = self.get(case_id)
        if case is None:
            raise ValueError(f"Unknown case: {case_id}")
        return case

    def close(self, case_id: int) -> Case:
        return self.set_status(case_id, "closed")

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Case:
        return Case(
            id=row["id"],
            engagement_id=row["engagement_id"],
            title=row["title"],
            description=row["description"],
            severity=row["severity"],
            status=row["status"],
            owner=row["owner"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )