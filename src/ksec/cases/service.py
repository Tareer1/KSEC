"""Case engine (spec: CASE MANAGEMENT).

Cases tie together findings, evidence, assets, notes and a status lifecycle.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from ksec.audit.service import AuditService
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


@dataclass(frozen=True)
class CaseNote:
    id: int
    case_id: int
    author: str
    content: str
    created_at: str


@dataclass(frozen=True)
class CaseEvent:
    id: int
    case_id: int
    event_type: str
    details: str
    actor: str
    created_at: str


class CaseService:
    def __init__(self, db: Database, audit: AuditService | None = None):
        self.db = db
        self.audit = audit

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
        case = self.get(cursor.lastrowid)
        assert case is not None
        self._record_event(
            case.id,
            event_type="created",
            details=f"case created ({case.title})",
            actor=owner or "",
        )
        if self.audit:
            self.audit.record(
                event_type="case.create",
                actor=owner or None,
                workspace="BLUE_TEAM",
                action="case.create",
                target=f"case:{case.id}",
            )
        return case

    def get(self, case_id: int) -> Case | None:
        row = self.db.query_one("SELECT * FROM cases WHERE id = ?", (case_id,))
        return self._from_row(row) if row else None

    def list(self) -> list[Case]:
        rows = self.db.query_all("SELECT * FROM cases ORDER BY id DESC")
        return [self._from_row(row) for row in rows]

    def add_finding(self, case_id: int, finding_id: int, actor: str | None = None) -> None:
        if self.get(case_id) is None:
            raise ValueError(f"Unknown case: {case_id}")
        self.db.execute(
            "INSERT OR IGNORE INTO case_findings (case_id, finding_id) VALUES (?, ?)",
            (case_id, finding_id),
        )
        self._record_event(
            case_id,
            event_type="finding_linked",
            details=f"finding {finding_id} linked",
            actor=actor or "",
        )
        if self.audit:
            self.audit.record(
                event_type="case.add_finding",
                actor=actor,
                workspace="BLUE_TEAM",
                action="case.add_finding",
                target=f"case:{case_id} finding:{finding_id}",
            )

    def findings(self, case_id: int) -> list[sqlite3.Row]:
        return self.db.query_all(
            "SELECT f.* FROM findings f JOIN case_findings cf ON cf.finding_id = f.id"
            " WHERE cf.case_id = ? ORDER BY f.id",
            (case_id,),
        )

    def set_status(self, case_id: int, status: str, actor: str | None = None) -> Case:
        if status not in VALID_STATUS:
            raise ValueError(f"Invalid status: {status}")
        self.db.execute(
            "UPDATE cases SET status = ?, updated_at = ? WHERE id = ?",
            (status, now_utc(), case_id),
        )
        case = self.get(case_id)
        if case is None:
            raise ValueError(f"Unknown case: {case_id}")
        self._record_event(
            case_id,
            event_type="status",
            details=f"status -> {status}",
            actor=actor or "",
        )
        if self.audit:
            self.audit.record(
                event_type="case.status",
                actor=actor,
                workspace="BLUE_TEAM",
                action=f"case.status:{status}",
                target=f"case:{case_id}",
            )
        return case

    def close(self, case_id: int, actor: str | None = None) -> Case:
        return self.set_status(case_id, "closed", actor=actor)

    def reopen(self, case_id: int, reason: str = "", actor: str | None = None) -> Case:
        """Reopen a closed case; the reason is recorded (spec 05 #92)."""
        case = self.get(case_id)
        if case is None:
            raise ValueError(f"Unknown case: {case_id}")
        self.db.execute(
            "UPDATE cases SET status = 'open', updated_at = ? WHERE id = ?",
            (now_utc(), case_id),
        )
        self._record_event(
            case_id,
            event_type="reopen",
            details=reason or "reopened",
            actor=actor or "",
        )
        if self.audit:
            self.audit.record(
                event_type="case.reopen",
                actor=actor,
                workspace="BLUE_TEAM",
                action="case.reopen",
                target=f"case:{case_id}",
                payload={"reason": reason or ""},
            )
        updated = self.get(case_id)
        assert updated is not None
        return updated

    def add_note(self, case_id: int, content: str, author: str = "") -> CaseNote:
        """Append a case note (spec 05 #36 — notes are never overwritten)."""
        if self.get(case_id) is None:
            raise ValueError(f"Unknown case: {case_id}")
        if not content or not content.strip():
            raise ValueError("Note content must not be empty")
        now = now_utc()
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO case_notes (case_id, author, content, created_at)"
                " VALUES (?, ?, ?, ?)",
                (case_id, author, content.strip(), now),
            )
        self._record_event(
            case_id,
            event_type="note",
            details="note added",
            actor=author or "",
        )
        if self.audit:
            self.audit.record(
                event_type="case.note",
                actor=author or None,
                workspace="BLUE_TEAM",
                action="case.note",
                target=f"case:{case_id}",
            )
        return self.get_note(cursor.lastrowid)

    def get_note(self, note_id: int) -> CaseNote:
        row = self.db.query_one("SELECT * FROM case_notes WHERE id = ?", (note_id,))
        assert row is not None
        return CaseNote(
            id=row["id"], case_id=row["case_id"], author=row["author"],
            content=row["content"], created_at=row["created_at"],
        )

    def notes(self, case_id: int) -> list[CaseNote]:
        rows = self.db.query_all(
            "SELECT * FROM case_notes WHERE case_id = ? ORDER BY id", (case_id,)
        )
        return [
            CaseNote(
                id=r["id"], case_id=r["case_id"], author=r["author"],
                content=r["content"], created_at=r["created_at"],
            )
            for r in rows
        ]

    def events(self, case_id: int) -> list[CaseEvent]:
        """Case timeline, oldest first (spec 08 #42)."""
        rows = self.db.query_all(
            "SELECT * FROM case_events WHERE case_id = ? ORDER BY id", (case_id,)
        )
        return [
            CaseEvent(
                id=r["id"], case_id=r["case_id"], event_type=r["event_type"],
                details=r["details"], actor=r["actor"], created_at=r["created_at"],
            )
            for r in rows
        ]

    def _record_event(self, case_id: int, event_type: str, details: str, actor: str) -> None:
        self.db.execute(
            "INSERT INTO case_events (case_id, event_type, details, actor, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (case_id, event_type, details, actor, now_utc()),
        )

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