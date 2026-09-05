"""Event-driven workflow triggers (spec 07 — beyond cron schedules).

A trigger binds an event pattern (event_type + glob on the event payload) to
a workflow that should run when that event occurs. Firing re-validates the
workflow against the current scope, exactly like a normal run — a trigger
never bypasses authorization.
"""
from __future__ import annotations

import fnmatch
import sqlite3
from dataclasses import dataclass

from ksec.db.connection import Database
from ksec.identity.users import now_utc


@dataclass(frozen=True)
class WorkflowTrigger:
    id: int
    name: str
    event_type: str
    event_glob: str
    workflow: str
    target_field: str
    workspace: str
    enabled: bool
    created_by: str
    created_at: str
    last_fired_at: str | None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "event_type": self.event_type,
            "event_glob": self.event_glob,
            "workflow": self.workflow,
            "target_field": self.target_field,
            "workspace": self.workspace,
            "enabled": self.enabled,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "last_fired_at": self.last_fired_at,
        }


class TriggerStore:
    def __init__(self, db: Database):
        self.db = db

    def create(
        self,
        *,
        name: str,
        event_type: str,
        workflow: str,
        event_glob: str = "*",
        target_field: str = "target",
        workspace: str = "RED_TEAM",
        created_by: str = "",
    ) -> WorkflowTrigger:
        if not name.strip() or not event_type.strip() or not workflow.strip():
            raise ValueError("name, event_type and workflow are required")
        cursor = self.db.execute(
            "INSERT INTO workflow_triggers (name, event_type, event_glob, workflow,"
            " target_field, workspace, enabled, created_by, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (
                name.strip(), event_type.strip(), event_glob or "*", workflow.strip(),
                target_field or "target", workspace, created_by, now_utc(),
            ),
        )
        trigger = self.get(cursor.lastrowid)
        assert trigger is not None
        return trigger

    def get(self, trigger_id: int) -> WorkflowTrigger | None:
        row = self.db.query_one(
            "SELECT * FROM workflow_triggers WHERE id = ?", (trigger_id,)
        )
        return self._from_row(row) if row else None

    def list(self, enabled_only: bool = False) -> list[WorkflowTrigger]:
        sql = "SELECT * FROM workflow_triggers"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY id"
        return [self._from_row(row) for row in self.db.query_all(sql)]

    def remove(self, trigger_id: int) -> bool:
        cursor = self.db.execute(
            "DELETE FROM workflow_triggers WHERE id = ?", (trigger_id,)
        )
        return cursor.rowcount > 0

    def set_enabled(self, trigger_id: int, enabled: bool) -> WorkflowTrigger | None:
        self.db.execute(
            "UPDATE workflow_triggers SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, trigger_id),
        )
        return self.get(trigger_id)

    def matches(self, event_type: str, payload: dict | None = None) -> list[WorkflowTrigger]:
        """Return enabled triggers whose event_type + glob match the event."""
        payload = payload or {}
        hits: list[WorkflowTrigger] = []
        for trigger in self.list(enabled_only=True):
            if trigger.event_type != event_type:
                continue
            candidate = str(payload.get(trigger.target_field) or "")
            if fnmatch.fnmatch(candidate, trigger.event_glob):
                hits.append(trigger)
        return hits

    def mark_fired(self, trigger_id: int) -> None:
        self.db.execute(
            "UPDATE workflow_triggers SET last_fired_at = ? WHERE id = ?",
            (now_utc(), trigger_id),
        )

    @staticmethod
    def _from_row(row: sqlite3.Row) -> WorkflowTrigger:
        return WorkflowTrigger(
            id=row["id"],
            name=row["name"],
            event_type=row["event_type"],
            event_glob=row["event_glob"] or "*",
            workflow=row["workflow"],
            target_field=row["target_field"] or "target",
            workspace=row["workspace"] or "RED_TEAM",
            enabled=bool(row["enabled"]),
            created_by=row["created_by"] or "",
            created_at=row["created_at"],
            last_fired_at=row["last_fired_at"],
        )
