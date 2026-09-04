"""Recurring job schedules: 5-field cron matching + storage.

Minimal, deterministic cron: fields are ``minute hour day-of-month month
day-of-week`` and support numbers, ``*``, ``*/step`` and comma lists.
No external dependency — KSEC stays zero-dependency.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime

from ksec.db.connection import Database
from ksec.identity.users import now_utc


def cron_matches(cron: str, when: datetime) -> bool:
    """Return True when ``when`` matches the 5-field cron expression."""
    fields = cron.strip().split()
    if len(fields) != 5:
        return False
    values = (when.minute, when.hour, when.day, when.month, when.isoweekday())
    for field, value in zip(fields, values):
        if not _field_matches(field, value):
            return False
    return True


def _field_matches(field: str, value: int) -> bool:
    for part in field.split(","):
        part = part.strip()
        if part in ("*", "?"):
            return True
        if part.startswith("*/"):
            step = _int(part[2:])
            if step and value % step == 0:
                return True
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.isdigit() and hi.isdigit() and int(lo) <= value <= int(hi):
                return True
            continue
        if part.isdigit() and int(part) == value:
            return True
    return False


def _int(text: str) -> int | None:
    try:
        return int(text)
    except ValueError:
        return None


def current_cron_minute() -> str:
    """A cron expression matching exactly 'right now' (for tests / --now)."""
    now = datetime.utcnow()
    return f"{now.minute} {now.hour} {now.day} {now.month} *"


@dataclass(frozen=True)
class Schedule:
    id: int
    capability: str
    target: str
    options: dict
    cron: str
    workspace: str
    user_id: int | None
    engagement_id: int | None
    enabled: bool
    last_run_at: str | None
    created_at: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "capability": self.capability,
            "target": self.target,
            "options": self.options,
            "cron": self.cron,
            "workspace": self.workspace,
            "user_id": self.user_id,
            "engagement_id": self.engagement_id,
            "enabled": self.enabled,
            "last_run_at": self.last_run_at,
            "created_at": self.created_at,
        }


class ScheduleStore:
    def __init__(self, db: Database):
        self.db = db

    def create(
        self,
        *,
        capability: str,
        target: str,
        cron: str,
        options: dict | None = None,
        workspace: str = "RED_TEAM",
        user_id: int | None = None,
        engagement_id: int | None = None,
    ) -> Schedule:
        if not cron_matches(cron, datetime.utcnow().replace(second=0, microsecond=0)):
            # Validate the expression shape even if it does not match now.
            if len(cron.strip().split()) != 5:
                raise ValueError(
                    "cron must be 5 fields: minute hour day-of-month month day-of-week "
                    "(e.g. '0 6 * * *' for daily 06:00)"
                )
        cursor = self.db.execute(
            "INSERT INTO job_schedules (capability, target, options, cron, workspace,"
            " user_id, engagement_id, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (capability.strip(), target.strip(), json.dumps(options or {}), cron.strip(),
             workspace, user_id, engagement_id, now_utc()),
        )
        schedule = self.get(cursor.lastrowid)
        assert schedule is not None
        return schedule

    def get(self, schedule_id: int) -> Schedule | None:
        row = self.db.query_one(
            "SELECT * FROM job_schedules WHERE id = ?", (schedule_id,)
        )
        return self._from_row(row) if row else None

    def list(self, enabled_only: bool = False) -> list[Schedule]:
        sql = "SELECT * FROM job_schedules"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY id"
        return [self._from_row(row) for row in self.db.query_all(sql)]

    def remove(self, schedule_id: int) -> bool:
        cursor = self.db.execute(
            "DELETE FROM job_schedules WHERE id = ?", (schedule_id,)
        )
        return cursor.rowcount > 0

    def set_enabled(self, schedule_id: int, enabled: bool) -> Schedule | None:
        self.db.execute(
            "UPDATE job_schedules SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, schedule_id),
        )
        return self.get(schedule_id)

    def mark_run(self, schedule_id: int) -> None:
        self.db.execute(
            "UPDATE job_schedules SET last_run_at = ? WHERE id = ?",
            (now_utc(), schedule_id),
        )

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Schedule:
        try:
            options = json.loads(row["options"] or "{}")
        except json.JSONDecodeError:
            options = {}
        return Schedule(
            id=row["id"],
            capability=row["capability"],
            target=row["target"],
            options=options,
            cron=row["cron"],
            workspace=row["workspace"],
            user_id=row["user_id"],
            engagement_id=row["engagement_id"],
            enabled=bool(row["enabled"]),
            last_run_at=row["last_run_at"],
            created_at=row["created_at"],
        )