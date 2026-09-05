"""Purple team subsystem (spec 08 #28).

A purple exercise coordinates the red side (adversary emulation producing
findings) with the blue side (SOC detection producing alerts). KSEC keeps it
deterministic: one service records the exercise lifecycle and tallies
observable outcomes — findings (red), alerts (blue) and rules that fired
(detection coverage) — without executing anything.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from ksec.db.connection import Database
from ksec.identity.users import now_utc

VALID_STATUS = ("planned", "running", "completed", "cancelled")


@dataclass(frozen=True)
class PurpleExercise:
    id: int
    name: str
    description: str
    engagement_id: int | None
    status: str
    red_findings: int
    blue_alerts: int
    detections_fired: int
    created_by: str
    created_at: str
    completed_at: str | None


class PurpleService:
    def __init__(self, db: Database, audit=None, notifications=None):
        self.db = db
        self.audit = audit
        self.notifications = notifications

    def create(
        self,
        *,
        name: str,
        description: str = "",
        engagement_id: int | None = None,
        created_by: str = "",
    ) -> PurpleExercise:
        if not name.strip():
            raise ValueError("name is required")
        cursor = self.db.execute(
            "INSERT INTO purple_exercises (name, description, engagement_id, status,"
            " red_findings, blue_alerts, detections_fired, created_by, created_at)"
            " VALUES (?, ?, ?, 'planned', 0, 0, 0, ?, ?)",
            (name.strip(), description, engagement_id, created_by, now_utc()),
        )
        exercise = self.get(cursor.lastrowid)
        assert exercise is not None
        self._audit("purple.exercise.create", actor=created_by, target=str(exercise.id))
        return exercise

    def get(self, exercise_id: int) -> PurpleExercise | None:
        row = self.db.query_one(
            "SELECT * FROM purple_exercises WHERE id = ?", (exercise_id,)
        )
        return self._from_row(row) if row else None

    def list(self) -> list[PurpleExercise]:
        rows = self.db.query_all("SELECT * FROM purple_exercises ORDER BY id DESC")
        return [self._from_row(row) for row in rows]

    def start(self, exercise_id: int, actor: str = "") -> PurpleExercise:
        exercise = self.get(exercise_id)
        if exercise is None:
            raise ValueError(f"unknown purple exercise: {exercise_id}")
        if exercise.status not in ("planned", "cancelled"):
            raise ValueError(f"cannot start exercise in status {exercise.status}")
        self.db.execute(
            "UPDATE purple_exercises SET status = 'running' WHERE id = ?", (exercise_id,)
        )
        self._audit("purple.exercise.start", actor=actor or "purple", target=str(exercise_id))
        updated = self.get(exercise_id)
        assert updated is not None
        return updated

    def complete(self, exercise_id: int, actor: str = "") -> PurpleExercise:
        """Tally observable outcomes and close the exercise.

        Deterministic: counts the findings of the linked engagement (the red
        side's observable output), open SOC alerts (blue side detections) and
        the detection rules that fired for those alerts.
        """
        exercise = self.get(exercise_id)
        if exercise is None:
            raise ValueError(f"unknown purple exercise: {exercise_id}")
        if exercise.status == "completed":
            return exercise
        engagement = exercise.engagement_id
        if engagement is None:
            red = self.db.query_one("SELECT COUNT(*) AS c FROM findings")
            red_count = int(red["c"]) if red else 0
        else:
            red = self.db.query_one(
                "SELECT COUNT(*) AS c FROM findings WHERE engagement_id = ?", (engagement,)
            )
            red_count = int(red["c"]) if red else 0
        blue = self.db.query_one("SELECT COUNT(*) AS c FROM alerts WHERE status != 'closed'")
        blue_count = int(blue["c"]) if blue else 0
        fired = self.db.query_one(
            "SELECT COUNT(*) AS c FROM alerts WHERE rule_id IS NOT NULL"
        )
        fired_count = int(fired["c"]) if fired else 0
        self.db.execute(
            "UPDATE purple_exercises SET status = 'completed', red_findings = ?,"
            " blue_alerts = ?, detections_fired = ?, completed_at = ? WHERE id = ?",
            (red_count, blue_count, fired_count, now_utc(), exercise_id),
        )
        if self.notifications:
            self.notifications.record(
                event_type="purple.exercise.completed",
                title=f"Purple exercise completed: {exercise.name}",
                body=f"red_findings={red_count} blue_alerts={blue_count} "
                     f"detections_fired={fired_count}",
            )
        self._audit("purple.exercise.complete", actor=actor or "purple", target=str(exercise_id))
        updated = self.get(exercise_id)
        assert updated is not None
        return updated

    def summary(self, exercise_id: int) -> dict | None:
        exercise = self.get(exercise_id)
        if exercise is None:
            return None
        data = self._to_dict(exercise)
        if exercise.status == "completed":
            coverage = (
                round((exercise.detections_fired / exercise.red_findings) * 100, 1)
                if exercise.red_findings
                else 0.0
            )
            data["detection_coverage"] = coverage
            data["verdict"] = "good" if coverage >= 60 else ("partial" if coverage >= 25 else "gap")
        return data

    def remove(self, exercise_id: int) -> bool:
        cursor = self.db.execute(
            "DELETE FROM purple_exercises WHERE id = ?", (exercise_id,)
        )
        if cursor.rowcount > 0:
            self._audit("purple.exercise.delete", target=str(exercise_id))
            return True
        return False

    def _audit(self, event_type: str, actor: str = "", target: str | None = None) -> None:
        if self.audit:
            self.audit.record(
                event_type=event_type,
                actor=actor or None,
                action=event_type,
                target=target,
                outcome="success",
            )

    @staticmethod
    def _from_row(row: sqlite3.Row) -> PurpleExercise:
        return PurpleExercise(
            id=row["id"],
            name=row["name"],
            description=row["description"] or "",
            engagement_id=row["engagement_id"],
            status=row["status"],
            red_findings=row["red_findings"] or 0,
            blue_alerts=row["blue_alerts"] or 0,
            detections_fired=row["detections_fired"] or 0,
            created_by=row["created_by"] or "",
            created_at=row["created_at"],
            completed_at=row["completed_at"],
        )

    @staticmethod
    def _to_dict(exercise: PurpleExercise) -> dict:
        return {
            "id": exercise.id,
            "name": exercise.name,
            "description": exercise.description,
            "engagement_id": exercise.engagement_id,
            "status": exercise.status,
            "red_findings": exercise.red_findings,
            "blue_alerts": exercise.blue_alerts,
            "detections_fired": exercise.detections_fired,
            "created_by": exercise.created_by,
            "created_at": exercise.created_at,
            "completed_at": exercise.completed_at,
        }
