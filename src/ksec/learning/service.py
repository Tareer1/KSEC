"""Learning service: per-user progress across the curriculum."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from ksec.db.connection import Database
from ksec.identity.users import now_utc
from ksec.learning.curriculum import (
    LEARNING_LEVELS,
    find_lesson,
    lesson_count,
    phases,
)

VALID_STATUS = ("pending", "in_progress", "completed")


@dataclass(frozen=True)
class LessonProgress:
    lesson_id: str
    phase: int
    title: str
    status: str
    completed_at: str | None


class LearningService:
    def __init__(self, db: Database):
        self.db = db

    def start_lesson(self, user_id: int, lesson_id: str) -> None:
        if find_lesson(lesson_id) is None:
            raise ValueError(f"Unknown lesson: {lesson_id}")
        self.db.execute(
            "INSERT INTO learning_progress (user_id, phase, lesson_id, status)"
            " VALUES (?, ?, ?, 'in_progress')"
            " ON CONFLICT (user_id, lesson_id) DO UPDATE SET status = 'in_progress'",
            (user_id, find_lesson(lesson_id)[0].number, lesson_id),
        )

    def complete_lesson(self, user_id: int, lesson_id: str) -> None:
        if find_lesson(lesson_id) is None:
            raise ValueError(f"Unknown lesson: {lesson_id}")
        phase_number = find_lesson(lesson_id)[0].number
        self.db.execute(
            "INSERT INTO learning_progress (user_id, phase, lesson_id, status, completed_at)"
            " VALUES (?, ?, ?, 'completed', ?)"
            " ON CONFLICT (user_id, lesson_id) DO UPDATE SET status = 'completed',"
            " completed_at = ?",
            (user_id, phase_number, lesson_id, now_utc(), now_utc()),
        )

    def progress(self, user_id: int) -> dict:
        rows = self.db.query_all(
            "SELECT lesson_id, phase, status, completed_at FROM learning_progress"
            " WHERE user_id = ?",
            (user_id,),
        )
        by_lesson = {row["lesson_id"]: row for row in rows}
        completed = sum(1 for row in rows if row["status"] == "completed")
        total = lesson_count()
        phase_summary = []
        for phase in phases():
            done = 0
            for lesson in phase.lessons:
                row = by_lesson.get(lesson.id)
                if row is not None and row["status"] == "completed":
                    done += 1
            phase_summary.append(
                {
                    "phase": phase.number,
                    "title": phase.title,
                    "completed": done,
                    "total": len(phase.lessons),
                }
            )
        level = self.level_for_completion(completed, total)
        return {
            "completed_lessons": completed,
            "total_lessons": total,
            "percent": round((completed / total) * 100, 1) if total else 0.0,
            "level": level,
            "level_name": LEARNING_LEVELS.get(level, "Explorer"),
            "phases": phase_summary,
        }

    @staticmethod
    def level_for_completion(completed: int, total: int) -> int:
        ratio = (completed / total) if total else 0.0
        if ratio >= 0.9:
            return 5
        if ratio >= 0.6:
            return 4
        if ratio >= 0.35:
            return 3
        if ratio >= 0.15:
            return 2
        return 1

    def lesson_status(self, user_id: int, lesson_id: str) -> LessonProgress | None:
        row = self.db.query_one(
            "SELECT lesson_id, phase, status, completed_at FROM learning_progress"
            " WHERE user_id = ? AND lesson_id = ?",
            (user_id, lesson_id),
        )
        if row is None:
            return None
        lesson = find_lesson(lesson_id)
        return LessonProgress(
            lesson_id=row["lesson_id"],
            phase=row["phase"],
            title=lesson[1].title if lesson else lesson_id,
            status=row["status"],
            completed_at=row["completed_at"],
        )