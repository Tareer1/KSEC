"""Job model and repository (spec: JOB MANAGER).

A job is one execution task: capability + target + options, with a full
lifecycle from QUEUED to COMPLETED/FAILED/CANCELLED.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field

from ksec.db.connection import Database
from ksec.identity.users import now_utc

JOB_STATES = (
    "QUEUED",
    "VALIDATING",
    "READY",
    "RUNNING",
    "PAUSED",
    "CANCELLING",
    "CANCELLED",
    "COMPLETED",
    "FAILED",
    "RECOVERING",
    "RETRYING",
)

_TERMINAL = ("COMPLETED", "FAILED", "CANCELLED")


@dataclass(frozen=True)
class Job:
    id: str
    session_id: str | None
    user_id: int | None
    workspace: str
    workflow: str
    capability: str
    target: str
    options: dict
    state: str
    priority: int
    created_at: str
    started_at: str | None
    completed_at: str | None
    exit_code: int | None
    error: str
    result: dict

    @property
    def is_terminal(self) -> bool:
        return self.state in _TERMINAL


class JobRepository:
    def __init__(self, db: Database):
        self.db = db

    def create(
        self,
        *,
        capability: str,
        target: str = "",
        options: dict | None = None,
        session_id: str | None = None,
        user_id: int | None = None,
        workspace: str = "",
        workflow: str = "",
        priority: int = 0,
    ) -> Job:
        job_id = uuid.uuid4().hex
        now = now_utc()
        self.db.execute(
            "INSERT INTO jobs (id, session_id, user_id, workspace, workflow, capability,"
            " target, options, state, priority, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?,"
            " 'QUEUED', ?, ?)",
            (
                job_id,
                session_id,
                user_id,
                workspace,
                workflow,
                capability,
                target,
                json.dumps(options or {}),
                priority,
                now,
            ),
        )
        job = self.get(job_id)
        assert job is not None
        return job

    def get(self, job_id: str) -> Job | None:
        row = self.db.query_one("SELECT * FROM jobs WHERE id = ?", (job_id,))
        return self._from_row(row) if row else None

    def list(self, limit: int = 100, state: str | None = None) -> list[Job]:
        sql = "SELECT * FROM jobs"
        params: list = []
        if state:
            sql += " WHERE state = ?"
            params.append(state)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        return [self._from_row(row) for row in self.db.query_all(sql, params)]

    def set_state(self, job_id: str, state: str, **fields) -> Job:
        if state not in JOB_STATES:
            raise ValueError(f"Unknown job state: {state}")
        assignments = ["state = ?"]
        params: list = [state]
        for key, value in fields.items():
            if key not in ("started_at", "completed_at", "exit_code", "error", "result"):
                raise ValueError(f"Unsupported job field: {key}")
            assignments.append(f"{key} = ?")
            params.append(json.dumps(value) if key == "result" else value)
        params.append(job_id)
        self.db.execute(
            f"UPDATE jobs SET {', '.join(assignments)} WHERE id = ?", params
        )
        job = self.get(job_id)
        assert job is not None
        return job

    def fail(self, job_id: str, error: str, exit_code: int | None = None) -> Job:
        return self.set_state(
            job_id, "FAILED", error=error[:2000], exit_code=exit_code, completed_at=now_utc()
        )

    def complete(self, job_id: str, result: dict, exit_code: int = 0) -> Job:
        return self.set_state(
            job_id, "COMPLETED", result=result, exit_code=exit_code, completed_at=now_utc()
        )

    def mark_interrupted(self) -> list[str]:
        """Recovery: jobs left RUNNING by a previous process become FAILED.

        Spec: never blindly resume an unsafe operation.
        """
        stuck = self.db.query_all("SELECT id FROM jobs WHERE state = 'RUNNING'")
        ids = [row["id"] for row in stuck]
        for job_id in ids:
            self.fail(job_id, "Interrupted: process terminated before completion")
        return ids

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Job:
        return Job(
            id=row["id"],
            session_id=row["session_id"],
            user_id=row["user_id"],
            workspace=row["workspace"] or "",
            workflow=row["workflow"] or "",
            capability=row["capability"],
            target=row["target"] or "",
            options=json.loads(row["options"] or "{}"),
            state=row["state"],
            priority=row["priority"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            exit_code=row["exit_code"],
            error=row["error"] or "",
            result=json.loads(row["result"] or "{}"),
        )