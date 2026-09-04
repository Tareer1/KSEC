"""Append-only audit logging.

Security-relevant actions produce audit events (login, session changes,
permission changes, tool execution, ...). Records are append-only: ordinary
UI/API operations can never modify historical records (spec: Audit).
"""
from __future__ import annotations

import json
import sqlite3
import uuid

from ksec.config.loader import KsecConfig
from ksec.db.connection import Database
from ksec.identity.users import now_utc


class AuditService:
    def __init__(self, db: Database, config: KsecConfig):
        self.db = db
        self.config = config

    def record(
        self,
        *,
        event_type: str,
        actor: str | None = None,
        session_id: str | None = None,
        workspace: str | None = None,
        action: str | None = None,
        target: str | None = None,
        outcome: str = "success",
        payload: dict | None = None,
        correlation_id: str | None = None,
    ) -> str:
        """Record an audit event; returns its event ID."""
        event_id = uuid.uuid4().hex
        if not self.config.audit_enabled:
            return event_id
        self.db.execute(
            "INSERT INTO audit_log (event_id, event_type, actor, session_id, workspace, action,"
            " target, outcome, payload, correlation_id, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                event_type,
                actor,
                session_id,
                workspace,
                action,
                target,
                outcome,
                json.dumps(payload or {}),
                correlation_id,
                now_utc(),
            ),
        )
        return event_id

    def list(
        self, limit: int = 100, event_type: str | None = None, actor: str | None = None
    ) -> list[sqlite3.Row]:
        sql = "SELECT * FROM audit_log"
        clauses: list[str] = []
        params: list = []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if actor:
            clauses.append("actor = ?")
            params.append(actor)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return self.db.query_all(sql, params)

    def count(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS c FROM audit_log")
        return int(row["c"]) if row else 0