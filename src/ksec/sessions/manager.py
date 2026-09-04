"""Session lifecycle management.

Sessions bind a user, a workspace and a role together. One user may operate
five sessions (one per workspace); five users may each hold one. Every session
maintains independent state (spec: Session Manager / Multi-Terminal Model).
"""
from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass

from ksec.audit.service import AuditService
from ksec.core.errors import SessionError
from ksec.db.connection import Database
from ksec.identity.users import User, now_utc
from ksec.rbac.roles import RbacService

SESSION_STATES = ("CREATED", "ACTIVE", "PAUSED", "CLOSED", "FAILED")

_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "CREATED": {"ACTIVE", "FAILED", "CLOSED"},
    "ACTIVE": {"PAUSED", "CLOSED", "FAILED"},
    "PAUSED": {"ACTIVE", "CLOSED"},
}


@dataclass(frozen=True)
class Session:
    id: str
    user_id: int
    username: str
    workspace_id: int
    workspace: str
    role_id: int
    role: str
    state: str
    created_at: str
    closed_at: str | None


class SessionManager:
    def __init__(self, db: Database, rbac: RbacService, audit: AuditService):
        self.db = db
        self.rbac = rbac
        self.audit = audit

    def open(
        self, user: User, workspace_name: str, role_name: str | None = None
    ) -> Session:
        workspace_id = self.rbac.workspace_id(workspace_name)
        if workspace_id is None:
            raise SessionError(f"Unknown workspace: {workspace_name}")
        roles = self.rbac.user_roles(user.id)
        if not roles:
            raise SessionError(f"User {user.username} has no roles assigned")
        if role_name:
            role = next((r for r in roles if r["name"] == role_name), None)
            if role is None:
                raise SessionError(
                    f"User {user.username} does not have role {role_name}"
                )
        else:
            role = roles[0]
        session_id = uuid.uuid4().hex
        created = now_utc()
        self.db.execute(
            "INSERT INTO sessions (id, user_id, workspace_id, role_id, state, created_at,"
            " metadata) VALUES (?, ?, ?, ?, 'ACTIVE', ?, '{}')",
            (session_id, user.id, workspace_id, role["id"], created),
        )
        self.audit.record(
            event_type="session.open",
            actor=user.username,
            session_id=session_id,
            workspace=workspace_name,
            action="session.open",
            outcome="success",
        )
        session = self.get(session_id)
        assert session is not None
        return session

    def get(self, session_id: str) -> Session | None:
        row = self.db.query_one(
            "SELECT s.id, s.user_id, s.workspace_id, s.role_id, s.state, s.created_at,"
            " s.closed_at, u.username AS username, w.name AS workspace, r.name AS role"
            " FROM sessions s"
            " JOIN users u ON u.id = s.user_id"
            " JOIN workspaces w ON w.id = s.workspace_id"
            " JOIN roles r ON r.id = s.role_id"
            " WHERE s.id = ?",
            (session_id,),
        )
        return self._from_row(row) if row else None

    def list(self, user_id: int | None = None) -> list[Session]:
        sql = (
            "SELECT s.id, s.user_id, s.workspace_id, s.role_id, s.state, s.created_at,"
            " s.closed_at, u.username AS username, w.name AS workspace, r.name AS role"
            " FROM sessions s"
            " JOIN users u ON u.id = s.user_id"
            " JOIN workspaces w ON w.id = s.workspace_id"
            " JOIN roles r ON r.id = s.role_id"
        )
        params: tuple = ()
        if user_id is not None:
            sql += " WHERE s.user_id = ?"
            params = (user_id,)
        sql += " ORDER BY s.created_at DESC"
        return [self._from_row(row) for row in self.db.query_all(sql, params)]

    def transition(self, session_id: str, new_state: str) -> Session:
        if new_state not in SESSION_STATES:
            raise SessionError(f"Unknown session state: {new_state}")
        session = self.get(session_id)
        if session is None:
            raise SessionError(f"Unknown session: {session_id}")
        allowed = _ALLOWED_TRANSITIONS.get(session.state, set())
        if new_state not in allowed:
            raise SessionError(
                f"Cannot move session from {session.state} to {new_state}"
            )
        closed_at = now_utc() if new_state == "CLOSED" else None
        self.db.execute(
            "UPDATE sessions SET state = ?, closed_at = ? WHERE id = ?",
            (new_state, closed_at, session_id),
        )
        event = f"session.{new_state.lower()}"
        self.audit.record(
            event_type=event,
            actor=session.username,
            session_id=session_id,
            workspace=session.workspace,
            action=event,
            outcome="success",
        )
        updated = self.get(session_id)
        assert updated is not None
        return updated

    def close(self, session_id: str) -> Session:
        return self.transition(session_id, "CLOSED")

    def pause(self, session_id: str) -> Session:
        return self.transition(session_id, "PAUSED")

    def resume(self, session_id: str) -> Session:
        return self.transition(session_id, "ACTIVE")

    def require_active(self, session_id: str, user_id: int) -> Session:
        """Return the session if it is active and owned by ``user_id``."""
        session = self.get(session_id)
        if session is None:
            raise SessionError(f"Unknown session: {session_id}")
        if session.user_id != user_id:
            raise SessionError("Session belongs to a different user")
        if session.state != "ACTIVE":
            raise SessionError(f"Session is {session.state}, expected ACTIVE")
        return session

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Session:
        return Session(
            id=row["id"],
            user_id=row["user_id"],
            username=row["username"],
            workspace_id=row["workspace_id"],
            workspace=row["workspace"],
            role_id=row["role_id"],
            role=row["role"],
            state=row["state"],
            created_at=row["created_at"],
            closed_at=row["closed_at"],
        )