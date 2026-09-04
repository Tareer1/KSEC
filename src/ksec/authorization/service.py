"""Engagement authorization and scope enforcement.

Authorization is represented independently from user identity: an engagement
carries its own scope allow/deny rules, and out-of-scope targets must be
blocked (spec: Authorization and Scope).
"""
from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass
from urllib.parse import urlsplit

from ksec.core.errors import AuthorizationError
from ksec.db.connection import Database
from ksec.identity.users import now_utc

VALID_EFFECTS = ("allow", "deny")


def _normalize_target(target: str) -> str:
    """Reduce a target to its host for scope matching.

    ``https://example.com/path`` -> ``example.com``, ``example.com:8080`` ->
    ``example.com``, ``1.2.3.4:80`` -> ``1.2.3.4``. IPv6 literals are left
    untouched (multiple colons).
    """
    t = target.strip().lower()
    try:
        parts = urlsplit(t)
        if parts.scheme and parts.netloc and parts.hostname:
            return parts.hostname
    except ValueError:
        pass
    if t.count(":") == 1:
        host, _, port = t.rpartition(":")
        if host and port.isdigit():
            return host
    return t


def target_matches(target: str, pattern: str) -> bool:
    """Match a target against an authorization pattern.

    Supports ``*`` (everything), exact IP/domain match, CIDR ranges, domain
    suffix matching (``example.com`` or ``.example.com`` also matches
    ``sub.example.com``), and URL/port forms (``https://example.com`` or
    ``example.com:443`` match a scope rule for ``example.com``).
    """
    target = _normalize_target(target)
    pattern = pattern.strip().lower()
    if not target or not pattern:
        return False
    if pattern == "*":
        return True
    if target == pattern:
        return True
    if pattern.startswith("*."):
        # "*.example.com" behaves like ".example.com" (suffix match)
        pattern = pattern[1:]
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        address = ipaddress.ip_address(target)
        return address in network
    except ValueError:
        pass
    if pattern.startswith("."):
        return target.endswith(pattern) and target != pattern[1:]
    return target.endswith("." + pattern)


@dataclass(frozen=True)
class Engagement:
    id: int
    name: str
    description: str
    status: str
    created_at: str


class AuthorizationService:
    def __init__(self, db: Database):
        self.db = db

    def create_engagement(
        self, name: str, description: str = "", created_by: int | None = None
    ) -> Engagement:
        if not name or not name.strip():
            raise AuthorizationError("Engagement name must not be empty")
        created = now_utc()
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO engagements (name, description, status, created_at, created_by)"
                " VALUES (?, ?, 'open', ?, ?)",
                (name.strip(), description, created, created_by),
            )
        return self.get_engagement(cursor.lastrowid)

    def get_engagement(self, engagement_id: int) -> Engagement | None:
        row = self.db.query_one(
            "SELECT id, name, description, status, created_at FROM engagements WHERE id = ?",
            (engagement_id,),
        )
        if row is None:
            return None
        return Engagement(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            status=row["status"],
            created_at=row["created_at"],
        )

    def list_engagements(self) -> list[Engagement]:
        rows = self.db.query_all(
            "SELECT id, name, description, status, created_at FROM engagements ORDER BY id"
        )
        return [
            Engagement(
                id=row["id"],
                name=row["name"],
                description=row["description"],
                status=row["status"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

    def add_authorization(
        self,
        engagement_id: int,
        target: str,
        action: str = "*",
        effect: str = "allow",
        created_by: int | None = None,
    ) -> int:
        if effect not in VALID_EFFECTS:
            raise AuthorizationError(f"Invalid effect: {effect}")
        if self.get_engagement(engagement_id) is None:
            raise AuthorizationError(f"Unknown engagement: {engagement_id}")
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO authorizations (engagement_id, target, action, effect, created_at,"
                " created_by) VALUES (?, ?, ?, ?, ?, ?)",
                (engagement_id, target.strip(), action, effect, now_utc(), created_by),
            )
        return cursor.lastrowid

    def list_authorizations(self, engagement_id: int) -> list[sqlite3.Row]:
        return self.db.query_all(
            "SELECT id, target, action, effect, created_at FROM authorizations"
            " WHERE engagement_id = ? ORDER BY id",
            (engagement_id,),
        )

    def is_target_authorized(
        self, engagement_id: int, target: str, action: str = "*"
    ) -> tuple[bool, str]:
        """Check whether ``target`` is in scope for an engagement.

        Deny rules win over allow rules. Returns ``(authorized, reason)``.
        """
        rules = self.db.query_all(
            "SELECT target, action, effect FROM authorizations WHERE engagement_id = ?",
            (engagement_id,),
        )
        for rule in rules:
            if (
                rule["effect"] == "deny"
                and (rule["action"] == "*" or rule["action"] == action)
                and target_matches(target, rule["target"])
            ):
                return False, f"denied by rule {rule['target']}"
        for rule in rules:
            if (
                rule["effect"] == "allow"
                and (rule["action"] == "*" or rule["action"] == action)
                and target_matches(target, rule["target"])
            ):
                return True, "authorized"
        return False, "no matching authorization record"