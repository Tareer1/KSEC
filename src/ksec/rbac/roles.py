"""Role-based access control: workspaces, roles, permissions.

Roles describe operator permissions. Threat-actor profiles (Adversary
Simulation) are data objects and remain a separate concept (spec: RBAC).
"""
from __future__ import annotations

import sqlite3

from ksec.core.errors import AuthorizationError
from ksec.db.connection import Database

WORKSPACES: list[tuple[str, str]] = [
    ("RED_TEAM", "Authorized attack simulation and security testing."),
    ("BLUE_TEAM", "Defense, monitoring, detection, investigation and remediation."),
    ("RESEARCH_OSINT", "Security detective and intelligence workspace."),
    ("ADVERSARY_SIMULATION", "Controlled adversary behavior simulation."),
    ("LEARN_WORK", "Learning combined with practical authorized work."),
]

PERMISSIONS: dict[str, str] = {
    "assess.run": "Run authorized assessments",
    "recon.run": "Run reconnaissance workflows",
    "tools.list": "List discovered tools",
    "tools.install": "Install missing tools with approval",
    "findings.manage": "Create and update findings",
    "evidence.manage": "Manage evidence",
    "cases.manage": "Manage cases",
    "report.generate": "Generate reports",
    "intel.use": "Use research/OSINT intelligence data",
    "adversary.use": "Use adversary simulation",
    "learning.use": "Use the learning curriculum",
    "sessions.manage": "Manage sessions",
    "users.manage": "Manage users",
    "roles.manage": "Manage roles and permissions",
    "audit.read": "Read audit logs",
    "config.manage": "Manage configuration",
    "plugin.manage": "Install, enable and remove plugins",
}

ROLE_DEFINITIONS: dict[str, dict[str, object]] = {
    "admin": {
        "description": "Full platform administration.",
        "permissions": list(PERMISSIONS),
    },
    "operator": {
        "description": "Run authorized security workflows.",
        "permissions": [
            "assess.run",
            "recon.run",
            "tools.list",
            "findings.manage",
            "evidence.manage",
            "cases.manage",
            "report.generate",
            "intel.use",
        ],
    },
    "auditor": {
        "description": "Read-only audit and review.",
        "permissions": ["audit.read", "report.generate", "tools.list"],
    },
    "learner": {
        "description": "Learning curriculum access.",
        "permissions": ["learning.use", "tools.list"],
    },
}


class RbacService:
    def __init__(self, db: Database):
        self.db = db

    def seed(self) -> None:
        """Insert standard workspaces, permissions and roles (idempotent)."""
        self.db.executemany(
            "INSERT OR IGNORE INTO workspaces (name, description) VALUES (?, ?)", WORKSPACES
        )
        self.db.executemany(
            "INSERT OR IGNORE INTO permissions (name, description) VALUES (?, ?)",
            list(PERMISSIONS.items()),
        )
        self.db.executemany(
            "INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)",
            [(name, d["description"]) for name, d in ROLE_DEFINITIONS.items()],
        )
        rows: list[tuple[int, int]] = []
        for role_name, definition in ROLE_DEFINITIONS.items():
            role = self.db.query_one("SELECT id FROM roles WHERE name = ?", (role_name,))
            if role is None:
                continue
            for perm in definition["permissions"]:
                perm_row = self.db.query_one(
                    "SELECT id FROM permissions WHERE name = ?", (perm,)
                )
                if perm_row is not None:
                    rows.append((role["id"], perm_row["id"]))
        self.db.executemany(
            "INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
            rows,
        )

    def workspace_id(self, name: str) -> int | None:
        row = self.db.query_one("SELECT id FROM workspaces WHERE name = ?", (name,))
        return row["id"] if row else None

    def role_id(self, name: str) -> int | None:
        row = self.db.query_one("SELECT id FROM roles WHERE name = ?", (name,))
        return row["id"] if row else None

    def list_workspaces(self) -> list[sqlite3.Row]:
        return self.db.query_all("SELECT id, name, description FROM workspaces ORDER BY id")

    def list_roles(self) -> list[sqlite3.Row]:
        return self.db.query_all("SELECT id, name, description FROM roles ORDER BY id")

    def assign_role(self, user_id: int, role_name: str) -> None:
        role = self.db.query_one("SELECT id FROM roles WHERE name = ?", (role_name,))
        if role is None:
            raise AuthorizationError(f"Unknown role: {role_name}")
        self.db.execute(
            "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
            (user_id, role["id"]),
        )

    def remove_role(self, user_id: int, role_name: str) -> bool:
        """Revoke one role from a user. Returns False when the user does not
        have that role (the last role is never removed)."""
        roles = self.user_roles(user_id)
        if role_name not in {r["name"] for r in roles}:
            return False
        if len(roles) <= 1:
            raise AuthorizationError(
                f"User {user_id} has only role {role_name}; a user needs at least one role"
            )
        role = self.db.query_one("SELECT id FROM roles WHERE name = ?", (role_name,))
        if role is None:
            raise AuthorizationError(f"Unknown role: {role_name}")
        self.db.execute(
            "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
            (user_id, role["id"]),
        )
        return True

    def user_roles(self, user_id: int) -> list[sqlite3.Row]:
        return self.db.query_all(
            "SELECT r.id, r.name, r.description FROM roles r "
            "JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ? ORDER BY r.id",
            (user_id,),
        )

    def role_has_permission(self, role_id: int, permission: str) -> bool:
        row = self.db.query_one(
            "SELECT 1 FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id "
            "WHERE rp.role_id = ? AND p.name = ?",
            (role_id, permission),
        )
        return row is not None

    def user_has_permission(self, user_id: int, permission: str) -> bool:
        row = self.db.query_one(
            "SELECT 1 FROM user_roles ur "
            "JOIN role_permissions rp ON rp.role_id = ur.role_id "
            "JOIN permissions p ON p.id = rp.permission_id "
            "WHERE ur.user_id = ? AND p.name = ?",
            (user_id, permission),
        )
        return row is not None