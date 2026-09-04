"""Policy Engine.

The Policy Engine evaluates whether an action is permitted and returns one of:
ALLOW, DENY, REQUIRE_CONFIRMATION, REQUIRE_PRIVILEGE or
REQUIRE_AUTHORIZATION. No security-sensitive execution may bypass this engine
(spec: Policy Engine). Every decision carries a deterministic reason.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ksec.authorization.service import AuthorizationService
from ksec.config.loader import KsecConfig
from ksec.db.connection import Database
from ksec.identity.users import User
from ksec.rbac.roles import RbacService
from ksec.sessions.manager import Session


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"
    REQUIRE_PRIVILEGE = "REQUIRE_PRIVILEGE"
    REQUIRE_AUTHORIZATION = "REQUIRE_AUTHORIZATION"


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str


# Actions that mutate state; blocked when the platform is read-only.
MUTATING_ACTIONS = {
    "tools.install",
    "findings.manage",
    "evidence.manage",
    "cases.manage",
    "users.manage",
    "roles.manage",
    "config.manage",
}


class PolicyEngine:
    def __init__(
        self,
        db: Database,
        rbac: RbacService,
        authz: AuthorizationService,
        config: KsecConfig,
    ):
        self.db = db
        self.rbac = rbac
        self.authz = authz
        self.config = config

    def evaluate(
        self,
        *,
        user: User,
        action: str,
        session: Session | None = None,
        target: str | None = None,
        engagement_id: int | None = None,
    ) -> PolicyResult:
        # 1. Account status
        if user.status != "active":
            return PolicyResult(Decision.DENY, f"User account is {user.status}")

        # 2. Session validity and ownership
        if session is not None:
            if session.state != "ACTIVE":
                return PolicyResult(
                    Decision.DENY, f"Session is {session.state}, expected ACTIVE"
                )
            if session.user_id != user.id:
                return PolicyResult(Decision.DENY, "Session belongs to a different user")

        # 3. Role permission
        if not self.rbac.user_has_permission(user.id, action):
            return PolicyResult(
                Decision.DENY, f"User {user.username} lacks permission {action}"
            )

        # 4. Authorization / scope
        if self.config.require_authorization and target is not None:
            if engagement_id is None:
                return PolicyResult(
                    Decision.REQUIRE_AUTHORIZATION,
                    "Action on a target requires an engagement authorization",
                )
            authorized, reason = self.authz.is_target_authorized(
                engagement_id, target, action
            )
            if not authorized:
                return PolicyResult(
                    Decision.REQUIRE_AUTHORIZATION,
                    f"Target {target} not authorized for {action}: {reason}",
                )

        # 5. Safety settings
        if self.config.read_only and action in MUTATING_ACTIONS:
            return PolicyResult(Decision.DENY, "Platform is in read-only mode")
        if self.config.safe_mode and action == "tools.install":
            return PolicyResult(
                Decision.REQUIRE_CONFIRMATION,
                "Safe mode requires confirmation for tool installation",
            )

        return PolicyResult(Decision.ALLOW, "Permitted by policy")