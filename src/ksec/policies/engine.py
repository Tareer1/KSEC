"""Policy Engine.

The Policy Engine evaluates whether an action is permitted and returns one of:
ALLOW, DENY, REQUIRE_CONFIRMATION, REQUIRE_PRIVILEGE or
REQUIRE_AUTHORIZATION. No security-sensitive execution may bypass this engine
(spec: Policy Engine). Every decision carries a deterministic reason.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit

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


# Lab/CTF mode (spec 06#56): only clearly-labelled targets may be touched.
# Private/loopback ranges plus common lab TLDs (.test .local .lab .ctf) and
# hostnames containing a lab marker are treated as lab-scope.
_LAB_NETWORKS = (
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
)
_LAB_TLDS = (".test", ".local", ".lab", ".ctf", ".lan", ".internal", ".example")
_LAB_MARKERS = ("lab", "ctf", "target", "sandbox", "training", "localhost")


def _is_lab_target(target: str) -> bool:
    """True when a target is a lab-range IP/CIDR or a lab-labelled hostname."""
    if not target:
        return False
    t = target.strip().lower()
    try:
        parts = urlsplit(t)
        if parts.scheme and parts.hostname:
            t = parts.hostname
    except ValueError:
        pass
    if t.count(":") == 1:
        host, _, port = t.rpartition(":")
        if host and port.isdigit():
            t = host
    try:
        addr = ipaddress.ip_address(t)
        return any(addr in ipaddress.ip_network(net) for net in _LAB_NETWORKS)
    except ValueError:
        pass
    if any(t.endswith(tld) for tld in _LAB_TLDS):
        return True
    if any(marker in t for marker in _LAB_MARKERS):
        return True
    return False


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

        # 5. Lab/CTF mode (spec 06#56): target actions restricted to lab scope
        if self.config.lab_mode and target is not None and not _is_lab_target(target):
            return PolicyResult(
                Decision.DENY,
                f"Lab/CTF mode active: target {target} is not a lab-range/lab-labelled host",
            )

        # 6. Safety settings
        if self.config.read_only and action in MUTATING_ACTIONS:
            return PolicyResult(Decision.DENY, "Platform is in read-only mode")
        if self.config.safe_mode and action == "tools.install":
            return PolicyResult(
                Decision.REQUIRE_CONFIRMATION,
                "Safe mode requires confirmation for tool installation",
            )

        return PolicyResult(Decision.ALLOW, "Permitted by policy")