"""Policy-gated vulnerability check service.

Runs the deterministic checks in :mod:`ksec.vuln.checks` against a target
that must be authorized by the engagement scope, then creates findings
(one per distinct outcome) with deterministic risk scores.
"""
from __future__ import annotations

from dataclasses import dataclass

from ksec.audit.service import AuditService
from ksec.core.errors import KSECError
from ksec.db.connection import Database
from ksec.findings.service import FindingService
from ksec.identity.users import User
from ksec.policies.engine import PolicyEngine
from ksec.risk.engine import calculate_risk
from ksec.vuln import checks as checklib


@dataclass
class VulnReport:
    target: str
    url: str
    checks_run: int
    findings_created: list[int]
    findings_existing: int
    outcomes: list[dict]


def _is_private(host: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host in ("localhost",) or host.endswith(".local")
    return ip.is_private or ip.is_loopback or ip.is_link_local


class VulnService:
    def __init__(
        self,
        db: Database,
        policy: PolicyEngine,
        findings: FindingService,
        audit: AuditService,
    ):
        self.db = db
        self.policy = policy
        self.findings = findings
        self.audit = audit

    def run(
        self,
        *,
        target: str,
        user: User,
        engagement_id: int | None = None,
        port: int | None = None,
    ) -> VulnReport:
        decision = self.policy.evaluate(
            user=user, action="assess.run", target=target, engagement_id=engagement_id
        )
        if decision.decision.value != "ALLOW":
            raise KSECError(f"authorization denied: {decision.reason}")

        ref = checklib.normalize_target(target, port=port)
        outcomes = checklib.run_checks(ref)

        exposure = "internal" if _is_private(ref.host) else "internet"
        created: list[int] = []
        existing = 0
        for outcome in outcomes:
            dup = self.db.query_one(
                "SELECT id FROM findings WHERE engagement_id = ? AND title = ?"
                " AND source LIKE 'vuln:%' LIMIT 1",
                (engagement_id, outcome.title),
            )
            if dup is not None:
                existing += 1
                continue
            risk = calculate_risk(
                severity=outcome.severity,
                asset_criticality="low",
                exploitability="low" if outcome.severity in ("high", "critical") else "none",
                exposure=exposure,
                business_impact="medium" if outcome.severity in ("high", "critical") else "low",
                confidence=outcome.confidence,
                evidence_quality="reproducible",
            )
            finding = self.findings.create(
                title=outcome.title,
                description=(
                    f"{outcome.description}\n\nEvidence:\n{outcome.evidence.strip()[:2000]}"
                ),
                severity=outcome.severity,
                confidence=outcome.confidence,
                recommendation=outcome.recommendation,
                engagement_id=engagement_id,
                source=f"vuln:{outcome.check_id}",
                risk=risk,
            )
            created.append(finding.id)

        self.audit.record(
            event_type="vuln.check",
            actor=user.username,
            action="vuln.check",
            target=target,
            outcome="success",
            payload={
                "url": ref.base_url,
                "checks": len(outcomes),
                "findings": created,
            },
        )
        return VulnReport(
            target=target,
            url=ref.base_url,
            checks_run=len(outcomes),
            findings_created=created,
            findings_existing=existing,
            outcomes=[_outcome_dict(o) for o in outcomes],
        )


def _outcome_dict(o: checklib.CheckOutcome) -> dict:
    return {
        "check": o.check_id,
        "title": o.title,
        "severity": o.severity,
        "confidence": o.confidence,
        "description": o.description,
    }
