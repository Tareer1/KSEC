"""Atomic red test definitions + policy-gated runner.

Each atomic emulates ONE ATT&CK technique using a regular KSEC
capability. Intended use: run it against an authorized target, then check
whether your SOC/analytics stack noticed (see ``detection`` on every
atomic). All side effects are limited to what the underlying read-only
tools do — no payloads, no persistence, nothing destructive.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ksec.audit.service import AuditService
from ksec.core.errors import KSECError
from ksec.db.connection import Database
from ksec.identity.users import User
from ksec.policies.engine import PolicyEngine
from ksec.workflows.definitions import WorkflowDefinition, WorkflowStep
from ksec.workflows.engine import WorkflowEngine


@dataclass(frozen=True)
class Atomic:
    id: str
    name: str
    technique: str
    tactic: str
    capability: str
    description: str
    detection: str
    options: dict = None  # type: ignore[assignment]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "technique": self.technique,
            "tactic": self.tactic,
            "capability": self.capability,
            "description": self.description,
            "detection": self.detection,
        }


ATOMICS: list[Atomic] = [
    Atomic(
        id="net-dns-lookup",
        name="DNS lookup (recon)",
        technique="T1590",
        tactic="reconnaissance",
        capability="dns_lookup",
        description="Resolve the target name (equivalent to `dig`).",
        detection="Watch for unusual or bulk DNS queries from the scanning host.",
    ),
    Atomic(
        id="net-port-scan",
        name="Port scan (discovery)",
        technique="T1046",
        tactic="discovery",
        capability="port_scan",
        description="TCP connect scan of the target's top 100 ports (nmap).",
        detection="Watch for port-scan alerts / connection bursts from one source.",
    ),
    Atomic(
        id="web-http-probe",
        name="HTTP request (C2 channel)",
        technique="T1071.001",
        tactic="command-and-control",
        capability="http_probe",
        description="Single HTTP(S) request to the target (curl) — emulates an",
        detection="Watch for repeated connections to a suspicious domain.",
    ),
    Atomic(
        id="web-header-fetch",
        name="HTTP header fetch (initial access recon)",
        technique="T1190",
        tactic="initial-access",
        capability="http_probe",
        description="Fetch response headers of the target web service.",
        detection="Watch for web-scan signatures (HEAD/OPTIONS bursts).",
    ),
    Atomic(
        id="service-banner",
        name="Service banner grab",
        technique="T1082",
        tactic="discovery",
        capability="http_probe",
        description="Collect service/version banner exposed by the target.",
        detection="Watch for versioned banner disclosure in proxy logs.",
    ),
]

_ATOMIC_MAP: dict[str, Atomic] = {a.id: a for a in ATOMICS}


def atomics() -> list[Atomic]:
    return list(ATOMICS)


def get_atomic(atomic_id: str) -> Atomic | None:
    return _ATOMIC_MAP.get(atomic_id)


class AtomicService:
    def __init__(
        self,
        db: Database,
        policy: PolicyEngine,
        workflows: WorkflowEngine,
        audit: AuditService,
    ):
        self.db = db
        self.policy = policy
        self.workflows = workflows
        self.audit = audit

    def run(
        self,
        *,
        atomic_id: str,
        target: str,
        user: User,
        session: Any,
        engagement_id: int | None = None,
    ) -> dict:
        atomic = get_atomic(atomic_id)
        if atomic is None:
            raise KSECError(f"unknown atomic test: {atomic_id}")

        from ksec.capabilities.catalog import capability_permission

        action = capability_permission(atomic.capability)
        decision = self.policy.evaluate(
            user=user,
            action=action,
            session=session,
            target=target,
            engagement_id=engagement_id,
        )
        if decision.decision.value != "ALLOW":
            raise KSECError(f"authorization denied: {decision.reason}")

        definition = WorkflowDefinition(
            name=f"atomic:{atomic.id}",
            description=atomic.description,
            steps=(WorkflowStep(atomic.capability, atomic.options or {}),),
        )
        run = self.workflows.run(
            definition,
            user=user,
            session=session,
            target=target,
            engagement_id=engagement_id,
        )
        step = run.steps[0] if run.steps else None
        self.audit.record(
            event_type="atomic.run",
            actor=user.username,
            action="atomic.run",
            target=target,
            outcome="success" if run.status == "completed" else "failed",
            payload={
                "atomic": atomic.id,
                "technique": atomic.technique,
                "tactic": atomic.tactic,
                "job_id": step.job_id if step else None,
            },
        )
        return {
            "atomic": atomic.id,
            "name": atomic.name,
            "technique": atomic.technique,
            "tactic": atomic.tactic,
            "target": target,
            "status": run.status,
            "job_id": step.job_id if step else None,
            "entities": step.entities if step else 0,
            "detection": atomic.detection,
        }
