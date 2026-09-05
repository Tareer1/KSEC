"""Built-in workflow definitions (spec: AUTOMATION).

Workflows are reusable sequences of capability steps. Custom workflows can be
defined by users in a later stage; these are the built-in seeds.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class WorkflowStep:
    capability: str
    options: dict = field(default_factory=dict)
    name: str | None = None
    depends_on: tuple[str, ...] = ()
    retry: int = 0
    retry_delay: float = 1.0


@dataclass(frozen=True)
class WorkflowDefinition:
    name: str
    description: str
    steps: tuple[WorkflowStep, ...]
    version: int = 1

    def step_name(self, index: int, step: WorkflowStep) -> str:
        """Explicit step name, else a stable positional id (step1, step2, ...)."""
        return step.name or f"step{index + 1}"

    def as_snapshot(self) -> dict:
        """Immutable JSON-safe snapshot of the executed definition (spec 07)."""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "steps": [
                {
                    "capability": s.capability,
                    "options": s.options,
                    "name": s.name,
                    "depends_on": list(s.depends_on),
                    "retry": s.retry,
                    "retry_delay": s.retry_delay,
                }
                for s in self.steps
            ],
        }


WORKFLOWS: dict[str, WorkflowDefinition] = {
    "recon": WorkflowDefinition(
        name="recon",
        description="Passive + light-active reconnaissance of a target.",
        steps=(
            WorkflowStep("dns_lookup"),
            WorkflowStep("port_scan", {"top_ports": 100}),
        ),
    ),
    "assess": WorkflowDefinition(
        name="assess",
        description="Standard authorized assessment flow.",
        steps=(
            WorkflowStep("dns_lookup"),
            WorkflowStep("port_scan", {"service_version": True, "top_ports": 1000}),
            WorkflowStep("http_probe"),
        ),
    ),
    "network": WorkflowDefinition(
        name="network",
        description="Network-focused authorized scanning: ports, SMB enumeration.",
        steps=(
            WorkflowStep("port_scan", {"top_ports": 1000}),
            WorkflowStep("smb_enum"),
            WorkflowStep("smb_map"),
        ),
    ),
    "web": WorkflowDefinition(
        name="web",
        description="Web application authorized assessment: fingerprint, probe, TLS, vulns.",
        steps=(
            WorkflowStep("web_fingerprint"),
            WorkflowStep("http_probe"),
            WorkflowStep("tls_scan"),
            WorkflowStep("web_vuln_scan"),
            WorkflowStep("directory_brute"),
        ),
    ),
    "research": WorkflowDefinition(
        name="research",
        description="Research/OSINT authorized workflow: DNS + passive harvest.",
        steps=(
            WorkflowStep("dns_lookup"),
            WorkflowStep("dns_enum"),
            WorkflowStep("osint_harvest"),
        ),
    ),
    "osint": WorkflowDefinition(
        name="osint",
        description="Passive open-source intelligence on an authorized target.",
        steps=(
            WorkflowStep("osint_harvest"),
            WorkflowStep("dns_lookup"),
        ),
    ),
    "exploit_lookup": WorkflowDefinition(
        name="exploit_lookup",
        description="Real-world red team: map discovered software to known public exploits.",
        steps=(
            WorkflowStep("web_fingerprint"),
            WorkflowStep("exploit_search", {"retry": 1, "retry_delay": 0.5}),
        ),
    ),
}


def get_workflow(name: str) -> WorkflowDefinition | None:
    return WORKFLOWS.get(name)


def list_workflows() -> list[WorkflowDefinition]:
    return list(WORKFLOWS.values())