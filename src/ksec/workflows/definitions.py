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


@dataclass(frozen=True)
class WorkflowDefinition:
    name: str
    description: str
    steps: tuple[WorkflowStep, ...]


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
}


def get_workflow(name: str) -> WorkflowDefinition | None:
    return WORKFLOWS.get(name)


def list_workflows() -> list[WorkflowDefinition]:
    return list(WORKFLOWS.values())