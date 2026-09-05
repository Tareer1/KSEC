"""User-defined workflow storage (spec: AUTOMATION).

Users create reusable workflows from capability steps. They are validated
against the known capability set and RBAC permission mapping, then executed
by the same policy-gated engine as built-in workflows.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from ksec.adapters.registry import AdapterRegistry
from ksec.capabilities.registry import CapabilityRegistry
from ksec.core.errors import KSECError
from ksec.db.connection import Database
from ksec.identity.users import now_utc
from ksec.workflows.definitions import WorkflowDefinition, WorkflowStep

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,63}$")

# Built-in workflow names may not be shadowed by custom workflows.
RESERVED_NAMES = ("recon", "assess")

_ALLOWED_VALUE_TYPES = (str, int, float, bool)


@dataclass(frozen=True)
class CustomWorkflow:
    id: int
    name: str
    description: str
    steps: list[dict]
    enabled: bool
    created_by: str
    created_at: str
    updated_at: str
    version: int = 1

    def to_definition(self) -> WorkflowDefinition:
        return WorkflowDefinition(
            name=self.name,
            description=self.description,
            version=self.version,
            steps=tuple(
                WorkflowStep(
                    capability=step["capability"],
                    options=step.get("options", {}),
                    name=step.get("name"),
                    depends_on=tuple(step.get("depends_on", []) or []),
                    retry=int(step.get("retry", 0) or 0),
                    retry_delay=float(step.get("retry_delay", 1.0) or 1.0),
                )
                for step in self.steps
            ),
        )


class WorkflowStore:
    def __init__(
        self,
        db: Database,
        capabilities: CapabilityRegistry | None = None,
        adapters: AdapterRegistry | None = None,
    ):
        self.db = db
        self.capabilities = capabilities
        self.adapters = adapters

    # -- validation -------------------------------------------------------

    def known_capabilities(self) -> set[str]:
        known = set()
        if self.capabilities is not None:
            known.update(t.capability for t in self.capabilities.definitions())
        if self.adapters is not None:
            known.update(self.adapters.capabilities())
        return known

    def validate_name(self, name: str) -> list[str]:
        errors: list[str] = []
        if not NAME_RE.fullmatch(name):
            errors.append(
                f"invalid workflow name {name!r}: use 2-64 chars of [a-z0-9_.-], starting with [a-z0-9]"
            )
        if name in RESERVED_NAMES:
            errors.append(f"{name!r} is a built-in workflow name")
        return errors

    def validate_steps(self, steps: list[dict]) -> list[str]:
        errors: list[str] = []
        if not steps:
            return ["workflow must contain at least one step"]
        known = self.known_capabilities()
        adapters = self.adapters.capabilities() if self.adapters else set()
        names: set[str] = set()
        for index, step in enumerate(steps):
            capability = step.get("capability")
            if not isinstance(capability, str) or not capability:
                errors.append(f"step {index + 1}: missing 'capability'")
                continue
            if capability not in known:
                errors.append(f"step {index + 1}: unknown capability {capability!r}")
            elif self.adapters is not None and capability not in adapters:
                errors.append(
                    f"step {index + 1}: capability {capability!r} has no adapter installed — "
                    "it will fail at runtime"
                )
            name = step.get("name")
            if name is not None:
                if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_]+", name):
                    errors.append(
                        f"step {index + 1}: invalid 'name' {name!r} (use [a-z0-9_])"
                    )
                elif name in names:
                    errors.append(f"step {index + 1}: duplicate step name {name!r}")
                else:
                    names.add(name)
            depends_on = step.get("depends_on", []) or []
            if not isinstance(depends_on, list) or not all(
                isinstance(d, str) for d in depends_on
            ):
                errors.append(f"step {index + 1}: 'depends_on' must be a list of step names")
            retry = step.get("retry", 0) or 0
            if not isinstance(retry, int) or retry < 0 or retry > 10:
                errors.append(f"step {index + 1}: 'retry' must be an int in 0..10")
            retry_delay = step.get("retry_delay", 1.0) or 1.0
            if not isinstance(retry_delay, (int, float)) or retry_delay < 0:
                errors.append(f"step {index + 1}: 'retry_delay' must be a non-negative number")
            options = step.get("options", {})
            if not isinstance(options, dict):
                errors.append(f"step {index + 1}: 'options' must be a JSON object")
                continue
            for key, value in options.items():
                if not re.fullmatch(r"[a-z0-9_]+", str(key)):
                    errors.append(f"step {index + 1}: invalid option key {key!r}")
                if not self._valid_value(value):
                    errors.append(
                        f"step {index + 1}: option {key!r} has unsupported value type"
                    )
        # Resolve explicit names for dependency checks (positional ids are implicit).
        resolved = {}
        for index, step in enumerate(steps):
            resolved[step.get("name") or f"step{index + 1}"] = index
        for index, step in enumerate(steps):
            for dep in step.get("depends_on", []) or []:
                if dep not in resolved:
                    errors.append(f"step {index + 1}: depends_on unknown step {dep!r}")
        # Cycle detection over the dependency graph.
        if self._has_cycle(steps, resolved):
            errors.append("workflow contains a dependency cycle")
        return errors

    @staticmethod
    def _has_cycle(steps: list[dict], resolved: dict) -> bool:
        """Kahn-style cycle check on the step dependency graph."""
        indegree = {name: 0 for name in resolved}
        edges: dict[str, list[str]] = {name: [] for name in resolved}
        for index, step in enumerate(steps):
            name = step.get("name") or f"step{index + 1}"
            for dep in step.get("depends_on", []) or []:
                if dep in resolved:
                    edges[dep].append(name)
                    indegree[name] += 1
        queue = [n for n, d in indegree.items() if d == 0]
        visited = 0
        while queue:
            node = queue.pop()
            visited += 1
            for nxt in edges[node]:
                indegree[nxt] -= 1
                if indegree[nxt] == 0:
                    queue.append(nxt)
        return visited != len(resolved)

    @staticmethod
    def _valid_value(value: Any) -> bool:
        if isinstance(value, _ALLOWED_VALUE_TYPES):
            return True
        if isinstance(value, list) and all(isinstance(v, _ALLOWED_VALUE_TYPES) for v in value):
            return True
        return False

    def validate_workflow(self, name: str, steps: list[dict]) -> list[str]:
        return self.validate_name(name) + self.validate_steps(steps)

    # -- CRUD -------------------------------------------------------------

    def create(
        self,
        name: str,
        steps: list[dict],
        description: str = "",
        created_by: str = "",
    ) -> CustomWorkflow:
        errors = self.validate_workflow(name, steps)
        if errors:
            raise KSECError(f"invalid workflow: {'; '.join(errors)}")
        now = now_utc()
        try:
            with self.db.transaction() as conn:
                cursor = conn.execute(
                    "INSERT INTO custom_workflows (name, description, steps, enabled,"
                    " created_by, created_at, updated_at, version) VALUES (?, ?, ?, 1, ?, ?, ?, 1)",
                    (name, description, json.dumps(steps), created_by, now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise KSECError(f"workflow {name!r} already exists") from exc
        workflow = self.get(cursor.lastrowid)
        assert workflow is not None
        return workflow

    def get(self, workflow_id: int | None = None, name: str | None = None) -> CustomWorkflow | None:
        if workflow_id is not None:
            row = self.db.query_one(
                "SELECT * FROM custom_workflows WHERE id = ?", (workflow_id,)
            )
        elif name is not None:
            row = self.db.query_one(
                "SELECT * FROM custom_workflows WHERE name = ?", (name,)
            )
        else:
            raise ValueError("get() requires workflow_id or name")
        return self._from_row(row) if row else None

    def get_by_name(self, name: str) -> CustomWorkflow | None:
        return self.get(name=name)

    def list(self) -> list[CustomWorkflow]:
        rows = self.db.query_all("SELECT * FROM custom_workflows ORDER BY id")
        return [self._from_row(row) for row in rows]

    def update(
        self,
        name: str,
        *,
        steps: list[dict] | None = None,
        description: str | None = None,
        enabled: bool | None = None,
    ) -> CustomWorkflow:
        workflow = self.get_by_name(name)
        if workflow is None:
            raise KSECError(f"unknown workflow: {name}")
        if steps is not None:
            errors = self.validate_steps(steps)
            if errors:
                raise KSECError(f"invalid workflow: {'; '.join(errors)}")
        assignments = ["updated_at = ?", "version = version + 1"]
        params: list = [now_utc()]
        if steps is not None:
            assignments.append("steps = ?")
            params.append(json.dumps(steps))
        if description is not None:
            assignments.append("description = ?")
            params.append(description)
        if enabled is not None:
            assignments.append("enabled = ?")
            params.append(1 if enabled else 0)
        params.append(name)
        self.db.execute(
            f"UPDATE custom_workflows SET {', '.join(assignments)} WHERE name = ?", params
        )
        updated = self.get_by_name(name)
        assert updated is not None
        return updated

    def delete(self, name: str) -> None:
        self.db.execute("DELETE FROM custom_workflows WHERE name = ?", (name,))

    def resolve(self, name: str) -> WorkflowDefinition | None:
        """Resolve a workflow name: built-ins, then custom workflows, then
        capability-as-workflow (any registered adapter — including plugin
        capabilities — runs as a single-step workflow)."""
        from ksec.workflows.definitions import WorkflowDefinition, WorkflowStep, get_workflow

        builtin = get_workflow(name)
        if builtin is not None:
            return builtin
        custom = self.get_by_name(name)
        if custom is not None and custom.enabled:
            return custom.to_definition()
        if self.adapters is not None and self.adapters.get(name) is not None:
            return WorkflowDefinition(
                name=name,
                description=f"Single-step run of capability {name}",
                steps=(WorkflowStep(name),),
            )
        return None

    @staticmethod
    def _from_row(row: sqlite3.Row) -> CustomWorkflow:
        return CustomWorkflow(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            steps=json.loads(row["steps"] or "[]"),
            enabled=bool(row["enabled"]),
            created_by=row["created_by"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            version=int(row["version"] or 1),
        )