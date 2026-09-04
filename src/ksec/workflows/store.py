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

    def to_definition(self) -> WorkflowDefinition:
        return WorkflowDefinition(
            name=self.name,
            description=self.description,
            steps=tuple(
                WorkflowStep(capability=step["capability"], options=step.get("options", {}))
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
        return errors

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
                    " created_by, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?, ?)",
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
        assignments = ["updated_at = ?"]
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
        """Resolve a workflow name: built-ins first, then custom workflows."""
        from ksec.workflows.definitions import get_workflow

        builtin = get_workflow(name)
        if builtin is not None:
            return builtin
        custom = self.get_by_name(name)
        if custom is not None and custom.enabled:
            return custom.to_definition()
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
        )