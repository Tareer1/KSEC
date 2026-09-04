"""Update readiness checks (spec 01#36 UPDATE SYSTEM, 01#37 OFFLINE).

An update touches the KSEC codebase (version), the schema (migrations), the
tool registry, installed plugins and adapters. This service verifies each
area is consistent and that a rollback path (verified backup) exists before
recommending an update. Everything runs offline.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from ksec import __version__
from ksec.db.connection import Database
from ksec.db.migrations import MigrationRunner


class UpdateService:
    def __init__(self, db: Database, migrations_dir: Path, backups=None, plugins=None):
        self.db = db
        self.migrations_dir = Path(migrations_dir)
        self.backups = backups
        self.plugins = plugins

    def check(self) -> dict:
        """Full offline update-readiness report."""
        runner = MigrationRunner(self.db, self.migrations_dir)
        current = runner.current_version()
        pending = runner.pending()

        checks = [
            self._schema_check(current, pending),
            self._rollback_check(),
            self._plugin_check(),
            self._registry_check(),
        ]
        ok = all(check["ok"] for check in checks)
        return {
            "ksec_version": __version__,
            "ok": ok,
            "offline": True,
            "checks": checks,
            "summary": "update-ready" if ok else "resolve failures before updating",
        }

    def _schema_check(self, current: int, pending: list) -> dict:
        return {
            "name": "schema",
            "ok": not pending,
            "detail": (
                f"current schema v{current}, pending migrations: {len(pending)}"
                if pending
                else f"schema v{current} is current"
            ),
            "pending_migrations": [Path(m).name for m in pending],
        }

    def _rollback_check(self) -> dict:
        if self.backups is None:
            return {"name": "rollback", "ok": True, "detail": "backup service not wired"}
        backups = self.backups.list()
        verified = [b for b in backups if self.backups.verify(b.id)[0]]
        return {
            "name": "rollback",
            "ok": len(verified) > 0,
            "detail": (
                f"{len(verified)} verified backup(s) available for rollback"
                if verified
                else "no verified backup — create one with `ksec backup create` before updating"
            ),
        }

    def _plugin_check(self) -> dict:
        if self.plugins is None:
            return {"name": "plugins", "ok": True, "detail": "plugin manager not wired"}
        results = self.plugins.check()
        bad = [r for r in results if not r["ok"]]
        return {
            "name": "plugins",
            "ok": not bad,
            "detail": (
                f"{len(bad)} unhealthy plugin(s): {', '.join(r['plugin_id'] for r in bad)}"
                if bad
                else f"{len(results)} plugin(s) healthy"
            ),
        }

    def _registry_check(self) -> dict:
        """Every step of the built-in workflows has a runnable adapter."""
        from ksec.workflows.definitions import get_workflow

        if self.plugins is None:
            return {"name": "registry", "ok": True, "detail": "adapter registry not wired"}
        adapters = set(self.plugins.adapters.capabilities())
        needed: set[str] = set()
        for name in ("recon", "assess"):
            workflow = get_workflow(name)
            if workflow:
                needed.update(step.capability for step in workflow.steps)
        missing = sorted(needed - adapters)
        if not missing:
            return {
                "name": "registry",
                "ok": True,
                "detail": "built-in workflows resolvable (adapters present)",
            }
        return {
            "name": "registry",
            "ok": False,
            "detail": f"built-in workflow step(s) lack adapters: {', '.join(missing)}",
        }