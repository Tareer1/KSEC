"""Change detection subsystem (spec 08 #59).

Baselines snapshot the state of the platform (assets, open findings, recent
jobs, config posture). A scan re-reads the current state and diffs it against
the baseline; differences become a deterministic drift report recorded in
``change_scans``. Detecting drift never executes anything against a target.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from ksec.db.connection import Database
from ksec.identity.users import now_utc

SCOPES = ("assets", "findings", "jobs", "config")


@dataclass(frozen=True)
class ChangeBaseline:
    id: int
    name: str
    scope: str
    target: str
    snapshot: dict
    created_by: str
    created_at: str


@dataclass(frozen=True)
class ChangeScan:
    id: int
    baseline_id: int
    status: str
    drift: list
    created_at: str


class ChangeService:
    def __init__(self, db: Database, audit=None, notifications=None):
        self.db = db
        self.audit = audit
        self.notifications = notifications

    # -- baselines ---------------------------------------------------------

    def create_baseline(
        self,
        *,
        name: str,
        scope: str = "assets",
        target: str = "*",
        created_by: str = "",
    ) -> ChangeBaseline:
        if scope not in SCOPES:
            raise ValueError(f"invalid scope: {scope} (choose from {', '.join(SCOPES)})")
        if not name.strip():
            raise ValueError("name is required")
        snapshot = self._snapshot(scope, target)
        cursor = self.db.execute(
            "INSERT INTO change_baselines (name, scope, target, snapshot_json, created_by,"
            " created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (name.strip(), scope, target, json.dumps(snapshot), created_by, now_utc()),
        )
        baseline = self.get_baseline(cursor.lastrowid)
        assert baseline is not None
        self._audit("change.baseline.create", actor=created_by, target=str(baseline.id))
        return baseline

    def get_baseline(self, baseline_id: int) -> ChangeBaseline | None:
        row = self.db.query_one(
            "SELECT * FROM change_baselines WHERE id = ?", (baseline_id,)
        )
        return self._baseline_from_row(row) if row else None

    def list_baselines(self) -> list[ChangeBaseline]:
        rows = self.db.query_all("SELECT * FROM change_baselines ORDER BY id DESC")
        return [self._baseline_from_row(row) for row in rows]

    def remove_baseline(self, baseline_id: int) -> bool:
        cursor = self.db.execute(
            "DELETE FROM change_baselines WHERE id = ?", (baseline_id,)
        )
        if cursor.rowcount > 0:
            self._audit("change.baseline.delete", target=str(baseline_id))
            return True
        return False

    # -- scans -------------------------------------------------------------

    def scan(self, baseline_id: int, *, actor: str = "") -> ChangeScan:
        """Re-read the state for the baseline's scope and diff it.

        Adds/removes/changes are reported as drift items. A scan with no
        differences is ``clean``; otherwise ``drift``. A notification is
        recorded when drift is found.
        """
        baseline = self.get_baseline(baseline_id)
        if baseline is None:
            raise ValueError(f"unknown baseline: {baseline_id}")
        current = self._snapshot(baseline.scope, baseline.target)
        drift = self._diff(baseline.snapshot, current)
        status = "drift" if drift else "clean"
        cursor = self.db.execute(
            "INSERT INTO change_scans (baseline_id, status, drift_json, created_at)"
            " VALUES (?, ?, ?, ?)",
            (baseline_id, status, json.dumps(drift), now_utc()),
        )
        if drift and self.notifications:
            self.notifications.record(
                event_type="change.drift",
                title=f"Change detected on baseline {baseline.name}",
                body=f"{len(drift)} difference(s) on scope {baseline.scope}",
            )
        self._audit(
            "change.scan", actor=actor or "change", target=str(baseline_id),
            payload={"status": status, "drift_count": len(drift)},
        )
        scan = self.get_scan(cursor.lastrowid)
        assert scan is not None
        return scan

    def get_scan(self, scan_id: int) -> ChangeScan | None:
        row = self.db.query_one("SELECT * FROM change_scans WHERE id = ?", (scan_id,))
        return self._scan_from_row(row) if row else None

    def list_scans(self, baseline_id: int | None = None) -> list[ChangeScan]:
        if baseline_id is not None:
            rows = self.db.query_all(
                "SELECT * FROM change_scans WHERE baseline_id = ? ORDER BY id DESC",
                (baseline_id,),
            )
        else:
            rows = self.db.query_all("SELECT * FROM change_scans ORDER BY id DESC")
        return [self._scan_from_row(row) for row in rows]

    # -- snapshot helpers --------------------------------------------------

    def _snapshot(self, scope: str, target: str) -> dict:
        if scope == "assets":
            return self._assets_snapshot(target)
        if scope == "findings":
            return self._findings_snapshot()
        if scope == "jobs":
            return self._jobs_snapshot()
        return self._config_snapshot()

    def _assets_snapshot(self, target: str) -> dict:
        """Snapshot of the asset inventory: asset type -> list of targets.

        ``target`` may be an engagement id (int-like) to scope the snapshot
        to one engagement, or ``*`` for the whole inventory.
        """
        if target and target != "*" and target.isdigit():
            rows = self.db.query_all(
                "SELECT target, asset_type, criticality FROM assets WHERE engagement_id = ?"
                " ORDER BY target",
                (int(target),),
            )
        else:
            rows = self.db.query_all(
                "SELECT target, asset_type, criticality FROM assets ORDER BY target"
            )
        grouped: dict[str, list[dict]] = {}
        for row in rows:
            grouped.setdefault(row["asset_type"], []).append(
                {"target": row["target"], "criticality": row["criticality"]}
            )
        return {"assets": grouped}

    def _findings_snapshot(self) -> dict:
        rows = self.db.query_all(
            "SELECT title, severity, status, engagement_id FROM findings ORDER BY id"
        )
        return {
            "findings": [
                {
                    "title": r["title"],
                    "severity": r["severity"],
                    "status": r["status"],
                    "engagement_id": r["engagement_id"],
                }
                for r in rows
            ]
        }

    def _jobs_snapshot(self) -> dict:
        rows = self.db.query_all(
            "SELECT capability, state, COUNT(*) AS n FROM jobs GROUP BY capability, state"
            " ORDER BY capability, state"
        )
        return {
            "jobs": [
                {"capability": r["capability"], "state": r["state"], "count": r["n"]}
                for r in rows
            ]
        }

    def _config_snapshot(self) -> dict:
        """Snapshot of platform state counters (read-only, deterministic)."""
        counters: dict[str, int] = {}
        for table in ("users", "sessions", "engagements", "assets", "findings", "alerts",
                      "cases", "reports"):
            try:
                row = self.db.query_one(f"SELECT COUNT(*) AS c FROM {table}")
                counters[table] = int(row["c"]) if row else 0
            except Exception:  # pragma: no cover - pre-migration safety
                counters[table] = -1
        return {"counters": counters}

    @staticmethod
    def _diff(before: dict, after: dict) -> list[dict]:
        """Deep-ish diff that reports added/removed/changed keys as items.

        Deterministic ordering: sorted by the JSON serialization of the key.
        """
        drift: list[dict] = []

        def walk(a, b, path: str) -> None:
            if isinstance(a, dict) and isinstance(b, dict):
                keys = sorted(set(a) | set(b))
                for key in keys:
                    sub = f"{path}.{key}" if path else str(key)
                    if key not in a:
                        drift.append({"path": sub, "change": "added", "value": b[key]})
                    elif key not in b:
                        drift.append({"path": sub, "change": "removed", "value": a[key]})
                    else:
                        walk(a[key], b[key], sub)
                return
            if isinstance(a, list) and isinstance(b, list):
                if a != b:
                    drift.append({"path": path or "(list)", "change": "changed",
                                  "before": a, "after": b})
                return
            if a != b:
                drift.append({"path": path or "(value)", "change": "changed",
                              "before": a, "after": b})

        walk(before, after, "")
        return drift

    def _audit(self, event_type: str, *, actor: str = "", target: str | None = None,
               payload: dict | None = None) -> None:
        if self.audit:
            self.audit.record(
                event_type=event_type,
                actor=actor or None,
                action=event_type,
                target=target,
                outcome="success",
                payload=payload or {},
            )

    @staticmethod
    def _baseline_from_row(row: sqlite3.Row) -> ChangeBaseline:
        try:
            snapshot = json.loads(row["snapshot_json"] or "{}")
        except json.JSONDecodeError:
            snapshot = {}
        return ChangeBaseline(
            id=row["id"],
            name=row["name"],
            scope=row["scope"],
            target=row["target"] or "*",
            snapshot=snapshot,
            created_by=row["created_by"] or "",
            created_at=row["created_at"],
        )

    @staticmethod
    def _scan_from_row(row: sqlite3.Row) -> ChangeScan:
        try:
            drift = json.loads(row["drift_json"] or "[]")
        except json.JSONDecodeError:
            drift = []
        return ChangeScan(
            id=row["id"],
            baseline_id=row["baseline_id"],
            status=row["status"],
            drift=drift,
            created_at=row["created_at"],
        )
