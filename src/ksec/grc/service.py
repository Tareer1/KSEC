"""GRC / Compliance service (spec 08 #36-37).

Runs deterministic, read-only checks that provide evidence for framework
controls (NIST 800-53, CIS, OWASP, ISO 27001, SOC 2, PCI DSS). Results are
versioned (GRC_VERSION) and every run is stored as evidence so the mapping
Framework -> Control -> Requirement -> Technical Test -> Evidence -> Status
(spec 08 #37) is preserved. KSEC never claims legal certification.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from ksec.audit.service import AuditService
from ksec.db.connection import Database
from ksec.identity.users import now_utc
from ksec.grc.frameworks import CONTROLS, GRC_VERSION, check_ids, controls, frameworks


@dataclass(frozen=True)
class GrcCheckResult:
    check_id: str
    status: str            # PASS | FAIL | NOT_APPLICABLE | NOT_RUN
    detail: str


class GrcService:
    def __init__(self, db: Database, audit: AuditService, config=None, evidence=None,
                 vuln=None, backups=None):
        self.db = db
        self.audit = audit
        self.config = config
        self.evidence = evidence
        self.vuln = vuln
        self.backups = backups

    def run_checks(self, target: str | None = None) -> list[GrcCheckResult]:
        """Run every deterministic check once; returns stable ordered results."""
        results: dict[str, GrcCheckResult] = {}

        def _set(check_id: str, status: str, detail: str) -> None:
            results[check_id] = GrcCheckResult(check_id, status, detail)

        # -- platform checks (local, read-only) ---------------------------
        audit_ok = bool(self.config) and getattr(self.config, "audit_enabled", False)
        audit_count = 0
        if audit_ok:
            try:
                audit_count = self.audit.count()
            except Exception:
                audit_count = 0
        _set("audit_active", "PASS" if audit_ok and audit_count > 0 else "FAIL",
             f"audit enabled={audit_ok}, events={audit_count}")

        require_auth = bool(self.config) and getattr(self.config, "require_authorization", True)
        _set("scope_enforcement", "PASS" if require_auth else "FAIL",
             f"require_authorization={require_auth}")

        engagements = self.db.query_all("SELECT COUNT(*) AS c FROM engagements")[0]["c"]
        scope_rules = self.db.query_all("SELECT COUNT(*) AS c FROM authorizations")[0]["c"] \
            if self._has_table("authorizations") else 0
        auth_ok = engagements > 0 and scope_rules > 0
        _set("authorization", "PASS" if auth_ok else "FAIL",
             f"engagements={engagements}, scope_rules={scope_rules}")

        evidence_ok = True
        evidence_total = 0
        if self.evidence is not None:
            for ev in self.evidence.list():
                evidence_total += 1
                ok, _ = self.evidence.verify(ev.id)
                if not ok:
                    evidence_ok = False
        if evidence_total == 0:
            _set("evidence_integrity", "NOT_APPLICABLE", "no evidence to verify")
        else:
            _set("evidence_integrity", "PASS" if evidence_ok else "FAIL",
                 f"{evidence_total} evidence objects verified")

        backup_ok = False
        backup_detail = "no backups found"
        if self.backups is not None:
            try:
                backups = self.backups.list()
                if backups:
                    backup_detail = f"{len(backups)} backup(s) found"
                    # backups.list() orders DESC, so [0] is the most recent.
                    ok, _ = self.backups.verify(backups[0].id)
                    backup_ok = ok
                    backup_detail += f"; latest verify={'ok' if ok else 'FAIL'}"
            except Exception as exc:  # noqa: BLE001
                backup_detail = f"backup check error: {exc}"
        _set("backup_verified", "PASS" if backup_ok else "FAIL", backup_detail)

        # -- targeted checks (need an in-scope target) ---------------------
        if target:
            for check_id in ("tls_version", "security_headers", "banner_disclosure",
                             "dev_fingerprint"):
                _set(check_id, "NOT_RUN", "targeted check requires ksec vuln check output")
        else:
            for check_id in ("tls_version", "security_headers", "banner_disclosure",
                             "dev_fingerprint"):
                _set(check_id, "NOT_RUN", "no target provided; run grc check with --target")

        ordered = [results[c] for c in sorted(check_ids()) if c in results]
        for extra in sorted(set(check_ids()) - set(results)):
            ordered.append(GrcCheckResult(extra, "NOT_RUN", "check not executed"))
        return ordered

    def status(self, framework: str | None = None) -> dict:
        """Per-framework status derived from the last stored snapshot (if any)
        or the live check run without a target."""
        results = {r.check_id: r for r in self.run_checks()}
        summary = []
        for ctrl in controls(framework):
            ctrl_results = [results.get(cid) for cid in ctrl.check_ids]
            passed = all(r and r.status == "PASS" for r in ctrl_results)
            failed = any(r and r.status == "FAIL" for r in ctrl_results)
            state = "PASS" if passed else ("FAIL" if failed else "NOT_RUN")
            summary.append({
                "framework": ctrl.framework,
                "control_id": ctrl.control_id,
                "title": ctrl.title,
                "status": state,
                "checks": [
                    {"check_id": cid, "status": results.get(cid).status if results.get(cid) else "NOT_RUN"}
                    for cid in ctrl.check_ids
                ],
            })
        return {
            "grc_version": GRC_VERSION,
            "framework": framework or "ALL",
            "controls": summary,
            "passed": sum(1 for s in summary if s["status"] == "PASS"),
            "failed": sum(1 for s in summary if s["status"] == "FAIL"),
            "not_run": sum(1 for s in summary if s["status"] == "NOT_RUN"),
        }

    def snapshot(self, target: str | None = None, actor: str = "grc") -> dict:
        """Run all checks and store the result as evidence + audit event."""
        results = self.run_checks(target=target)
        payload = {
            "grc_version": GRC_VERSION,
            "generated_at": now_utc(),
            "target": target,
            "checks": [vars(r) for r in results],
        }
        evidence_id = None
        if self.evidence is not None:
            evidence = self.evidence.add(
                json.dumps(payload, indent=2, default=str),
                tool="grc",
                operator=actor,
                collection_method="grc.snapshot",
                source=f"grc:{GRC_VERSION}",
            )
            evidence_id = evidence.id
        self.audit.record(
            event_type="grc.snapshot",
            actor=actor,
            action="grc.snapshot",
            target=target or None,
            outcome="success",
            payload={"evidence_id": evidence_id, "checks": len(results)},
        )
        return {"evidence_id": evidence_id, "payload": payload}

    def _has_table(self, table: str) -> bool:
        row = self.db.query_one(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
        )
        return row is not None


def available_checks() -> list[str]:
    return sorted(check_ids())