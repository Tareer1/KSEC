"""Finding engine (spec: FINDING ENGINE).

Findings carry severity, confidence, risk, evidence linkage, remediation and
a status lifecycle (open -> confirmed -> remediated -> verified).
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from ksec.db.connection import Database
from ksec.identity.users import now_utc
from ksec.risk.engine import RiskResult

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")
VALID_CONFIDENCE = ("low", "medium", "high")
VALID_STATUS = ("open", "confirmed", "false_positive", "accepted_risk", "remediated", "verified")
VALID_PRIORITY = ("low", "medium", "high", "critical")
VALID_REMEDIATION_STATUS = ("open", "in_progress", "completed", "verified", "rejected")
VALID_VERIFY_RESULT = ("verified", "failed", "inconclusive")


@dataclass(frozen=True)
class Finding:
    id: int
    engagement_id: int | None
    asset_id: int | None
    title: str
    description: str
    severity: str
    confidence: str
    recommendation: str
    status: str
    risk_score: float | None
    risk_level: str | None
    source: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class Remediation:
    id: int
    finding_id: int
    description: str
    owner: str
    priority: str
    status: str
    due_date: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class RemediationVerification:
    id: int
    remediation_id: int
    method: str
    result: str
    evidence_id: int | None
    verified_by: str
    details: str
    created_at: str


class FindingService:
    def __init__(self, db: Database):
        self.db = db

    def create(
        self,
        *,
        title: str,
        description: str = "",
        severity: str = "info",
        confidence: str = "medium",
        recommendation: str = "",
        asset_id: int | None = None,
        engagement_id: int | None = None,
        source: str = "",
        risk: RiskResult | None = None,
    ) -> Finding:
        if not title or not title.strip():
            raise ValueError("Finding title must not be empty")
        if severity not in VALID_SEVERITY:
            raise ValueError(f"Invalid severity: {severity}")
        if confidence not in VALID_CONFIDENCE:
            raise ValueError(f"Invalid confidence: {confidence}")
        now = now_utc()
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO findings (engagement_id, asset_id, title, description, severity,"
                " confidence, recommendation, status, risk_score, risk_level, source,"
                " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)",
                (
                    engagement_id,
                    asset_id,
                    title.strip(),
                    description,
                    severity,
                    confidence,
                    recommendation,
                    risk.score if risk else None,
                    risk.level if risk else None,
                    source,
                    now,
                    now,
                ),
            )
        return self.get(cursor.lastrowid)

    def get(self, finding_id: int) -> Finding | None:
        row = self.db.query_one("SELECT * FROM findings WHERE id = ?", (finding_id,))
        return self._from_row(row) if row else None

    def list(
        self,
        engagement_id: int | None = None,
        status: str | None = None,
        severity: str | None = None,
    ) -> list[Finding]:
        sql = "SELECT * FROM findings"
        clauses: list[str] = []
        params: list = []
        if engagement_id is not None:
            clauses.append("engagement_id = ?")
            params.append(engagement_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        return [self._from_row(row) for row in self.db.query_all(sql, params)]

    def update_status(self, finding_id: int, status: str) -> Finding:
        if status not in VALID_STATUS:
            raise ValueError(f"Invalid status: {status}")
        self.db.execute(
            "UPDATE findings SET status = ?, updated_at = ? WHERE id = ?",
            (status, now_utc(), finding_id),
        )
        finding = self.get(finding_id)
        if finding is None:
            raise ValueError(f"Unknown finding: {finding_id}")
        return finding

    def set_risk(self, finding_id: int, risk: RiskResult) -> Finding:
        self.db.execute(
            "UPDATE findings SET risk_score = ?, risk_level = ?, updated_at = ? WHERE id = ?",
            (risk.score, risk.level, now_utc(), finding_id),
        )
        return self.get(finding_id)

    # -- remediation engine (spec 08 #56-57, spec 05 #37-38) ----------------

    def remediations(self, finding_id: int) -> list[Remediation]:
        rows = self.db.query_all(
            "SELECT * FROM finding_remediations WHERE finding_id = ? ORDER BY id",
            (finding_id,),
        )
        return [self._remediation_from_row(r) for r in rows]

    def add_remediation(
        self,
        finding_id: int,
        *,
        description: str = "",
        owner: str = "",
        priority: str = "medium",
        due_date: str | None = None,
    ) -> Remediation:
        if self.get(finding_id) is None:
            raise ValueError(f"Unknown finding: {finding_id}")
        if priority not in VALID_PRIORITY:
            raise ValueError(f"Invalid priority: {priority}")
        now = now_utc()
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO finding_remediations (finding_id, description, owner, priority,"
                " status, due_date, created_at, updated_at) VALUES (?, ?, ?, ?, 'open', ?, ?, ?)",
                (finding_id, description, owner, priority, due_date, now, now),
            )
        return self._remediation_from_row(
            self.db.query_one(
                "SELECT * FROM finding_remediations WHERE id = ?", (cursor.lastrowid,)
            )
        )

    def update_remediation_status(self, remediation_id: int, status: str) -> Remediation:
        if status not in VALID_REMEDIATION_STATUS:
            raise ValueError(f"Invalid remediation status: {status}")
        self.db.execute(
            "UPDATE finding_remediations SET status = ?, updated_at = ? WHERE id = ?",
            (status, now_utc(), remediation_id),
        )
        row = self.db.query_one(
            "SELECT * FROM finding_remediations WHERE id = ?", (remediation_id,)
        )
        if row is None:
            raise ValueError(f"Unknown remediation: {remediation_id}")
        return self._remediation_from_row(row)

    def verify_remediation(
        self,
        remediation_id: int,
        *,
        method: str = "manual",
        result: str = "verified",
        evidence_id: int | None = None,
        verified_by: str = "",
        details: str = "",
    ) -> RemediationVerification:
        """Record a separate verification (spec 05 #38): a remediation is only
        VERIFIED through an explicit verification record with evidence."""
        row = self.db.query_one(
            "SELECT * FROM finding_remediations WHERE id = ?", (remediation_id,)
        )
        if row is None:
            raise ValueError(f"Unknown remediation: {remediation_id}")
        if result not in VALID_VERIFY_RESULT:
            raise ValueError(f"Invalid verification result: {result}")
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO remediation_verifications (remediation_id, method, result,"
                " evidence_id, verified_by, details, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (remediation_id, method, result, evidence_id, verified_by, details, now_utc()),
            )
        # If the verification confirms remediation, mark the remediation
        # verified and auto-propagate to the finding status.
        if result == "verified":
            self.update_remediation_status(remediation_id, "verified")
            finding_id = row["finding_id"]
            self.update_status(finding_id, "verified")
        elif result == "failed":
            self.update_remediation_status(remediation_id, "in_progress")
        return self._verification_from_row(
            self.db.query_one(
                "SELECT * FROM remediation_verifications WHERE id = ?", (cursor.lastrowid,)
            )
        )

    def verifications(self, remediation_id: int) -> list[RemediationVerification]:
        rows = self.db.query_all(
            "SELECT * FROM remediation_verifications WHERE remediation_id = ? ORDER BY id",
            (remediation_id,),
        )
        return [self._verification_from_row(r) for r in rows]

    @staticmethod
    def _remediation_from_row(row: sqlite3.Row | None) -> Remediation:
        assert row is not None
        return Remediation(
            id=row["id"],
            finding_id=row["finding_id"],
            description=row["description"],
            owner=row["owner"],
            priority=row["priority"],
            status=row["status"],
            due_date=row["due_date"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _verification_from_row(row: sqlite3.Row | None) -> RemediationVerification:
        assert row is not None
        return RemediationVerification(
            id=row["id"],
            remediation_id=row["remediation_id"],
            method=row["method"],
            result=row["result"],
            evidence_id=row["evidence_id"],
            verified_by=row["verified_by"],
            details=row["details"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Finding:
        return Finding(
            id=row["id"],
            engagement_id=row["engagement_id"],
            asset_id=row["asset_id"],
            title=row["title"],
            description=row["description"],
            severity=row["severity"],
            confidence=row["confidence"],
            recommendation=row["recommendation"],
            status=row["status"],
            risk_score=row["risk_score"],
            risk_level=row["risk_level"],
            source=row["source"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )