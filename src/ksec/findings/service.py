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
VALID_STATUS = ("open", "confirmed", "false_positive", "remediated", "verified")


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