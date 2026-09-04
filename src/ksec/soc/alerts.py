"""SOC alerts (spec 05#48 ALERT ENTITY, spec 08#16 SOC MODULE).

Alerts are actionable security signals with a lifecycle:
open -> acknowledged -> resolved (or closed). Each alert tracks its source
event, the rule that fired it, linked asset/finding/case/IOC, a risk score
and the acknowledgement/resolution timestamps.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass

from ksec.audit.service import AuditService
from ksec.core.errors import KSECError
from ksec.db.connection import Database
from ksec.identity.users import now_utc

VALID_STATUS = ("open", "acknowledged", "resolved", "closed")


@dataclass(frozen=True)
class Alert:
    id: int
    alert_id: str
    source: str
    type: str
    severity: str
    risk_score: float
    status: str
    rule_id: int | None
    event_id: int | None
    asset_id: int | None
    finding_id: int | None
    case_id: int | None
    ioc_id: int | None
    summary: str
    details: dict
    created_at: str
    acknowledged_at: str | None
    resolved_at: str | None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "source": self.source,
            "type": self.type,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "status": self.status,
            "rule_id": self.rule_id,
            "event_id": self.event_id,
            "asset_id": self.asset_id,
            "finding_id": self.finding_id,
            "case_id": self.case_id,
            "ioc_id": self.ioc_id,
            "summary": self.summary,
            "details": self.details,
            "created_at": self.created_at,
            "acknowledged_at": self.acknowledged_at,
            "resolved_at": self.resolved_at,
        }


class AlertService:
    def __init__(self, db: Database, audit: AuditService | None = None):
        self.db = db
        self.audit = audit

    def create(
        self,
        *,
        source: str,
        type: str,
        severity: str,
        risk_score: float,
        summary: str,
        details: dict | None = None,
        rule_id: int | None = None,
        event_id: int | None = None,
        asset_id: int | None = None,
        finding_id: int | None = None,
        case_id: int | None = None,
        ioc_id: int | None = None,
    ) -> Alert:
        now = now_utc()
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO alerts (alert_id, source, type, severity, risk_score, status,"
                " rule_id, event_id, asset_id, finding_id, case_id, ioc_id, summary,"
                " details, created_at) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?,"
                " ?, ?)",
                (
                    uuid.uuid4().hex,
                    source,
                    type,
                    severity,
                    float(risk_score),
                    rule_id,
                    event_id,
                    asset_id,
                    finding_id,
                    case_id,
                    ioc_id,
                    summary,
                    json.dumps(details or {}),
                    now,
                ),
            )
        alert = self.get(cursor.lastrowid)
        assert alert is not None
        if self.audit:
            self.audit.record(
                event_type="alert.create",
                workspace="BLUE_TEAM",
                action="alert.create",
                target=f"alert:{alert.id}",
                outcome="success",
            )
        return alert

    def get(self, alert_id: int) -> Alert | None:
        row = self.db.query_one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        return self._from_row(row) if row else None

    def list(
        self, limit: int = 50, status: str | None = None, severity: str | None = None
    ) -> list[Alert]:
        sql = "SELECT * FROM alerts"
        clauses: list[str] = []
        params: list = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [self._from_row(row) for row in self.db.query_all(sql, params)]

    def count(self, status: str | None = None) -> int:
        sql = "SELECT COUNT(*) AS c FROM alerts"
        params: tuple = ()
        if status:
            sql += " WHERE status = ?"
            params = (status,)
        row = self.db.query_one(sql, params)
        return int(row["c"]) if row else 0

    def set_status(self, alert_row_id: int, status: str) -> Alert:
        if status not in VALID_STATUS:
            raise KSECError(f"invalid alert status: {status}")
        alert = self.get(alert_row_id)
        if alert is None:
            raise KSECError(f"unknown alert: {alert_row_id}")
        now = now_utc()
        acknowledged = alert.acknowledged_at
        resolved = alert.resolved_at
        if status == "acknowledged" and acknowledged is None:
            acknowledged = now
        if status in ("resolved", "closed") and resolved is None:
            resolved = now
        self.db.execute(
            "UPDATE alerts SET status = ?, acknowledged_at = ?, resolved_at = ? WHERE id = ?",
            (status, acknowledged, resolved, alert_row_id),
        )
        updated = self.get(alert_row_id)
        assert updated is not None
        if self.audit:
            self.audit.record(
                event_type=f"alert.{status}",
                workspace="BLUE_TEAM",
                action=f"alert.{status}",
                target=f"alert:{alert_row_id}",
                outcome="success",
            )
        return updated

    def acknowledge(self, alert_row_id: int) -> Alert:
        return self.set_status(alert_row_id, "acknowledged")

    def resolve(self, alert_row_id: int, *, case_id: int | None = None) -> Alert:
        alert = self.set_status(alert_row_id, "resolved")
        if case_id is not None:
            self.db.execute(
                "UPDATE alerts SET case_id = ? WHERE id = ?", (case_id, alert.id)
            )
            alert = self.get(alert.id)
            assert alert is not None
        return alert

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Alert:
        return Alert(
            id=row["id"],
            alert_id=row["alert_id"],
            source=row["source"],
            type=row["type"],
            severity=row["severity"],
            risk_score=row["risk_score"] or 0.0,
            status=row["status"],
            rule_id=row["rule_id"],
            event_id=row["event_id"],
            asset_id=row["asset_id"],
            finding_id=row["finding_id"],
            case_id=row["case_id"],
            ioc_id=row["ioc_id"],
            summary=row["summary"],
            details=json.loads(row["details"] or "{}"),
            created_at=row["created_at"],
            acknowledged_at=row["acknowledged_at"],
            resolved_at=row["resolved_at"],
        )