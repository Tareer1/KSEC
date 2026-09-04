"""SOC detection rules (spec 08#18 DETECTION ENGINE).

Deterministic rules evaluate normalized events: field equality, inequality,
substring, regex and minimum-severity gates. A rule that fires contributes a
severity and a risk boost; rules may auto-open cases.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass

from ksec.core.errors import KSECError
from ksec.db.connection import Database
from ksec.identity.users import now_utc

OPERATORS = ("eq", "ne", "contains", "regex", "min_severity")
_FIELDS = (
    "ip", "domain", "host", "username", "process", "source",
    "event_type", "severity", "details",
)
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class DetectionRule:
    id: int | None
    name: str
    description: str
    enabled: bool
    event_type: str
    field: str
    operator: str
    value: str
    severity: str
    risk_boost: float
    open_case: bool
    created_at: str
    updated_at: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "event_type": self.event_type,
            "field": self.field,
            "operator": self.operator,
            "value": self.value,
            "severity": self.severity,
            "risk_boost": self.risk_boost,
            "open_case": self.open_case,
        }

    def matches(self, event) -> bool:
        """Evaluate this rule against a :class:`NormalizedEvent`."""
        if self.event_type and self.event_type != event.event_type:
            return False
        if self.operator == "min_severity":
            return SEVERITY_RANK[event.severity] >= SEVERITY_RANK.get(self.value, 2)

        actual = self._field_value(event)
        if actual is None:
            actual = ""
        actual = str(actual).lower()
        expected = self.value.lower()
        if self.operator == "eq":
            return actual == expected
        if self.operator == "ne":
            return actual != expected
        if self.operator == "contains":
            return expected in actual
        if self.operator == "regex":
            try:
                return re.search(self.value, actual) is not None
            except re.error:
                return False
        return False

    def _field_value(self, event) -> str:
        if self.field == "details":
            return " ".join(str(v) for v in event.details.values())
        value = getattr(event, self.field, "")
        return value or ""


class RuleStore:
    def __init__(self, db: Database):
        self.db = db

    def create(
        self,
        name: str,
        *,
        description: str = "",
        event_type: str = "",
        field: str = "ip",
        operator: str = "eq",
        value: str = "",
        severity: str = "medium",
        risk_boost: float = 0.0,
        open_case: bool = True,
    ) -> DetectionRule:
        errors = self.validate(
            name=name, field=field, operator=operator, severity=severity
        )
        if errors:
            raise KSECError(f"invalid rule: {'; '.join(errors)}")
        now = now_utc()
        try:
            with self.db.transaction() as conn:
                cursor = conn.execute(
                    "INSERT INTO detection_rules (name, description, enabled, event_type,"
                    " field, operator, value, severity, risk_boost, open_case, created_at,"
                    " updated_at) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (name.strip(), description, event_type, field, operator, value,
                     severity, float(risk_boost), 1 if open_case else 0, now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise KSECError(f"rule {name!r} already exists") from exc
        rule = self.get(cursor.lastrowid)
        assert rule is not None
        return rule

    @staticmethod
    def validate(*, name: str, field: str, operator: str, severity: str) -> list[str]:
        errors: list[str] = []
        if not name or not name.strip():
            errors.append("name is required")
        if field not in _FIELDS:
            errors.append(f"field must be one of {', '.join(_FIELDS)}")
        if operator not in OPERATORS:
            errors.append(f"operator must be one of {', '.join(OPERATORS)}")
        if severity not in SEVERITY_RANK:
            errors.append("severity must be info|low|medium|high|critical")
        return errors

    def get(self, rule_id: int) -> DetectionRule | None:
        row = self.db.query_one(
            "SELECT * FROM detection_rules WHERE id = ?", (rule_id,)
        )
        return self._from_row(row) if row else None

    def get_by_name(self, name: str) -> DetectionRule | None:
        row = self.db.query_one(
            "SELECT * FROM detection_rules WHERE name = ?", (name,)
        )
        return self._from_row(row) if row else None

    def list(self, enabled_only: bool = False) -> list[DetectionRule]:
        sql = "SELECT * FROM detection_rules"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY name"
        return [self._from_row(row) for row in self.db.query_all(sql)]

    def set_enabled(self, rule_id: int, enabled: bool) -> DetectionRule:
        self.db.execute(
            "UPDATE detection_rules SET enabled = ?, updated_at = ? WHERE id = ?",
            (1 if enabled else 0, now_utc(), rule_id),
        )
        rule = self.get(rule_id)
        if rule is None:
            raise KSECError(f"unknown rule: {rule_id}")
        return rule

    def delete(self, rule_id: int) -> None:
        self.db.execute("DELETE FROM detection_rules WHERE id = ?", (rule_id,))

    @staticmethod
    def _from_row(row: sqlite3.Row) -> DetectionRule:
        return DetectionRule(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            enabled=bool(row["enabled"]),
            event_type=row["event_type"],
            field=row["field"],
            operator=row["operator"],
            value=row["value"],
            severity=row["severity"],
            risk_boost=row["risk_boost"] or 0.0,
            open_case=bool(row["open_case"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )