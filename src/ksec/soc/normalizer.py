"""SOC event normalization (spec: Event normalization).

Ingested events are heterogeneous: different sources name the same entity
differently. Normalization maps an arbitrary event onto a canonical record
with validated entity fields so enrichment, correlation and rule evaluation
are deterministic.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from ksec.db.connection import Database
from ksec.identity.users import now_utc
from ksec.normalization.service import normalize_domain, normalize_ip

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")

_SEVERITY_ALIASES = {
    "0": "info", "1": "low", "2": "low", "3": "medium", "4": "medium",
    "5": "medium", "6": "high", "7": "high", "8": "high", "9": "critical",
    "10": "critical", "informational": "info", "warn": "low", "warning": "low",
    "error": "medium", "alert": "high", "emergency": "critical", "crit": "critical",
}

_IPV4_IN_TEXT = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
_DOMAIN_IN_TEXT = re.compile(
    r"(?<![a-z0-9.])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![a-z0-9.])",
    re.IGNORECASE,
)


def normalize_severity(value: Any) -> str:
    """Map arbitrary severity labels onto the canonical 5-level scale."""
    if value is None:
        return "medium"
    text = str(value).strip().lower()
    if text in VALID_SEVERITY:
        return text
    if text in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[text]
    try:
        number = int(text)
        if 0 <= number <= 10:
            return _SEVERITY_ALIASES[str(number)]
    except ValueError:
        pass
    return "medium"


def _first_ip(text: str) -> str:
    match = _IPV4_IN_TEXT.search(text)
    if not match:
        return ""
    ip = normalize_ip(match.group(0))
    return ip or ""


def _first_domain(text: str) -> str:
    match = _DOMAIN_IN_TEXT.search(text)
    if not match:
        return ""
    return normalize_domain(match.group(0)) or ""


@dataclass(frozen=True)
class NormalizedEvent:
    id: int | None
    event_id: str
    source: str
    event_type: str
    severity: str
    host: str
    ip: str
    domain: str
    username: str
    process: str
    details: dict
    normalized: dict
    occurred_at: str
    created_at: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity,
            "host": self.host,
            "ip": self.ip,
            "domain": self.domain,
            "username": self.username,
            "process": self.process,
            "details": self.details,
            "occurred_at": self.occurred_at,
            "created_at": self.created_at,
        }


class EventNormalizer:
    """Convert a raw event dict into a canonical :class:`NormalizedEvent`."""

    # Field keys accepted as top-level event fields.
    _KEYS = (
        "source", "event_type", "type", "severity", "host", "ip", "domain",
        "username", "user", "process", "occurred_at", "timestamp", "time",
        "details", "message", "event_id", "id",
    )

    def normalize(self, raw: dict) -> NormalizedEvent:
        if not isinstance(raw, dict):
            raise ValueError("event must be a JSON object")

        # Accept nested payloads (e.g. {"event": {...}} or {"alert": {...}}).
        for wrapper in ("event", "alert", "data"):
            if wrapper in raw and isinstance(raw[wrapper], dict) and len(raw) <= 2:
                raw = {**raw, **raw[wrapper]}

        event_id = str(raw.get("event_id") or raw.get("id") or "").strip()
        if not event_id:
            raise ValueError("event requires 'event_id' (or 'id') for idempotent intake")

        source = str(raw.get("source") or "").strip() or "unknown"
        event_type = str(raw.get("event_type") or raw.get("type") or "").strip()
        if not event_type:
            raise ValueError("event requires 'event_type' (or 'type')")

        details = raw.get("details")
        if details is None and raw.get("message") is not None:
            details = {"message": raw["message"]}
        if details is None:
            details = {}
        if not isinstance(details, dict):
            details = {"message": str(details)}
        # Preserve unknown top-level fields as detail context.
        for key, value in raw.items():
            if key not in self._KEYS and key not in details and isinstance(value, (str, int, float, bool, list)):
                details[key] = value

        text = " ".join(
            str(v)
            for v in (
                raw.get("ip"), raw.get("host"), raw.get("domain"),
                details.get("ip"), details.get("dst_ip"), details.get("src_ip"),
                details.get("host"), details.get("domain"),
            )
            if v
        )

        ip = normalize_ip(str(raw.get("ip") or "")) or _first_ip(text)
        domain = normalize_domain(str(raw.get("domain") or "")) or _first_domain(text)
        host = str(raw.get("host") or "").strip().lower() or (domain or "")
        username = str(raw.get("username") or raw.get("user") or "").strip().lower()
        process = str(raw.get("process") or "").strip()
        severity = normalize_severity(raw.get("severity"))

        occurred_at = str(
            raw.get("occurred_at") or raw.get("timestamp") or raw.get("time") or ""
        )
        if not occurred_at:
            occurred_at = now_utc()

        normalized = {
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "host": host,
            "ip": ip,
            "domain": domain,
            "username": username,
            "process": process,
            "occurred_at": occurred_at,
        }
        return NormalizedEvent(
            id=None,
            event_id=event_id,
            source=source,
            event_type=event_type,
            severity=severity,
            host=host,
            ip=ip,
            domain=domain,
            username=username,
            process=process,
            details=details,
            normalized=normalized,
            occurred_at=occurred_at,
            created_at=now_utc(),
        )


class EventStore:
    """Persist and query normalized SOC events (idempotent intake)."""

    def __init__(self, db: Database):
        self.db = db
        self.normalizer = EventNormalizer()

    def ingest(self, raw: dict) -> tuple[NormalizedEvent, bool]:
        """Normalize + store an event. Returns (event, created).

        Re-ingesting the same ``event_id`` returns the stored event with
        ``created=False`` (deduplicated intake).
        """
        event = self.normalizer.normalize(raw)
        existing = self.db.query_one(
            "SELECT id FROM soc_events WHERE event_id = ?", (event.event_id,)
        )
        if existing is not None:
            stored = self.get(existing["id"])
            assert stored is not None
            return stored, False
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO soc_events (event_id, source, event_type, severity, host, ip,"
                " domain, username, process, details, normalized, occurred_at, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.event_id,
                    event.source,
                    event.event_type,
                    event.severity,
                    event.host,
                    event.ip,
                    event.domain,
                    event.username,
                    event.process,
                    json.dumps(event.details),
                    json.dumps(event.normalized),
                    event.occurred_at,
                    event.created_at,
                ),
            )
        stored = self.get(cursor.lastrowid)
        assert stored is not None
        return stored, True

    def get(self, event_row_id: int) -> NormalizedEvent | None:
        row = self.db.query_one("SELECT * FROM soc_events WHERE id = ?", (event_row_id,))
        return self._from_row(row) if row else None

    def list(
        self, limit: int = 50, event_type: str | None = None, entity: str | None = None
    ) -> list[NormalizedEvent]:
        sql = "SELECT * FROM soc_events"
        clauses: list[str] = []
        params: list = []
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if entity:
            entity = entity.strip().lower()
            clauses.append("(ip = ? OR domain = ? OR host = ?)")
            params.extend([entity, entity, entity])
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [self._from_row(row) for row in self.db.query_all(sql, params)]

    def recent_for_entity(
        self, entity: str, window_minutes: int = 60, exclude_event_id: str | None = None
    ) -> list[NormalizedEvent]:
        """Recent events sharing an entity (IP/domain/host), for correlation."""
        if not entity:
            return []
        rows = self.db.query_all(
            "SELECT * FROM soc_events WHERE (ip = ? OR domain = ? OR host = ?)"
            " AND datetime(occurred_at) >= datetime('now', ?) ORDER BY id DESC LIMIT 50",
            (entity, entity, entity, f"-{window_minutes} minutes"),
        )
        events = [self._from_row(row) for row in rows]
        if exclude_event_id:
            events = [e for e in events if e.event_id != exclude_event_id]
        return events

    @staticmethod
    def _from_row(row: sqlite3.Row) -> NormalizedEvent:
        return NormalizedEvent(
            id=row["id"],
            event_id=row["event_id"],
            source=row["source"],
            event_type=row["event_type"],
            severity=row["severity"],
            host=row["host"],
            ip=row["ip"],
            domain=row["domain"],
            username=row["username"],
            process=row["process"],
            details=json.loads(row["details"] or "{}"),
            normalized=json.loads(row["normalized"] or "{}"),
            occurred_at=row["occurred_at"],
            created_at=row["created_at"],
        )