"""DFIR module (spec: DFIR MODULE / TIMELINE CONSTRUCTION).

Forensic artifacts are collected with provenance (host, tool, evidence link)
and timeline events reconstruct the incident chronology. Timeline events can
be linked to artifacts and are always presented in chronological order.

Forensic extras:

* :meth:`hash_artifact` — record SHA-256/SHA-1 hashes of a collected file so
  the examiner can later prove the copy matches the source
* :meth:`chronology` — a merged, chronological view of artifacts and events
  for export (CSV / JSONL) and reporting
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime

from ksec.audit.service import AuditService
from ksec.db.connection import Database
from ksec.identity.users import now_utc

VALID_ARTIFACT_TYPES = (
    "file", "log", "process", "network", "auth", "browser",
    "malware", "registry", "memory", "other",
)

VALID_EVENT_TYPES = (
    "created", "modified", "deleted", "executed", "network", "login",
    "auth_failure", "privilege", "persistence", "exfiltration", "other",
)


def normalize_time(value: str | None) -> str | None:
    """Canonicalize an ISO-8601 timestamp (accepts 'Z' suffix)."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return None


@dataclass(frozen=True)
class Artifact:
    id: int
    case_id: int | None
    host: str
    artifact_type: str
    name: str
    details: str
    tool: str
    evidence_id: int | None
    collected_at: str
    created_at: str


@dataclass(frozen=True)
class TimelineEvent:
    id: int
    case_id: int | None
    artifact_id: int | None
    event_time: str
    event_type: str
    actor: str
    source: str
    details: str
    created_at: str


class DfirService:
    def __init__(self, db: Database, audit: AuditService | None = None):
        self.db = db
        self.audit = audit

    # -- artifacts ---------------------------------------------------------

    def add_artifact(
        self,
        case_id: int,
        name: str,
        artifact_type: str,
        *,
        host: str = "",
        details: str = "",
        tool: str = "",
        evidence_id: int | None = None,
        collected_at: str | None = None,
    ) -> Artifact:
        if artifact_type not in VALID_ARTIFACT_TYPES:
            raise ValueError(f"Invalid artifact type: {artifact_type}")
        if not name or not name.strip():
            raise ValueError("Artifact name must not be empty")
        case = self.db.query_one("SELECT id FROM cases WHERE id = ?", (case_id,))
        if case is None:
            raise ValueError(f"Unknown case: {case_id}")
        if evidence_id is not None:
            evidence = self.db.query_one(
                "SELECT id FROM evidence WHERE id = ?", (evidence_id,)
            )
            if evidence is None:
                raise ValueError(f"Unknown evidence: {evidence_id}")
        collected = normalize_time(collected_at) or now_utc()
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO dfir_artifacts (case_id, host, artifact_type, name, details,"
                " tool, evidence_id, collected_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?,"
                " ?, ?)",
                (case_id, host, artifact_type, name.strip(), details, tool, evidence_id,
                 collected, now_utc()),
            )
        artifact = self.get_artifact(cursor.lastrowid)
        assert artifact is not None
        if self.audit:
            self.audit.record(
                event_type="dfir.artifact.add",
                workspace="BLUE_TEAM",
                action="dfir.artifact.add",
                target=f"case:{case_id} artifact:{artifact.id}",
            )
        return artifact

    def get_artifact(self, artifact_id: int) -> Artifact | None:
        row = self.db.query_one("SELECT * FROM dfir_artifacts WHERE id = ?", (artifact_id,))
        return self._artifact_from_row(row) if row else None

    def list_artifacts(
        self, case_id: int | None = None, host: str | None = None
    ) -> list[Artifact]:
        sql = "SELECT * FROM dfir_artifacts"
        clauses: list[str] = []
        params: list = []
        if case_id is not None:
            clauses.append("case_id = ?")
            params.append(case_id)
        if host:
            clauses.append("host = ?")
            params.append(host)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY collected_at"
        return [self._artifact_from_row(r) for r in self.db.query_all(sql, params)]

    # -- timeline ----------------------------------------------------------

    def add_event(
        self,
        case_id: int,
        event_time: str,
        event_type: str,
        *,
        actor: str = "",
        source: str = "",
        details: str = "",
        artifact_id: int | None = None,
    ) -> TimelineEvent:
        if event_type not in VALID_EVENT_TYPES:
            raise ValueError(f"Invalid event type: {event_type}")
        normalized = normalize_time(event_time)
        if normalized is None:
            raise ValueError("event_time must be an ISO-8601 timestamp")
        case = self.db.query_one("SELECT id FROM cases WHERE id = ?", (case_id,))
        if case is None:
            raise ValueError(f"Unknown case: {case_id}")
        if artifact_id is not None:
            artifact = self.db.query_one(
                "SELECT id FROM dfir_artifacts WHERE id = ?", (artifact_id,)
            )
            if artifact is None:
                raise ValueError(f"Unknown artifact: {artifact_id}")
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO dfir_timeline (case_id, artifact_id, event_time, event_type,"
                " actor, source, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (case_id, artifact_id, normalized, event_type, actor, source, details,
                 now_utc()),
            )
        event = self.get_event(cursor.lastrowid)
        assert event is not None
        if self.audit:
            self.audit.record(
                event_type="dfir.event.add",
                workspace="BLUE_TEAM",
                action="dfir.event.add",
                target=f"case:{case_id} event:{event.id}",
            )
        return event

    def get_event(self, event_id: int) -> TimelineEvent | None:
        row = self.db.query_one("SELECT * FROM dfir_timeline WHERE id = ?", (event_id,))
        return self._event_from_row(row) if row else None

    def list_events(
        self,
        case_id: int | None = None,
        event_type: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[TimelineEvent]:
        sql = "SELECT * FROM dfir_timeline"
        clauses: list[str] = []
        params: list = []
        if case_id is not None:
            clauses.append("case_id = ?")
            params.append(case_id)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if since:
            clauses.append("event_time >= ?")
            params.append(normalize_time(since))
        if until:
            clauses.append("event_time <= ?")
            params.append(normalize_time(until))
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY event_time ASC"
        return [self._event_from_row(r) for r in self.db.query_all(sql, params)]

    def timeline(self, case_id: int | None = None) -> list[TimelineEvent]:
        """The incident timeline: all events in chronological order."""
        return self.list_events(case_id=case_id)

    # -- forensics ---------------------------------------------------------

    def hash_artifact(self, artifact_id: int, path: str) -> dict:
        """Hash a collected file and record the hashes on the artifact.

        Computes SHA-256 and SHA-1 over the file bytes plus size, then appends
        a ``[hash]`` block to the artifact's details so the recorded values
        travel with the artifact in lists and exports. Raises ValueError for
        unknown artifacts or unreadable files.
        """
        artifact = self.get_artifact(artifact_id)
        if artifact is None:
            raise ValueError(f"Unknown artifact: {artifact_id}")
        if not path or not os.path.isfile(path):
            raise ValueError(f"no such file: {path}")
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()
        size = 0
        try:
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    sha256.update(chunk)
                    sha1.update(chunk)
                    size += len(chunk)
        except OSError as exc:
            raise ValueError(f"cannot read {path}: {exc}") from exc
        block = (
            f"[hash] sha256={sha256.hexdigest()} sha1={sha1.hexdigest()}"
            f" size={size} path={os.path.abspath(path)}"
        )
        details = artifact.details
        if details:
            details = details + "\n" + block
        else:
            details = block
        self.db.execute(
            "UPDATE dfir_artifacts SET details = ? WHERE id = ?",
            (details, artifact_id),
        )
        if self.audit:
            self.audit.record(
                event_type="dfir.artifact.hash",
                workspace="BLUE_TEAM",
                action="dfir.artifact.hash",
                target=f"artifact:{artifact_id}",
                payload={"sha256": sha256.hexdigest(), "size": size, "path": path},
            )
        return {
            "artifact_id": artifact_id,
            "sha256": sha256.hexdigest(),
            "sha1": sha1.hexdigest(),
            "size": size,
            "path": os.path.abspath(path),
        }

    def chronology(self, case_id: int | None = None) -> list[dict]:
        """Merged, chronological view of artifact collections and timeline
        events for a case (export / reporting)."""
        rows: list[dict] = []
        for artifact in self.list_artifacts(case_id=case_id):
            rows.append({
                "kind": "artifact",
                "time": artifact.collected_at,
                "event_type": artifact.artifact_type,
                "name": artifact.name,
                "actor": "",
                "source": artifact.tool or artifact.host,
                "details": artifact.details,
                "ref_id": artifact.id,
            })
        for event in self.list_events(case_id=case_id):
            artifact_name = ""
            if event.artifact_id:
                linked = self.get_artifact(event.artifact_id)
                if linked:
                    artifact_name = linked.name
            rows.append({
                "kind": "event",
                "time": event.event_time,
                "event_type": event.event_type,
                "name": artifact_name,
                "actor": event.actor,
                "source": event.source,
                "details": event.details,
                "ref_id": event.id,
            })
        return sorted(rows, key=lambda r: (r["time"] or "", r["kind"]))

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _artifact_from_row(row: sqlite3.Row) -> Artifact:
        return Artifact(
            id=row["id"],
            case_id=row["case_id"],
            host=row["host"],
            artifact_type=row["artifact_type"],
            name=row["name"],
            details=row["details"],
            tool=row["tool"],
            evidence_id=row["evidence_id"],
            collected_at=row["collected_at"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> TimelineEvent:
        return TimelineEvent(
            id=row["id"],
            case_id=row["case_id"],
            artifact_id=row["artifact_id"],
            event_time=row["event_time"],
            event_type=row["event_type"],
            actor=row["actor"],
            source=row["source"],
            details=row["details"],
            created_at=row["created_at"],
        )