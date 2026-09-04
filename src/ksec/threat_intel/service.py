"""Threat intelligence (spec: IOCs / THREAT ACTORS / CAMPAIGNS / TTPs).

IOCs are normalized at registration so correlation is deterministic. Threat
actors are intelligence objects — never operator roles. ATT&CK mappings are
stored as framework records, not hardcoded assumptions.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from ksec.db.connection import Database
from ksec.findings.service import Finding
from ksec.identity.users import now_utc
from ksec.normalization.service import normalize_domain, normalize_ip

VALID_IOC_TYPES = (
    "IP", "DOMAIN", "URL", "HASH", "EMAIL", "USERNAME",
    "FILE", "PROCESS", "CERTIFICATE", "OTHER",
)
VALID_CONFIDENCE = ("low", "medium", "high")


def normalize_ioc_value(value: str, ioc_type: str) -> str:
    """Deterministic normalization used for matching and deduplication."""
    value = value.strip()
    if ioc_type == "IP":
        return normalize_ip(value) or value.lower()
    if ioc_type == "DOMAIN":
        return normalize_domain(value) or value.lower().rstrip(".")
    if ioc_type == "HASH":
        return value.lower()
    return value.lower()


@dataclass(frozen=True)
class Ioc:
    id: int
    type: str
    value: str
    normalized_value: str
    confidence: str
    source: str
    first_seen: str | None
    last_seen: str | None
    status: str
    actor_id: int | None
    campaign_id: int | None
    created_at: str


@dataclass(frozen=True)
class ThreatActor:
    id: int
    name: str
    aliases: list[str]
    description: str
    confidence: str
    sources: list[str]
    created_at: str


@dataclass(frozen=True)
class Campaign:
    id: int
    name: str
    description: str
    threat_actor_id: int | None
    start_date: str | None
    end_date: str | None
    confidence: str


@dataclass(frozen=True)
class Ttp:
    id: int
    framework: str
    technique_id: str
    name: str
    description: str
    tactic: str
    source: str


class ThreatIntelService:
    def __init__(self, db: Database):
        self.db = db

    # -- IOCs --------------------------------------------------------------

    def register_ioc(
        self,
        value: str,
        ioc_type: str,
        *,
        confidence: str = "medium",
        source: str = "",
        first_seen: str | None = None,
        last_seen: str | None = None,
        actor_id: int | None = None,
        campaign_id: int | None = None,
    ) -> Ioc:
        ioc_type = ioc_type.upper()
        if ioc_type not in VALID_IOC_TYPES:
            raise ValueError(f"Invalid IOC type: {ioc_type}")
        if confidence not in VALID_CONFIDENCE:
            raise ValueError(f"Invalid confidence: {confidence}")
        if not value or not value.strip():
            raise ValueError("IOC value must not be empty")
        normalized = normalize_ioc_value(value, ioc_type)
        existing = self.db.query_one(
            "SELECT id FROM iocs WHERE type = ? AND normalized_value = ?",
            (ioc_type, normalized),
        )
        if existing is not None:
            # Upsert metadata (idempotent registration); enrich links when given.
            self.db.execute(
                "UPDATE iocs SET last_seen = ?, source = ?, actor_id = COALESCE(?, actor_id),"
                " campaign_id = COALESCE(?, campaign_id) WHERE id = ?",
                (last_seen or now_utc(), source, actor_id, campaign_id, existing["id"]),
            )
            return self.get_ioc(existing["id"])
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO iocs (type, value, normalized_value, confidence, source,"
                " first_seen, last_seen, status, actor_id, campaign_id, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)",
                (ioc_type, value.strip(), normalized, confidence, source, first_seen,
                 last_seen, actor_id, campaign_id, now_utc()),
            )
        return self.get_ioc(cursor.lastrowid)

    def get_ioc(self, ioc_id: int) -> Ioc | None:
        row = self.db.query_one("SELECT * FROM iocs WHERE id = ?", (ioc_id,))
        return self._ioc_from_row(row) if row else None

    def list_iocs(self, ioc_type: str | None = None, status: str | None = None) -> list[Ioc]:
        sql = "SELECT * FROM iocs"
        clauses: list[str] = []
        params: list = []
        if ioc_type:
            clauses.append("type = ?")
            params.append(ioc_type.upper())
        if status:
            clauses.append("status = ?")
            params.append(status)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        return [self._ioc_from_row(r) for r in self.db.query_all(sql, params)]

    # -- extraction / auto-registration -----------------------------------

    def extract_and_register(
        self,
        entities: list[dict] | None = None,
        raw_text: str = "",
        *,
        source: str = "",
        default_confidence: str = "medium",
    ) -> dict:
        """Extract IOC candidates from scan evidence and register them.

        ``entities`` are structured parser output (high confidence);
        ``raw_text`` is the tool's raw output (low/medium confidence).
        Returns a summary dict with the extracted candidates and the number
        of newly registered vs previously known IOCs.
        """
        from ksec.threat_intel.extractor import IocExtractor

        extractor = IocExtractor()
        candidates = extractor.extract_entities(entities or [])
        candidates += extractor.extract_text(raw_text)

        registered: list[Ioc] = []
        newly_registered = 0
        previously_known = 0
        for candidate in candidates:
            confidence = candidate.confidence or default_confidence
            existed = self.db.query_one(
                "SELECT id FROM iocs WHERE type = ? AND normalized_value = ?",
                (candidate.type, candidate.normalized_value),
            )
            ioc = self.register_ioc(
                candidate.value,
                candidate.type,
                confidence=confidence,
                source=source or f"auto:{candidate.origin}",
            )
            registered.append(ioc)
            if existed is None:
                newly_registered += 1
            else:
                previously_known += 1

        return {
            "candidates": [
                {
                    "type": c.type,
                    "value": c.value,
                    "normalized": c.normalized_value,
                    "confidence": c.confidence,
                    "origin": c.origin,
                }
                for c in candidates
            ],
            "total_candidates": len(candidates),
            "registered": newly_registered,
            "already_known": previously_known,
            "iocs": registered,
        }

    def extract_from_job_result(self, job_id: str, source: str = "") -> dict:
        """Extract IOCs from a stored job's result (entities + raw output).

        Used by ``ksec intel extract --job`` to re-run extraction over
        previously collected evidence.
        """
        row = self.db.query_one(
            "SELECT capability, target, result FROM jobs WHERE id = ?", (job_id,)
        )
        if row is None:
            raise ValueError(f"Unknown job: {job_id}")
        result = json.loads(row["result"] or "{}")
        entities = result.get("entities") or []
        raw_text = result.get("stdout") or ""
        source = source or f"job:{job_id}:{row['capability']}"
        return self.extract_and_register(entities, raw_text, source=source)

    def extract_from_evidence(self, evidence_id: int, source: str = "") -> dict:
        """Extract IOCs from stored evidence content."""
        row = self.db.query_one(
            "SELECT tool, content FROM evidence WHERE id = ?", (evidence_id,)
        )
        if row is None:
            raise ValueError(f"Unknown evidence: {evidence_id}")
        source = source or f"evidence:{evidence_id}:{row['tool']}"
        return self.extract_and_register(raw_text=row["content"], source=source)

    def correlate(self, value: str) -> list[Ioc]:
        """Find IOCs matching an observation across all IOC types."""
        haystack = value.strip().lower()
        matches = []
        for ioc in self.list_iocs(status="active"):
            if ioc.type == "IP":
                candidate = normalize_ip(haystack)
            elif ioc.type == "DOMAIN":
                candidate = normalize_domain(haystack)
            else:
                candidate = haystack
            if candidate is not None and candidate == ioc.normalized_value:
                matches.append(ioc)
        return matches

    def correlate_finding(self, finding: Finding) -> list[Ioc]:
        """Scan a finding's text for known IOC values."""
        text = " ".join(
            [finding.title, finding.description, finding.source, finding.recommendation]
        ).lower()
        matches = []
        for ioc in self.list_iocs(status="active"):
            if ioc.normalized_value and ioc.normalized_value in text:
                matches.append(ioc)
        return matches

    def enrich(self, ioc_id: int) -> dict:
        """Enrich an IOC: linked actor, campaign, campaign TTPs and findings."""
        ioc = self.get_ioc(ioc_id)
        if ioc is None:
            raise ValueError(f"Unknown IOC: {ioc_id}")
        actor = self.get_actor(ioc.actor_id) if ioc.actor_id else None
        campaign = self.get_campaign(ioc.campaign_id) if ioc.campaign_id else None
        ttps = self.campaign_ttps(ioc.campaign_id) if ioc.campaign_id else []
        related_findings = self._findings_mentioning(ioc.normalized_value)
        return {
            "ioc": ioc,
            "actor": actor,
            "campaign": campaign,
            "ttps": ttps,
            "related_findings": related_findings,
        }

    def _findings_mentioning(self, normalized_value: str) -> list[sqlite3.Row]:
        rows = self.db.query_all(
            "SELECT id, title, severity, status FROM findings"
            " WHERE LOWER(title) LIKE ? OR LOWER(description) LIKE ? OR LOWER(source) LIKE ?",
            (f"%{normalized_value.lower()}%",) * 3,
        )
        return rows

    # -- actors / campaigns / TTPs -----------------------------------------

    def add_actor(
        self,
        name: str,
        description: str = "",
        aliases: list[str] | None = None,
        confidence: str = "medium",
        sources: list[str] | None = None,
    ) -> ThreatActor:
        if not name or not name.strip():
            raise ValueError("Actor name must not be empty")
        now = now_utc()
        try:
            with self.db.transaction() as conn:
                cursor = conn.execute(
                    "INSERT INTO threat_actors (name, aliases, description, confidence,"
                    " sources, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (name.strip(), json.dumps(aliases or []), description, confidence,
                     json.dumps(sources or []), now, now),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Actor {name!r} already exists") from exc
        return self.get_actor(cursor.lastrowid)

    def get_actor(self, actor_id: int | None) -> ThreatActor | None:
        if actor_id is None:
            return None
        row = self.db.query_one("SELECT * FROM threat_actors WHERE id = ?", (actor_id,))
        return self._actor_from_row(row) if row else None

    def list_actors(self) -> list[ThreatActor]:
        rows = self.db.query_all("SELECT * FROM threat_actors ORDER BY name")
        return [self._actor_from_row(row) for row in rows]

    def add_campaign(
        self,
        name: str,
        description: str = "",
        actor_id: int | None = None,
        confidence: str = "medium",
    ) -> Campaign:
        try:
            with self.db.transaction() as conn:
                cursor = conn.execute(
                    "INSERT INTO campaigns (name, description, threat_actor_id, confidence,"
                    " sources, created_at) VALUES (?, ?, ?, ?, '[]', ?)",
                    (name.strip(), description, actor_id, confidence, now_utc()),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Campaign {name!r} already exists") from exc
        return self.get_campaign(cursor.lastrowid)

    def get_campaign(self, campaign_id: int | None) -> Campaign | None:
        if campaign_id is None:
            return None
        row = self.db.query_one("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
        return self._campaign_from_row(row) if row else None

    def list_campaigns(self) -> list[Campaign]:
        rows = self.db.query_all("SELECT * FROM campaigns ORDER BY id")
        return [self._campaign_from_row(row) for row in rows]

    def add_ttp(
        self,
        technique_id: str,
        name: str,
        description: str = "",
        tactic: str = "",
        framework: str = "mitre-attack",
        source: str = "",
    ) -> Ttp:
        try:
            with self.db.transaction() as conn:
                cursor = conn.execute(
                    "INSERT INTO ttps (framework, technique_id, name, description, tactic,"
                    " source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (framework, technique_id.strip().upper(), name.strip(), description,
                     tactic, source, now_utc()),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"TTP {framework}/{technique_id} already exists") from exc
        return self.get_ttp(cursor.lastrowid)

    def get_ttp(self, ttp_id: int) -> Ttp | None:
        row = self.db.query_one("SELECT * FROM ttps WHERE id = ?", (ttp_id,))
        return self._ttp_from_row(row) if row else None

    def list_ttps(self) -> list[Ttp]:
        rows = self.db.query_all("SELECT * FROM ttps ORDER BY technique_id")
        return [self._ttp_from_row(row) for row in rows]

    def link_ttp(self, campaign_id: int, ttp_id: int) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO campaign_ttps (campaign_id, ttp_id) VALUES (?, ?)",
            (campaign_id, ttp_id),
        )

    def campaign_ttps(self, campaign_id: int) -> list[Ttp]:
        rows = self.db.query_all(
            "SELECT t.* FROM ttps t JOIN campaign_ttps ct ON ct.ttp_id = t.id"
            " WHERE ct.campaign_id = ? ORDER BY t.technique_id",
            (campaign_id,),
        )
        return [self._ttp_from_row(row) for row in rows]

    def link_ioc_actor(self, ioc_id: int, actor_id: int) -> Ioc:
        self.db.execute("UPDATE iocs SET actor_id = ? WHERE id = ?", (actor_id, ioc_id))
        return self.get_ioc(ioc_id)

    # -- row mapping -------------------------------------------------------

    @staticmethod
    def _ioc_from_row(row: sqlite3.Row) -> Ioc:
        return Ioc(
            id=row["id"],
            type=row["type"],
            value=row["value"],
            normalized_value=row["normalized_value"],
            confidence=row["confidence"],
            source=row["source"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            status=row["status"],
            actor_id=row["actor_id"],
            campaign_id=row["campaign_id"],
            created_at=row["created_at"],
        )

    @staticmethod
    def _actor_from_row(row: sqlite3.Row) -> ThreatActor:
        return ThreatActor(
            id=row["id"],
            name=row["name"],
            aliases=json.loads(row["aliases"] or "[]"),
            description=row["description"],
            confidence=row["confidence"],
            sources=json.loads(row["sources"] or "[]"),
            created_at=row["created_at"],
        )

    @staticmethod
    def _campaign_from_row(row: sqlite3.Row) -> Campaign:
        return Campaign(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            threat_actor_id=row["threat_actor_id"],
            start_date=row["start_date"],
            end_date=row["end_date"],
            confidence=row["confidence"],
        )

    @staticmethod
    def _ttp_from_row(row: sqlite3.Row) -> Ttp:
        return Ttp(
            id=row["id"],
            framework=row["framework"],
            technique_id=row["technique_id"],
            name=row["name"],
            description=row["description"],
            tactic=row["tactic"],
            source=row["source"],
        )