"""Asset engine (spec: ASSET ENGINE).

Assets are the things being assessed: hosts, domains, URLs, CIDRs, cloud
resources, etc. They support ownership, criticality, tags and scope linkage.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from ksec.db.connection import Database
from ksec.identity.users import now_utc

VALID_CRITICALITY = ("low", "medium", "high", "critical")
VALID_TYPES = ("host", "ip", "domain", "cidr", "url", "application", "container", "cloud", "wireless")


@dataclass(frozen=True)
class Asset:
    id: int
    engagement_id: int | None
    target: str
    asset_type: str
    criticality: str
    owner: str
    tags: list[str]
    source: str
    created_at: str


class AssetService:
    def __init__(self, db: Database):
        self.db = db

    def register(
        self,
        target: str,
        *,
        asset_type: str = "host",
        criticality: str = "low",
        owner: str = "",
        tags: list[str] | None = None,
        engagement_id: int | None = None,
        source: str = "",
    ) -> Asset:
        target = target.strip().lower()
        if not target:
            raise ValueError("Asset target must not be empty")
        if asset_type not in VALID_TYPES:
            raise ValueError(f"Invalid asset type: {asset_type}")
        if criticality not in VALID_CRITICALITY:
            raise ValueError(f"Invalid criticality: {criticality}")
        existing = self.db.query_one(
            "SELECT id FROM assets WHERE engagement_id IS ? AND target = ?",
            (engagement_id, target),
        )
        if existing is not None:
            return self.get(existing["id"])
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO assets (engagement_id, target, asset_type, criticality, owner,"
                " tags, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    engagement_id,
                    target,
                    asset_type,
                    criticality,
                    owner,
                    json.dumps(tags or []),
                    source,
                    now_utc(),
                ),
            )
        return self.get(cursor.lastrowid)

    def get(self, asset_id: int) -> Asset | None:
        row = self.db.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,))
        return self._from_row(row) if row else None

    def list(self, engagement_id: int | None = None) -> list[Asset]:
        if engagement_id is not None:
            rows = self.db.query_all(
                "SELECT * FROM assets WHERE engagement_id = ? ORDER BY id", (engagement_id,)
            )
        else:
            rows = self.db.query_all("SELECT * FROM assets ORDER BY id")
        return [self._from_row(row) for row in rows]

    @staticmethod
    def _from_row(row: sqlite3.Row) -> Asset:
        return Asset(
            id=row["id"],
            engagement_id=row["engagement_id"],
            target=row["target"],
            asset_type=row["asset_type"],
            criticality=row["criticality"],
            owner=row["owner"],
            tags=json.loads(row["tags"] or "[]"),
            source=row["source"],
            created_at=row["created_at"],
        )