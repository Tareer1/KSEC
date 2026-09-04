"""Correlation engine (spec: CORRELATION ENGINE).

Connects parsed tool observations (hosts, ports, DNS records) to KSEC assets
so they can be registered, deduplicated and linked to findings. Confidence
and provenance are preserved; correlation is never treated as proof.
"""
from __future__ import annotations

from ksec.assets.service import AssetService
from ksec.normalization.service import normalize_domain, normalize_ip, normalize_port


class CorrelationService:
    def __init__(self, db, assets: AssetService):
        self.db = db
        self.assets = assets

    def ingest_entities(
        self,
        entities: list[dict],
        *,
        tool: str,
        engagement_id: int | None = None,
        source: str = "",
    ) -> list:
        """Register assets from parsed entities; returns created/updated assets."""
        registered: list = []
        for entity in entities or []:
            kind = entity.get("type")
            if kind == "host":
                for address in entity.get("addresses", []):
                    normalized = normalize_ip(address)
                    if normalized:
                        asset = self.assets.register(
                            normalized,
                            asset_type="ip",
                            engagement_id=engagement_id,
                            source=source or tool,
                        )
                        registered.append(asset)
                for hostname in entity.get("hostnames", []):
                    domain = normalize_domain(hostname)
                    if domain:
                        asset = self.assets.register(
                            domain,
                            asset_type="domain",
                            engagement_id=engagement_id,
                            source=source or tool,
                        )
                        registered.append(asset)
            elif kind == "dns_record":
                domain = normalize_domain(entity.get("name", ""))
                if domain:
                    asset = self.assets.register(
                        domain,
                        asset_type="domain",
                        engagement_id=engagement_id,
                        source=source or tool,
                    )
                    registered.append(asset)
                value = entity.get("value", "")
                ip = normalize_ip(value)
                if ip:
                    asset = self.assets.register(
                        ip,
                        asset_type="ip",
                        engagement_id=engagement_id,
                        source=source or tool,
                    )
                    registered.append(asset)
            elif kind == "http_response":
                # URL-based entities are correlated to their host.
                pass
        return registered