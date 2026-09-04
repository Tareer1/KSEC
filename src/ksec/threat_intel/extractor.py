"""IOC extraction from scan evidence (spec: IOC extraction / auto-registration).

Extracts candidate indicators of compromise from:

* structured parse entities (hosts, addresses, hostnames, DNS records)
* raw tool output / evidence text (IPs, domains, URLs, emails, hashes)

Extraction is conservative: values are validated and normalized before they
become IOCs, and every candidate carries a confidence derived from its
source. Structured entity fields are high confidence; raw-text matches are
low/medium confidence.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from ksec.normalization.service import normalize_domain, normalize_ip
from ksec.threat_intel.service import normalize_ioc_value

# Raw-text patterns (validated before use).
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE
)
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}\b", re.IGNORECASE)
_HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b")

# Reserved/private TLDs and domains that are never real IOCs (RFC 2606).
_RESERVED_TLDS = {"invalid", "test", "local", "localhost", "example"}
_RESERVED_DOMAINS = {"example.com", "example.net", "example.org", "example.edu"}


@dataclass(frozen=True)
class IocCandidate:
    type: str
    value: str
    normalized_value: str
    confidence: str  # low | medium | high
    origin: str      # e.g. "entity:host.addresses", "text:ipv4"


class IocExtractor:
    """Extract IOC candidates from entities and raw text."""

    def extract_entities(self, entities: list[dict]) -> list[IocCandidate]:
        """Structured parser entities -> high-confidence candidates."""
        candidates: list[IocCandidate] = []
        for entity in entities or []:
            kind = entity.get("type")
            if kind == "host":
                for address in entity.get("addresses", []):
                    candidate = self._ip_candidate(str(address), "entity:host.addresses")
                    if candidate:
                        candidates.append(candidate)
                for hostname in entity.get("hostnames", []):
                    candidate = self._domain_candidate(
                        str(hostname), "entity:host.hostnames", confidence="high"
                    )
                    if candidate:
                        candidates.append(candidate)
            elif kind == "dns_record":
                name = self._domain_candidate(
                    str(entity.get("name", "")), "entity:dns_record.name", confidence="high"
                )
                if name:
                    candidates.append(name)
                value = str(entity.get("value", ""))
                ip = self._ip_candidate(value, "entity:dns_record.value")
                if ip:
                    candidates.append(ip)
                else:
                    domain = self._domain_candidate(
                        value, "entity:dns_record.value", confidence="medium"
                    )
                    if domain:
                        candidates.append(domain)
            elif kind == "http_header":
                value = str(entity.get("value", ""))
                candidates.extend(self._from_text(value, origin="entity:http_header"))
        return _dedupe(candidates)

    def extract_text(self, text: str) -> list[IocCandidate]:
        """Raw output/evidence text -> low/medium confidence candidates."""
        return _dedupe(self._from_text(text or "", origin="text"))

    def _from_text(self, text: str, *, origin: str) -> list[IocCandidate]:
        candidates: list[IocCandidate] = []
        for match in _URL_RE.finditer(text):
            candidate = self._url_candidate(match.group(0), origin)
            if candidate:
                candidates.append(candidate)
        for match in _EMAIL_RE.finditer(text):
            email = match.group(0).lower()
            if not _url_covers(text, match.start(), match.end()):
                candidates.append(
                    IocCandidate(
                        type="EMAIL",
                        value=email,
                        normalized_value=normalize_ioc_value(email, "EMAIL"),
                        confidence="medium",
                        origin=origin,
                    )
                )
        for match in _IPV4_RE.finditer(text):
            ip = self._validated_ip(match.group(0))
            if ip and not _covered_by_other(text, match.start(), match.end()):
                candidates.append(
                    IocCandidate(
                        type="IP",
                        value=ip,
                        normalized_value=ip,
                        confidence="low",
                        origin=origin,
                    )
                )
        for match in _DOMAIN_RE.finditer(text):
            domain = match.group(0).lower().rstrip(".")
            if domain in _RESERVED_DOMAINS or not self._valid_domain(domain):
                continue
            if not _covered_by_other(text, match.start(), match.end()):
                candidates.append(
                    IocCandidate(
                        type="DOMAIN",
                        value=domain,
                        normalized_value=normalize_domain(domain) or domain,
                        confidence="medium" if origin.startswith("entity") else "low",
                        origin=origin,
                    )
                )
        for match in _HASH_RE.finditer(text):
            if not _covered_by_other(text, match.start(), match.end()):
                candidates.append(
                    IocCandidate(
                        type="HASH",
                        value=match.group(0),
                        normalized_value=match.group(0),
                        confidence="medium",
                        origin=origin,
                    )
                )
        return candidates

    # -- helpers ----------------------------------------------------------

    def _ip_candidate(self, value: str, origin: str) -> IocCandidate | None:
        ip = self._validated_ip(value)
        if not ip:
            return None
        return IocCandidate(
            type="IP",
            value=ip,
            normalized_value=ip,
            confidence="high",
            origin=origin,
        )

    def _domain_candidate(
        self, value: str, origin: str, *, confidence: str
    ) -> IocCandidate | None:
        value = value.strip().lower().rstrip(".")
        if not self._valid_domain(value):
            return None
        return IocCandidate(
            type="DOMAIN",
            value=value,
            normalized_value=normalize_domain(value) or value,
            confidence=confidence,
            origin=origin,
        )

    def _url_candidate(self, value: str, origin: str) -> IocCandidate | None:
        value = value.strip().rstrip(".,;:)]}")
        if not value.lower().startswith(("http://", "https://")):
            return None
        return IocCandidate(
            type="URL",
            value=value,
            normalized_value=normalize_ioc_value(value, "URL"),
            confidence="medium",
            origin=origin,
        )

    @staticmethod
    def _validated_ip(value: str) -> str | None:
        """Return a canonical IPv4/IPv6 string, or None if invalid."""
        value = value.strip()
        # Strip a trailing :port from "1.2.3.4:8080" in raw text.
        if ":" in value and value.count(":") == 1:
            head, _, tail = value.rpartition(":")
            if tail.isdigit() and head.count(".") == 3:
                value = head
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return None
        return str(parsed)

    @staticmethod
    def _valid_domain(domain: str) -> bool:
        if len(domain) < 4 or len(domain) > 253 or not domain:
            return False
        labels = domain.split(".")
        if len(labels) < 2:
            return False
        tld = labels[-1]
        if tld.isdigit() or tld in _RESERVED_TLDS or len(tld) < 2:
            return False
        for label in labels:
            if not label or len(label) > 63:
                return False
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label):
                return False
        return True


def _dedupe(candidates: list[IocCandidate]) -> list[IocCandidate]:
    """Drop duplicate (type, normalized_value), keeping the highest confidence."""
    best: dict[tuple[str, str], IocCandidate] = {}
    rank = {"low": 0, "medium": 1, "high": 2}
    for candidate in candidates:
        key = (candidate.type, candidate.normalized_value)
        existing = best.get(key)
        if existing is None or rank[candidate.confidence] > rank[existing.confidence]:
            best[key] = candidate
    return sorted(best.values(), key=lambda c: (c.type, c.value))


def _url_covers(text: str, start: int, end: int) -> bool:
    """True when the [start,end) span sits inside an earlier URL match."""
    for match in _URL_RE.finditer(text):
        if match.start() <= start and match.end() >= end:
            return True
    return False


def _covered_by_other(text: str, start: int, end: int) -> bool:
    """True when the span overlaps a URL (so the URL is the canonical IOC)."""
    for match in _URL_RE.finditer(text):
        if match.start() < end and match.end() > start:
            return True
    return False