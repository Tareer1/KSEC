"""Normalization engine (spec: NORMALIZATION ENGINE).

Different tools describe the same object differently; normalization maps
them onto one canonical representation so correlation and deduplication work.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def normalize_ip(value: str) -> str | None:
    """Return the canonical string for a valid IP address, else None."""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def normalize_cidr(value: str) -> str | None:
    value = value.strip()
    if "/" not in value:
        return None
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def normalize_domain(value: str) -> str | None:
    domain = value.strip().rstrip(".").lower()
    if _DOMAIN_RE.fullmatch(domain):
        return domain
    return None


def normalize_port(value) -> int | None:
    try:
        port = int(value)
        return port if 1 <= port <= 65535 else None
    except (TypeError, ValueError):
        return None


def normalize_target(value: str) -> tuple[str | None, str]:
    """Return (normalized, asset_type) for a target string."""
    value = value.strip()
    ip = normalize_ip(value)
    if ip:
        return ip, "ip"
    cidr = normalize_cidr(value)
    if cidr:
        return cidr, "cidr"
    if value.lower().startswith(("http://", "https://")):
        host = urlparse(value).hostname
        if host:
            return host.lower(), "url"
    domain = normalize_domain(value)
    if domain:
        return domain, "domain"
    return None, "host"