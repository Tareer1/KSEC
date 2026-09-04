"""Deterministic, read-only vulnerability checks.

Every check is non-destructive: it connects and reads (TLS negotiation,
HTTP headers, banner) — it never sends exploit payloads. Targets are
already policy-gated by the caller; commands are built as argv lists.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_TIMEOUT = 12

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", re.IGNORECASE)

# Headers a security-conscious web app should set (spec: HTTP hardening).
SECURITY_HEADERS = {
    "strict-transport-security": "HTTP Strict Transport Security (HSTS)",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options (clickjacking protection)",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}

# Server banners that reveal a development / built-in HTTP stack.
DEV_SERVER_MARKERS = (
    "simplehttp",
    "python",
    "werkzeug",
    "development",
    "php/5.",
    "php/7.",
    "lighttpd",
    "cowboy",
)


@dataclass(frozen=True)
class CheckOutcome:
    check_id: str
    title: str
    severity: str  # info | low | medium | high | critical
    description: str
    recommendation: str
    evidence: str = ""
    confidence: str = "high"


@dataclass
class TargetRef:
    host: str
    scheme: str  # http | https
    port: int

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


def normalize_target(target: str, port: int | None = None) -> TargetRef:
    """Parse ``host``, ``host:port`` or ``scheme://host[:port]`` into a ref.

    Scheme defaults follow the port: 443/8443 -> https, everything else ->
    http. IPv6 literals are accepted as-is.
    """
    raw = (target or "").strip().lower()
    if not raw:
        raise ValueError("empty target")
    host: str
    scheme = ""
    try:
        parts = urlsplit(raw)
        if parts.scheme and parts.netloc:
            scheme = parts.scheme
            host = parts.hostname or ""
            if parts.port:
                port = parts.port
    except ValueError:
        host = raw
    else:
        if not (scheme and host):
            host = raw
    if host.count(":") == 1 and not _IPV4_RE.match(host) and "[" not in host:
        h, _, p = host.rpartition(":")
        if h and p.isdigit():
            host = h
            port = int(p)
    if not host:
        raise ValueError(f"invalid target {target!r}")
    if not (_IPV4_RE.match(host) or _HOST_RE.match(host) or host.startswith("[")):
        raise ValueError(f"invalid host {host!r} in target")
    if port is None:
        # Bare host defaults to HTTPS/443 (modern web default). Explicit
        # schemes use their own default; pass --port or an http:// URL for
        # plain-HTTP-only services.
        port = {"https": 443, "http": 80}.get(scheme, 443)
        scheme = scheme if scheme in ("http", "https") else "https"
    else:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError(f"invalid port {port}")
        if scheme not in ("http", "https"):
            scheme = "https" if port in (443, 8443) else "http"
    return TargetRef(host=host, scheme=scheme, port=port)


def _run(argv: list[str], timeout: int = _TIMEOUT) -> str:
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return (proc.stdout or "") + (proc.stderr or "")


# ---------------------------------------------------------------------------
# TLS version check
# ---------------------------------------------------------------------------
_TLS_VERSION_RE = re.compile(r"Protocol\s*:\s*(TLSv[\d.]+|SSLv[\d.]+)", re.IGNORECASE)
_WEAK_TLS = {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}


def check_tls_version(ref: TargetRef) -> list[CheckOutcome]:
    if ref.scheme != "https":
        return []
    out = _run(["openssl", "s_client", "-connect", f"{ref.host}:{ref.port}", "-brief"])
    match = _TLS_VERSION_RE.search(out)
    if not match:
        # -brief may not print Protocol on some openssl versions; retry full.
        out2 = _run(["openssl", "s_client", "-connect", f"{ref.host}:{ref.port}"])
        match = _TLS_VERSION_RE.search(out2)
        out = out2
    if not match:
        return []
    proto = match.group(1).lower()
    if proto not in _WEAK_TLS:
        return []
    return [
        CheckOutcome(
            check_id="tls-weak-version",
            title=f"Legacy TLS version in use ({match.group(1)})",
            severity="high",
            description=(
                f"{ref.base_url} negotiates {match.group(1)}, which is deprecated and"
                " vulnerable to known attacks (POODLE, BEAST, DROWN)."
            ),
            recommendation="Disable TLS 1.0/1.1 and require TLS 1.2 or newer.",
            evidence=f"openssl s_client -connect {ref.host}:{ref.port}\n{out[:1200]}",
        )
    ]


# ---------------------------------------------------------------------------
# HTTP header checks
# ---------------------------------------------------------------------------
def _http_headers(ref: TargetRef) -> tuple[list[str], str]:
    url = f"{ref.base_url}/"
    out = _run(["curl", "-sSI", "-m", "10", url])
    raw_lines = [ln for ln in out.splitlines() if ":" in ln]
    headers: list[str] = []
    for ln in raw_lines:
        name, _, value = ln.partition(":")
        headers.append(f"{name.strip().lower()}: {value.strip()}")
    return headers, out


def _header_value(headers: list[str], name: str) -> str:
    for h in headers:
        k, _, v = h.partition(":")
        if k == name:
            return v
    return ""


def check_http_headers(ref: TargetRef) -> list[CheckOutcome]:
    headers, raw = _http_headers(ref)
    outcomes: list[CheckOutcome] = []
    if not headers:
        return outcomes  # not an HTTP endpoint on this port

    missing = [label for name, label in SECURITY_HEADERS.items() if _header_value(headers, name) == ""]
    if missing:
        outcomes.append(
            CheckOutcome(
                check_id="http-security-headers",
                title="Missing HTTP security headers",
                severity="medium",
                description=(
                    f"{ref.base_url} does not send: {', '.join(missing)}."
                    " Missing hardening headers increase exposure to clickjacking,"
                    " MIME sniffing and content-injection attacks."
                ),
                recommendation="Set the missing headers (HSTS, CSP, X-Frame-Options,"
                " X-Content-Type-Options, Referrer-Policy).",
                evidence=raw[:1500],
                confidence="high",
            )
        )

    server = _header_value(headers, "server")
    if server:
        outcomes.append(
            CheckOutcome(
                check_id="http-server-disclosure",
                title="Web server version disclosure",
                severity="low",
                description=(
                    f"{ref.base_url} reveals its server banner: {server!r}. Version"
                    " disclosure helps attackers pick known exploits for that stack."
                ),
                recommendation="Remove or genericize the Server header"
                " (hide version details at the reverse proxy).",
                evidence=f"Server: {server}",
                confidence="high",
            )
        )

    low = server.lower()
    if any(marker in low for marker in DEV_SERVER_MARKERS):
        outcomes.append(
            CheckOutcome(
                check_id="dev-server-exposed",
                title="Development/built-in web server exposed",
                severity="medium",
                description=(
                    f"{ref.base_url} is served by {server!r}, a development or built-in"
                    " stack not hardened for production."
                ),
                recommendation="Serve the application behind a hardened production"
                " web server / reverse proxy.",
                evidence=f"Server: {server}",
                confidence="high",
            )
        )
    return outcomes


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------
def run_checks(ref: TargetRef) -> list[CheckOutcome]:
    outcomes: list[CheckOutcome] = []
    try:
        outcomes += check_tls_version(ref)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        outcomes += check_http_headers(ref)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return outcomes


CHECKS: list[dict] = [
    {
        "id": "tls-weak-version",
        "name": "Legacy TLS version",
        "description": "Negotiates TLS and flags TLS 1.0/1.1 (https only).",
        "severity_base": "high",
    },
    {
        "id": "http-security-headers",
        "name": "Missing HTTP security headers",
        "description": "Checks HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.",
        "severity_base": "medium",
    },
    {
        "id": "http-server-disclosure",
        "name": "Server banner disclosure",
        "description": "Reports Server header version disclosure.",
        "severity_base": "low",
    },
    {
        "id": "dev-server-exposed",
        "name": "Development server exposed",
        "description": "Flags development/built-in server banners (SimpleHTTP, Werkzeug, ...).",
        "severity_base": "medium",
    },
]
