"""SIEM log-line parsing (spec: real SOC intake).

Parsers for the record formats a small SOC actually sees on the wire:

* ``JSONL`` — one JSON event object per line (modern SIEM / Zeek JSON, or any
  tool emitting ``{"event_type": ...}`` lines)
* ``SYSLOG`` — RFC3164-style ``<PRI>MMM dd HH:MM:SS host tag[pid]: message``
  (also accepts a plain ``timestamp host tag: message`` form)
* ``KEYVALUE`` — auditd-style ``key=value key=value ...`` records

Every parsed line is converted into the raw-event dict the SOC normalizer
expects. Lines without a real event id get a deterministic id derived from
the line content, so intake is idempotent (re-sending a burst after a
restart dedupes cleanly).
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

# -- event-type / severity guessing ------------------------------------------

_AUTH_FAIL = re.compile(
    r"failed (password|publickey)|authentication failure|invalid user|"
    r"authentication failed|bad password|login incorrect",
    re.IGNORECASE,
)
_AUTH_OK = re.compile(
    r"accepted (password|publickey)|session opened|login (successful|session)|"
    r"new session|successful login",
    re.IGNORECASE,
)
_PORT_SCAN = re.compile(r"port ?scan|tcp scan|syn scan|nmap|scan detected", re.IGNORECASE)
_WEB = re.compile(r"GET /|POST /|HTTP/1", re.IGNORECASE)
_PERSISTENCE = re.compile(
    r"cron|systemd.*(start|install)|added to crontab|\.bashrc|authorized_keys",
    re.IGNORECASE,
)


def guess_event_type(message: str) -> str:
    """Best-effort event_type from message keywords (deterministic)."""
    if not message:
        return "unknown"
    if _AUTH_FAIL.search(message):
        return "auth_failure"
    if _PORT_SCAN.search(message):
        return "port_scan"
    if _AUTH_OK.search(message):
        return "login"
    if _PERSISTENCE.search(message):
        return "persistence"
    if _WEB.search(message):
        return "web_request"
    return "unknown"


def guess_severity(message: str) -> str | None:
    """Map common syslog severity words; None keeps the normalizer default."""
    text = message.lower()
    if "critical" in text or "emergency" in text:
        return "critical"
    if "error" in text or "failed" in text or "failure" in text:
        return "medium"
    if "warning" in text or "warn" in text:
        return "low"
    return None


def deterministic_event_id(parts: list[str]) -> str:
    """Stable event id so re-sent lines dedupe (idempotent intake)."""
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace"))
    return digest.hexdigest()[:20]


_ISO_TS = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
_RFC3164_TS = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", re.IGNORECASE
)
_RFC3164_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

_KV_PAIR = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|(\S+))')


def parse_json_line(line: str, source: str) -> dict | None:
    """Parse a JSONL record into a raw event dict."""
    text = line.strip()
    if not text:
        return None
    try:
        raw = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    raw.setdefault("source", source)
    if not raw.get("event_id") and not raw.get("id"):
        parts = [raw.get("event_type", ""), raw.get("timestamp") or raw.get("occurred_at") or "", text]
        raw["event_id"] = deterministic_event_id(parts)
    return raw


def parse_syslog_line(line: str, source: str) -> dict | None:
    """Parse an RFC3164-style syslog line (with or without <PRI>)."""
    text = line.rstrip("\n")
    if not text.strip():
        return None
    body = text
    # Strip RFC3164 <PRI> prefix.
    pri = re.match(r"^<\d{1,3}>(.*)$", body)
    if pri:
        body = pri.group(1)

    occurred_at = ""
    host = ""
    tag = ""
    message = body
    rest = body

    # RFC3164 timestamp "MMM dd HH:MM:SS" (year = current year).
    m = _RFC3164_TS.match(rest)
    if m:
        occurred_at = _rfc3164_to_iso(m.group(1))
        rest = rest[m.end():].lstrip()
    else:
        # ISO-ish timestamp prefix.
        m = _ISO_TS.match(rest)
        if m:
            occurred_at = rest[m.start():m.end()].replace(" ", "T")
            rest = rest[m.end():]
            if rest.startswith(("Z", "z")):
                occurred_at += "+00:00"
                rest = rest[1:]
            rest = rest.lstrip()

    if not rest:
        return None
    parts = rest.split(None, 1)
    host = parts[0]
    rest = parts[1] if len(parts) > 1 else ""

    # Tag: sshd[1234]: message | sshd: message
    m = re.match(r"^([A-Za-z0-9_./-]+)(?:\[\d+\])?:\s?(.*)$", rest)
    if m:
        tag = m.group(1)
        message = m.group(2) or rest
    else:
        message = rest

    event_type = guess_event_type(message)
    raw = {
        "source": source,
        "host": host,
        "event_type": event_type,
        "event_id": deterministic_event_id([host, tag, occurred_at or "", message]),
        "details": {"message": message},
    }
    if tag:
        raw["details"]["tag"] = tag
    if occurred_at:
        raw["occurred_at"] = occurred_at
    severity = guess_severity(message)
    if severity:
        raw["severity"] = severity
    return raw


def parse_keyvalue_line(line: str, source: str) -> dict | None:
    """Parse an auditd-style ``type=... msg=... key=value ...`` record."""
    text = line.strip()
    if not text:
        return None
    if "\x1e" in text:  # auditd record separator handling (best effort)
        text = text.split("\x1e")[-1]
    record_type = ""
    if text.startswith("type="):
        m = re.match(r"^type=([A-Za-z0-9_]+)", text)
        if m:
            record_type = m.group(1).lower()
        text = text.split("msg=", 1)[-1] if "msg=" in text else text
    pairs = _KV_PAIR.findall(text)
    if not pairs:
        return None
    kv = {k: (v1 or v2) for k, v1, v2 in pairs}
    msg = kv.pop("msg", kv.pop("message", ""))
    host = kv.pop("host", kv.pop("hostname", ""))
    pid = kv.pop("pid", "")
    event_type = kv.pop("event_type", kv.pop("type", record_type or ""))
    if not event_type:
        event_type = guess_event_type(msg)
    occurred_at = kv.pop(
        "occurred_at", kv.pop("timestamp", kv.pop("time", ""))
    )
    raw = {
        "source": source,
        "event_type": event_type,
        "event_id": kv.pop("event_id", "") or deterministic_event_id(
            [host, event_type, occurred_at, msg or text]
        ),
        "details": dict(kv),
    }
    if host:
        raw["host"] = host
    if msg:
        raw["details"]["message"] = msg
    if pid:
        raw["details"]["pid"] = pid
    if occurred_at:
        raw["occurred_at"] = occurred_at
    sev = kv.get("severity") or guess_severity(msg)
    if sev:
        raw["severity"] = sev
    return raw


def parse_line(line: str, source: str = "siem") -> dict | None:
    """Parse one log line in any supported format. Returns a raw event or None.

    Dispatcher order: JSONL, then syslog (timestamp/host style), then
    key=value. Auditd records start with ``type=`` and would otherwise be
    mis-read as a syslog line, so they are routed to the key=value parser
    first.
    """
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.startswith("type="):
        parsed = parse_keyvalue_line(stripped, source)
        if parsed is not None:
            return parsed
    parsed = parse_json_line(stripped, source)
    if parsed is not None:
        return parsed
    parsed = parse_syslog_line(line, source)
    if parsed is not None:
        return parsed
    return parse_keyvalue_line(line, source)


def _rfc3164_to_iso(timestamp: str) -> str:
    """Convert 'MMM dd HH:MM:SS' to ISO-8601 UTC (current year)."""
    try:
        parts = timestamp.split()
        month = _RFC3164_MONTHS.get(parts[0][:3].lower(), 1)
        day = int(parts[1])
        now = datetime.now(timezone.utc)
        parsed = datetime(now.year, month, day, *[int(p) for p in parts[2].split(":")])
        return parsed.replace(tzinfo=timezone.utc).isoformat()
    except (ValueError, IndexError):
        return ""
