"""Parse ``whois`` text output into domain registration entities."""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_KNOWN_KEYS = (
    "domain name", "registrar", "creation date", "updated date", "registry expiry date",
    "registrant organization", "registrant country", "registrant state",
    "name server", "status",
)
_KEY_RE = re.compile(r"^\s*(.+?):\s*(.*)$", re.IGNORECASE)


class WhoisParser(OutputParser):
    name = "whois"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        fields: dict[str, list[str]] = {}
        for line in output.splitlines():
            match = _KEY_RE.match(line)
            if not match:
                continue
            key = match.group(1).strip().lower()
            value = match.group(2).strip()
            if key in _KNOWN_KEYS and value:
                fields.setdefault(key, []).append(value)
        entity: dict = {"type": "domain_info"}
        if "domain name" in fields:
            entity["domain"] = fields["domain name"][0].lower()
        if "registrar" in fields:
            entity["registrar"] = fields["registrar"][0]
        if "creation date" in fields:
            entity["created"] = fields["creation date"][0]
        if "registrant organization" in fields:
            entity["registrant"] = fields["registrant organization"][0]
        if "registrant country" in fields:
            entity["country"] = fields["registrant country"][0]
        if "name server" in fields:
            entity["name_servers"] = [ns.lower() for ns in fields["name server"]]
        entities = [entity] if entity.get("domain") or entity.get("registrar") else []
        return ParsedResult(tool="whois", entities=entities, raw=output, parsed_at=now_utc())