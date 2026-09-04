"""Parse ``dnsrecon`` text output into DNS record entities.

Handles both output generations:

* dnsrecon >= 1.6 logs every record to stderr as
  ``<timestamp> INFO <tab> TYPE name value ...``
* legacy builds print ``[*] TYPE name value ...``

Emits the same ``dns_record`` shape as the dig parser so downstream asset
correlation and IOC extraction work unchanged.
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "PTR", "SRV", "NAPTR")
_INFO_RE = re.compile(r"\bINFO\s+([A-Z]{1,6})\s+(\S+)(?:\s+(.*))?$")
_LEGACY_RE = re.compile(r"\[\*\]\s+([A-Z]+)\s+(\S+)(?:\s+(.*))?$")


class DnsreconParser(OutputParser):
    name = "dnsrecon"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for raw_line in output.splitlines():
            line = raw_line.replace("\t", " ")
            record = self._extract_record(line)
            if record is None:
                continue
            record_type, name, value = record
            entities.append(
                {
                    "type": "dns_record",
                    "name": name.rstrip("."),
                    "record_type": record_type,
                    "value": value.strip().rstrip("."),
                }
            )
        return ParsedResult(tool="dnsrecon", entities=entities, raw=output, parsed_at=now_utc())

    @staticmethod
    def _extract_record(line: str) -> tuple[str, str, str] | None:
        for pattern in (_INFO_RE, _LEGACY_RE):
            match = pattern.search(line)
            if match and match.group(1) in _RECORD_TYPES:
                return (match.group(1), match.group(2), (match.group(3) or "").strip())
        # Minimal builds may print bare 'TYPE name value' lines.
        tokens = [t for t in line.split(" ") if t]
        if len(tokens) >= 3 and tokens[0] in _RECORD_TYPES:
            return (tokens[0], tokens[1], " ".join(tokens[2:]))
        return None
