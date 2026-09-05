"""Parse ``dnsenum --enum`` text output into DNS record entities.

dnsenum prints records like ``www.example.com. 300 IN A 1.2.3.4`` plus
section headers (``Name Servers:``, ``Mail (MX) Servers:``).
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "PTR")
_RECORD_RE = re.compile(r"^(\S+)\s+\d+\s+IN\s+([A-Z]{1,6})\s+(.+)$")


class DnsenumParser(OutputParser):
    name = "dnsenum"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            match = _RECORD_RE.match(line.strip())
            if not match or match.group(2) not in _RECORD_TYPES:
                continue
            name = match.group(1).rstrip(".")
            value = match.group(3).strip().rstrip(".")
            if value.endswith((" (MX)", " (NS)", " (SOA)")):
                value = value.rsplit(" ", 1)[0]
            entities.append(
                {
                    "type": "dns_record",
                    "name": name,
                    "record_type": match.group(2),
                    "value": value,
                }
            )
        return ParsedResult(tool="dnsenum", entities=entities, raw=output, parsed_at=now_utc())