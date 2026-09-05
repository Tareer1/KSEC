"""Parse ``onesixtyone`` output into responding-SNMP host entities.

Lines look like ``192.168.1.10 [public] Linux test 5.4.0`` (responder with
a valid community string).
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_RESP_RE = re.compile(r"^([\d.]+)\s+\[(\S+)\]\s*(.*)$")


class OnesixyoneParser(OutputParser):
    name = "onesixtyone"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            match = _RESP_RE.match(line.strip())
            if not match:
                continue
            entities.append(
                {
                    "type": "snmp_host",
                    "ip": match.group(1),
                    "community": match.group(2),
                    "description": match.group(3).strip(),
                }
            )
        return ParsedResult(tool="onesixtyone", entities=entities, raw=output, parsed_at=now_utc())