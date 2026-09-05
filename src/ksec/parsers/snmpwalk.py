"""Parse ``snmpwalk -On`` output into OID/value entities."""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_OID_RE = re.compile(r"^([\d.]+)\s*=\s*(.+)$")


class SnmpwalkParser(OutputParser):
    name = "snmpwalk"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            match = _OID_RE.match(line.strip())
            if not match:
                continue
            value = match.group(2).strip()
            # Strip type prefix like 'STRING: ' or 'INTEGER: '
            if ":" in value:
                value = value.split(":", 1)[1].strip().strip('"')
            entities.append(
                {"type": "snmp_data", "oid": match.group(1), "value": value}
            )
        return ParsedResult(tool="snmpwalk", entities=entities, raw=output, parsed_at=now_utc())