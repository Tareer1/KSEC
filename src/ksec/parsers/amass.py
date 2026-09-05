"""Parse ``amass enum`` text output into subdomain DNS entities.

amass streams discovered names to stdout (one per line, optionally with an
``(FQDN)`` marker or ``[DNS]`` prefixes); status/log lines are ignored.
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_HOST_RE = re.compile(r"^[a-zA-Z0-9*_-]+(\.[a-zA-Z0-9_-]+)+\.?$")


class AmassParser(OutputParser):
    name = "amass"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        seen: set[str] = set()
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            # Strip common decorations: '[DNS] name', 'name (FQDN)'.
            if line.startswith("["):
                line = line.split("]", 1)[-1].strip()
            line = re.sub(r"\s*\(FQDN\)\s*$", "", line)
            if not _HOST_RE.match(line):
                continue
            name = line.rstrip(".").lower()
            if name in seen:
                continue
            seen.add(name)
            entities.append(
                {
                    "type": "dns_record",
                    "name": name,
                    "record_type": "A",
                    "value": name,
                }
            )
        return ParsedResult(tool="amass", entities=entities, raw=output, parsed_at=now_utc())