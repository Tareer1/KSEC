"""Parse ``hydra`` text output into authentication findings.

Only lines reporting a confirmed login (host + login + password) become
entities; progress/statistics lines are ignored.
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_SUCCESS_RE = re.compile(
    r"\[\d+\]\[[^\]]+\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)"
)
_META_RE = re.compile(r"\[\d+\]\[(\w+)\]\s+host:\s+(\S+)")


class HydraParser(OutputParser):
    name = "hydra"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            m = _SUCCESS_RE.search(line)
            if not m:
                continue
            service = ""
            meta = _META_RE.search(line)
            if meta:
                service = meta.group(1)
            entities.append(
                {
                    "type": "auth_finding",
                    "host": m.group(1),
                    "service": service,
                    "login": m.group(2),
                    "password": m.group(3),
                }
            )
        return ParsedResult(tool="hydra", entities=entities, raw=output, parsed_at=now_utc())
