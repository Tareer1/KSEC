"""Parse nikto text output into vulnerability-finding entities."""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_OSVDB_RE = re.compile(r"OSVDB-(\d+)")
_FINDING_RE = re.compile(r"^\+\s+(.+)$")


class NiktoParser(OutputParser):
    name = "nikto"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            m = _FINDING_RE.match(line.strip())
            if not m:
                continue
            text = m.group(1)
            osvdb = _OSVDB_RE.search(text)
            entities.append(
                {
                    "type": "nikto_finding",
                    "osvdb": osvdb.group(1) if osvdb else "",
                    "message": text[:500],
                }
            )
        return ParsedResult(tool="nikto", entities=entities, raw=output, parsed_at=now_utc())
