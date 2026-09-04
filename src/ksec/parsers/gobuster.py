"""Parse gobuster dir output into directory entities."""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_LINE_RE = re.compile(
    r"^(/\S*?)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\](?:\s*\[-->\s*(\S+)\])?$"
)


class GobusterParser(OutputParser):
    name = "gobuster"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            m = _LINE_RE.match(line.strip())
            if not m:
                continue
            entities.append(
                {
                    "type": "http_directory",
                    "path": m.group(1),
                    "status": int(m.group(2)),
                    "size": int(m.group(3)),
                    "redirect": m.group(4) or "",
                }
            )
        return ParsedResult(tool="gobuster", entities=entities, raw=output, parsed_at=now_utc())
