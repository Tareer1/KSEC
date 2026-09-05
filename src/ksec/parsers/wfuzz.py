"""Parse ``wfuzz`` text table output into web path entities.

wfuzz's default table looks like::

    000000002:   200        12 L      34 W      123 Ch   "admin"
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_ROW_RE = re.compile(
    r"^(\d+):\s+(\d{3})\s+(\d+)\s+L\s+(\d+)\s+W\s+(\d+)\s+Ch\s+\"?(.*?)\"?\s*$"
)


class WfuzzParser(OutputParser):
    name = "wfuzz"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            match = _ROW_RE.match(line.strip())
            if not match:
                continue
            entities.append(
                {
                    "type": "web_tech",
                    "url": match.group(6),
                    "status": int(match.group(2)),
                    "length": int(match.group(5)),
                    "words": int(match.group(4)),
                    "lines": int(match.group(3)),
                }
            )
        return ParsedResult(tool="wfuzz", entities=entities, raw=output, parsed_at=now_utc())