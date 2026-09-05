"""Parse ``traceroute`` text output into hop entities."""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_HOP_RE = re.compile(r"^\s*(\d+)\s+(\S+)(?:\s+\(([\d.]+)\))?\s+([\d.*]+)\s+ms")


class TracerouteParser(OutputParser):
    name = "traceroute"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            match = _HOP_RE.match(line)
            if not match:
                continue
            hop = int(match.group(1))
            host = match.group(2).rstrip("()")
            ip = match.group(3) or (host if re.match(r"^[\d.]+$", host) else "")
            entities.append(
                {
                    "type": "network_path",
                    "hop": hop,
                    "host": host if host != "*" else "",
                    "ip": ip,
                }
            )
        return ParsedResult(tool="traceroute", entities=entities, raw=output, parsed_at=now_utc())