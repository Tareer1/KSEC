"""Parse ``aircrack-ng`` text output into wifi_key entities.

Recognizes successful key recovery (``KEY FOUND! [ ... ]``) and network
lines from the handshake table.
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[\s*([^\]]+?)\s*\]")
_NET_RE = re.compile(
    r"^\s*\[\s*\d+\]\s+([0-9A-Fa-f:]{17})\s+\S+\s+(\d+)\s+\S+\s+\S+\s+(\S+)"
)


class AircrackNgParser(OutputParser):
    name = "aircrack_ng"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        key = _KEY_FOUND_RE.search(output)
        if key:
            entities.append(
                {
                    "type": "wifi_key",
                    "key": key.group(1).strip(),
                    "status": "recovered",
                }
            )
        for line in output.splitlines():
            match = _NET_RE.match(line)
            if match:
                entities.append(
                    {
                        "type": "wifi_ap",
                        "bssid": match.group(1).lower(),
                        "channel": int(match.group(2)),
                        "encryption": match.group(3),
                    }
                )
        return ParsedResult(
            tool="aircrack-ng", entities=entities, raw=output, parsed_at=now_utc()
        )