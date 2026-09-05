"""Parse ``ffuf -of json`` output into discovered web path entities."""
from __future__ import annotations

import json

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult


class FfufParser(OutputParser):
    name = "ffuf"
    formats = ("json",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return ParsedResult(tool="ffuf", entities=[], raw=output, parsed_at=now_utc())
        for result in data.get("results") or []:
            entities.append(
                {
                    "type": "web_tech",
                    "url": result.get("url", ""),
                    "status": result.get("status"),
                    "length": result.get("length"),
                    "words": result.get("words"),
                }
            )
        return ParsedResult(tool="ffuf", entities=entities, raw=output, parsed_at=now_utc())