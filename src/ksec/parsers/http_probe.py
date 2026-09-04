"""Parse ``curl -w`` probe output into HTTP response entities."""
from __future__ import annotations

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult


class HttpProbeParser(OutputParser):
    name = "http_probe"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 1 and parts[0].isdigit():
                entities.append(
                    {
                        "type": "http_response",
                        "status_code": int(parts[0]),
                        "content_type": parts[1] if len(parts) > 1 else "",
                    }
                )
        return ParsedResult(tool="curl", entities=entities, raw=output, parsed_at=now_utc())