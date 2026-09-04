"""Plugin parser: parse ``curl -sSI`` header output into entities."""
from __future__ import annotations

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult


class HttpHeadersParser(OutputParser):
    name = "http_headers"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        headers: list[dict] = []
        for line in output.splitlines():
            if ":" in line and not line.startswith((" ", "\t")):
                key, _, value = line.partition(":")
                headers.append({"name": key.strip().lower(), "value": value.strip()})
        entities = [
            {
                "type": "http_header",
                "name": h["name"],
                "value": h["value"],
            }
            for h in headers
        ]
        return ParsedResult(tool="curl", entities=entities, raw=output, parsed_at=now_utc())