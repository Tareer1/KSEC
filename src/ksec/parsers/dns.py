"""Parse ``dig`` output into DNS records."""
from __future__ import annotations

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR")


class DigParser(OutputParser):
    name = "dig"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[3] in _RECORD_TYPES:
                entities.append(
                    {
                        "type": "dns_record",
                        "name": parts[0].rstrip("."),
                        "record_type": parts[3],
                        "ttl": parts[1],
                        "value": " ".join(parts[4:]).strip('"'),
                    }
                )
        return ParsedResult(tool="dig", entities=entities, raw=output, parsed_at=now_utc())