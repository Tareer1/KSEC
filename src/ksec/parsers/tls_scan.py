"""Parse sslscan text output into TLS protocol / cipher entities."""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_PROTO_RE = re.compile(r"^\s*(SSLv\d|TLSv[\d.]+)\s+(enabled|disabled)\s*$", re.IGNORECASE)
_CIPHER_RE = re.compile(
    r"^\s*(Accepted|Rejected)\s+(SSLv\d|TLSv[\d.]+)\s+\d+\s+bits\s+([A-Z0-9\-]+)",
    re.IGNORECASE,
)


class TlsScanParser(OutputParser):
    name = "tls_scan"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            m = _CIPHER_RE.match(line)
            if m:
                entities.append(
                    {
                        "type": "tls_cipher",
                        "protocol": m.group(2).upper(),
                        "cipher": m.group(3),
                        "status": m.group(1).lower(),
                    }
                )
                continue
            m = _PROTO_RE.match(line)
            if m and m.group(2).lower() == "enabled":
                entities.append(
                    {
                        "type": "tls_protocol",
                        "protocol": m.group(1).upper(),
                        "status": "enabled",
                    }
                )
        return ParsedResult(tool="sslscan", entities=entities, raw=output, parsed_at=now_utc())
