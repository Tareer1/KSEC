"""Parse ``searchsploit --json`` output into exploit entities.

Each match becomes an ``exploit`` entity carrying the Exploit-DB id, title,
type, platform and any CVE codes — so findings can reference public exploit
ids instead of guessing.
"""
from __future__ import annotations

import json

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult


class SearchsploitParser(OutputParser):
    name = "searchsploit"
    formats = ("json",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return ParsedResult(tool="searchsploit", entities=[], raw=output, parsed_at=now_utc())
        for result in data.get("RESULTS_EXPLOIT") or []:
            entities.append(
                {
                    "type": "exploit",
                    "edb_id": result.get("EDB-ID", ""),
                    "title": result.get("Title", ""),
                    "exploit_type": result.get("Type", ""),
                    "platform": result.get("Platform", ""),
                    "cve": result.get("Codes", "") or "",
                    "path": result.get("Path", ""),
                    "verified": result.get("Verified", "0") == "1",
                    "date_published": result.get("Date_Published", ""),
                }
            )
        return ParsedResult(tool="searchsploit", entities=entities, raw=output, parsed_at=now_utc())