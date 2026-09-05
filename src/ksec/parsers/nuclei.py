"""Parse ``nuclei -jsonl`` output into CVE/vulnerability entities.

Each JSON line is one template match carrying the template id, info
(severity, name, classification with CVE/EDB ids) and matched-at target.
Only well-formed matches become entities — the engine's status lines
(``[INF]``) are JSON lines too but lack the ``template-id`` field and are
skipped.
"""
from __future__ import annotations

import json

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult


class NucleiParser(OutputParser):
    name = "nuclei"
    formats = ("jsonl",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "template-id" not in data:
                continue  # engine log line, not a match
            info = data.get("info") or {}
            classification = info.get("classification") or {}
            cve = classification.get("cve-id") or ""
            if isinstance(cve, list):
                cve = ",".join(cve)
            edb = classification.get("exploit-db") or ""
            if isinstance(edb, list):
                edb = ",".join(str(e) for e in edb)
            entities.append(
                {
                    "type": "cve_finding",
                    "template_id": data.get("template-id", ""),
                    "title": info.get("name", ""),
                    "severity": info.get("severity", "unknown"),
                    "matched_at": data.get("matched-at", ""),
                    "cve": cve,
                    "edb_id": edb,
                    "tags": info.get("tags", []),
                    "matcher_name": data.get("matcher-name", ""),
                }
            )
        return ParsedResult(tool="nuclei", entities=entities, raw=output, parsed_at=now_utc())