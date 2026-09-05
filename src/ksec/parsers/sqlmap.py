"""Parse ``sqlmap`` text output into SQL-injection entities.

sqlmap reports confirmed injectable parameters with lines like
``Parameter: id (GET)`` plus the injection type (boolean-based blind, error
based, UNION query...). We only emit entities when sqlmap reports an
injection is exploitable — never from its banner/progress noise.
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_PARAM_RE = re.compile(r"Parameter:\s+(\S+)\s+\((\w+)\)")
_TYPE_RE = re.compile(r"Type:\s+([A-Za-z][\w\s-]*)")
_TITLE_RE = re.compile(r"Title:\s+(.+)")
_IS_VULN = ("sqlmap identified", "the back-end DBMS", "Parameter:", "is vulnerable")


class SqlmapParser(OutputParser):
    name = "sqlmap"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        if not any(marker in output for marker in _IS_VULN):
            return ParsedResult(tool="sqlmap", entities=[], raw=output, parsed_at=now_utc())
        entities: list[dict] = []
        current: dict | None = None

        def flush() -> None:
            nonlocal current
            if current and (current.get("title") or current.get("injection_type")):
                entities.append(current)
            current = None

        for line in output.splitlines():
            m = _PARAM_RE.search(line)
            if m:
                flush()
                current = {
                    "type": "sqli_finding",
                    "parameter": m.group(1),
                    "method": m.group(2),
                    "injection_type": "",
                    "title": "",
                }
                continue
            t = _TYPE_RE.search(line)
            if t and current is not None:
                current["injection_type"] = t.group(1).strip()
                continue
            ti = _TITLE_RE.search(line)
            if ti and current is not None:
                current["title"] = ti.group(1).strip()
        flush()
        return ParsedResult(tool="sqlmap", entities=entities, raw=output, parsed_at=now_utc())