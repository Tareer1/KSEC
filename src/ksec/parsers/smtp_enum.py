"""Parse ``smtp-user-enum`` output into user existence entities.

Lines look like ``192.168.1.10: root exists`` / ``admin does not exist``
(with ``[+]`` / ``[-]`` prefixes in verbose modes).
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_EXISTS_RE = re.compile(r"^(\S+):\s+(\S+)\s+(exists|does not exist)\s*$")


class SmtpUserEnumParser(OutputParser):
    name = "smtp_enum"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for line in output.splitlines():
            stripped = line.strip().lstrip("+- ")
            match = _EXISTS_RE.match(stripped)
            if not match:
                continue
            user = match.group(2).lower()
            exists = match.group(3) == "exists"
            if (match.group(1), user) in seen:
                continue
            seen.add((match.group(1), user))
            entities.append(
                {
                    "type": "smtp_user",
                    "host": match.group(1),
                    "username": user,
                    "status": "exists" if exists else "not_found",
                }
            )
        return ParsedResult(
            tool="smtp-user-enum", entities=entities, raw=output, parsed_at=now_utc()
        )