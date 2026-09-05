"""Parse ``john`` output into cracked credential entities.

Handles the live cracking format (``password (user)``) and the summary
format from ``john --show`` (``user:password:...``).
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_CRACKED_RE = re.compile(r"^\s*(\S+)\s+\((\S+)\)\s*$")
_SHOW_RE = re.compile(r"^(\S+):([^:]*):")


class JohnParser(OutputParser):
    name = "john"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for line in output.splitlines():
            match = _CRACKED_RE.match(line)
            if match:
                password, user = match.group(1), match.group(2)
            else:
                show = _SHOW_RE.match(line)
                if not show:
                    continue
                user, password = show.group(1), show.group(2)
            if not password or (user, password) in seen:
                continue
            seen.add((user, password))
            entities.append(
                {
                    "type": "credential",
                    "username": user,
                    "password": password,
                    "status": "cracked",
                }
            )
        return ParsedResult(tool="john", entities=entities, raw=output, parsed_at=now_utc())