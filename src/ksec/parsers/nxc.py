"""Parse ``nxc smb`` output into credential + share entities.

nxc prints one line per result with a status tag: ``[+]`` = access gained,
``[-]`` = failed. Only confirmed lines become entities (never the scan
progress/banner).
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

_ACCESS_RE = re.compile(r"\[\+\]\s+\S+\s+(\S+)\s+\S+\s+(\S+):(\S+)\s+\((\S+)\)")
_SHARE_RE = re.compile(r"\[\+\]\s+(\S+)\s+SHARES?\s+listing:?.*?(\S+)\s+\(Read:\s*(\S+)\)")
_ADMIN_RE = re.compile(r"\[\+\]\s+(\S+)\s+.*Pwn3d!")


class NxcParser(OutputParser):
    name = "nxc"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            admin = _ADMIN_RE.search(line)
            if admin:
                entities.append(
                    {
                        "type": "auth_finding",
                        "host": admin.group(1),
                        "service": "smb",
                        "admin": True,
                        "title": "SMB admin access validated (Pwn3d!)",
                    }
                )
                continue
            access = _ACCESS_RE.search(line)
            if access:
                entities.append(
                    {
                        "type": "auth_finding",
                        "host": access.group(1),
                        "service": "smb",
                        "login": access.group(2),
                        "password": access.group(3),
                        "domain": access.group(4),
                        "title": "SMB credential validated",
                    }
                )
                continue
            share = _SHARE_RE.search(line)
            if share:
                entities.append(
                    {
                        "type": "smb_share",
                        "host": share.group(1),
                        "share": share.group(2),
                        "read": share.group(3),
                    }
                )
        return ParsedResult(tool="nxc", entities=entities, raw=output, parsed_at=now_utc())