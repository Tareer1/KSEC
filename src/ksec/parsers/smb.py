"""Parse SMB tooling output into structured entities.

Two parsers live here: ``enum4linux`` (share + null-session findings) and
``smbmap`` (host + share access map).
"""
from __future__ import annotations

import re

from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser, ParsedResult

# enum4linux ---------------------------------------------------------

_SHARE_RE = re.compile(r"^\s+(\S+)\s+(Disk|IPC|Printer)(?:\s+(.*))?$")
_NULL_SESSION_RE = re.compile(r"Server\s+(\S+)\s+allows sessions using username ''")
_OS_RE = re.compile(r"\[%2b\] Got OS info via .*?: (\S+)")


class Enum4LinuxParser(OutputParser):
    name = "enum4linux"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        for line in output.splitlines():
            share = _SHARE_RE.match(line)
            if share and share.group(1).lower() not in ("sharename",):
                entities.append(
                    {
                        "type": "smb_share",
                        "share": share.group(1),
                        "share_type": share.group(2).lower(),
                        "comment": (share.group(3) or "").strip()[:200],
                    }
                )
                continue
            null_session = _NULL_SESSION_RE.search(line)
            if null_session:
                entities.append(
                    {
                        "type": "smb_finding",
                        "kind": "null_session",
                        "host": null_session.group(1),
                        "message": "guest/null session permitted",
                    }
                )
        return ParsedResult(tool="enum4linux", entities=entities, raw=output, parsed_at=now_utc())


# smbmap --------------------------------------------------------------

_HOST_RE = re.compile(r"\[\+\] IP: (\S+):\d+\s+Name: (\S+).*?Admin: (\S+)")
_PERMISSIONS = ("NO ACCESS", "READ ONLY", "READ, WRITE", "WRITE, READ", "READ", "WRITE", "EXECUTE")
_SHARE_LINE_RE = re.compile(r"^\s+(\S+)\s+([A-Z][A-Z, ]+?)\s*$")


class SmbMapParser(OutputParser):
    name = "smbmap"
    formats = ("text",)

    def parse(self, output: str) -> ParsedResult:
        entities: list[dict] = []
        current_host = ""
        for line in output.splitlines():
            host = _HOST_RE.search(line)
            if host:
                current_host = host.group(1)
                entities.append(
                    {
                        "type": "smb_host",
                        "ip": host.group(1),
                        "name": host.group(2),
                        "admin": host.group(3).strip().upper() not in ("NO",),
                    }
                )
                continue
            share = _SHARE_LINE_RE.match(line)
            if share and share.group(2) in _PERMISSIONS:
                entities.append(
                    {
                        "type": "smb_share",
                        "host": current_host,
                        "share": share.group(1),
                        "permission": share.group(2),
                    }
                )
        return ParsedResult(tool="smbmap", entities=entities, raw=output, parsed_at=now_utc())
