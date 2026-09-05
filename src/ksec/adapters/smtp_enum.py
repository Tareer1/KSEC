"""smtp-user-enum adapter — SMTP user enumeration (capability: smtp_enum).

Tests whether usernames exist on an authorized mail server using VRFY (or
RCPT/EXPN). Usernames come from ``options.users`` (a file) or a built-in
default list.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target

DEFAULT_USERS = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"


class SmtpUserEnumAdapter(ToolAdapter):
    name = "smtp-user-enum"
    capability = "smtp_enum"
    description = "SMTP user enumeration (smtp-user-enum)."
    safety = "ACTIVE_SAFE"
    default_parser = "smtp_enum"

    def build_command(self, request: CommandRequest) -> list[str]:
        target = validate_target(request.target)
        opts = request.options or {}
        mode = str(opts.get("mode") or "VRFY").upper()
        users = str(opts.get("users") or DEFAULT_USERS)
        cmd = [
            "smtp-user-enum",
            "-M", mode,
            "-U", users,
            "-t", target,
        ]
        if opts.get("port"):
            cmd += ["-p", str(int(opts["port"]))]
        return cmd