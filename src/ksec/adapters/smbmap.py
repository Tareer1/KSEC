"""smbmap adapter — SMB share/access mapping (capability: smb_map)."""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter


class SmbMapAdapter(ToolAdapter):
    name = "smbmap"
    capability = "smb_map"
    description = "SMB share enumeration and access mapping (smbmap)."
    safety = "ACTIVE_AGGRESSIVE"
    default_parser = "smbmap"

    def build_command(self, request: CommandRequest) -> list[str]:
        opts = request.options or {}
        target = request.target.strip()
        cmd = ["smbmap", "-H", target]
        if opts.get("user"):
            cmd += ["-u", str(opts["user"])]
        if opts.get("password"):
            cmd += ["-p", str(opts["password"])]
        elif opts.get("guest"):
            cmd += ["-u", "", "-p", ""]
        if opts.get("domain"):
            cmd += ["-d", str(opts["domain"])]
        if opts.get("shares"):
            cmd += ["-s", str(opts["shares"])]
        return cmd
