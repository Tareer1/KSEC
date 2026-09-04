"""enum4linux adapter — SMB host enumeration (capability: smb_enum)."""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter


class Enum4LinuxAdapter(ToolAdapter):
    name = "enum4linux"
    capability = "smb_enum"
    description = "SMB/NetBIOS enumeration (enum4linux)."
    safety = "ACTIVE_AGGRESSIVE"
    default_parser = "enum4linux"

    def build_command(self, request: CommandRequest) -> list[str]:
        target = request.target.strip()
        cmd = ["enum4linux", "-a", target]
        opts = request.options or {}
        if opts.get("no_banner"):
            cmd.append("-n")
        return cmd
