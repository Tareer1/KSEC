"""amass adapter — deep subdomain enumeration (capability: subdomain_enum).

Default mode is passive (no active probing). Results stream to stdout via
``-o /dev/stdout`` so the scheduler captures them without temp files.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target


class AmassAdapter(ToolAdapter):
    name = "amass"
    capability = "subdomain_enum"
    description = "Deep subdomain enumeration (amass)."
    safety = "PASSIVE"
    default_parser = "amass"

    def build_command(self, request: CommandRequest) -> list[str]:
        target = validate_target(request.target)
        opts = request.options or {}
        cmd = ["amass", "enum", "-passive", "-d", target, "-o", "/dev/stdout"]
        if opts.get("active"):
            cmd.remove("-passive")
        if opts.get("timeout"):
            cmd += ["-timeout", str(int(opts["timeout"]))]
        return cmd