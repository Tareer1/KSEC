"""dig adapter: capability ``dns_lookup``."""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target


class DigAdapter(ToolAdapter):
    name = "dig"
    capability = "dns_lookup"
    description = "DNS lookup utility (dig)."
    safety = "PASSIVE"
    default_parser = "dig"

    def build_command(self, request: CommandRequest) -> list[str]:
        target = validate_target(request.target)
        cmd = ["dig", target]
        opts = request.options or {}
        if opts.get("record_type"):
            cmd.append(str(opts["record_type"]))
        return cmd