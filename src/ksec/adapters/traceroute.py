"""traceroute adapter — network path discovery (capability: traceroute)."""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target


class TracerouteAdapter(ToolAdapter):
    name = "traceroute"
    capability = "traceroute"
    description = "Network path discovery (traceroute)."
    safety = "PASSIVE"
    default_parser = "traceroute"

    def build_command(self, request: CommandRequest) -> list[str]:
        target = validate_target(request.target)
        opts = request.options or {}
        cmd = ["traceroute"]
        if opts.get("max_hops"):
            cmd += ["-m", str(int(opts["max_hops"]))]
        if opts.get("wait"):
            cmd += ["-w", str(int(opts["wait"]))]
        cmd.append(target)
        return cmd