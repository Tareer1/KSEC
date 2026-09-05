"""dnsenum adapter — DNS enumeration (capability: dns_enum, alternate tool).

Selected with ``--options '{"tool": "dnsenum"}'``; the preferred ``dns_enum``
adapter stays dnsrecon.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target


class DnsenumAdapter(ToolAdapter):
    name = "dnsenum"
    capability = "dns_enum"
    description = "DNS record enumeration (dnsenum)."
    safety = "PASSIVE"
    default_parser = "dnsenum"

    def build_command(self, request: CommandRequest) -> list[str]:
        target = validate_target(request.target)
        opts = request.options or {}
        cmd = ["dnsenum", "--enum", target]
        if opts.get("dictionary"):
            cmd += ["-f", str(opts["dictionary"])]
        if opts.get("threads"):
            cmd += ["-t", str(int(opts["threads"]))]
        if opts.get("zone_transfer"):
            cmd += ["--no-web", "--noreverse"]  # keep passive-ish; AXFR via -t axfr
        return cmd