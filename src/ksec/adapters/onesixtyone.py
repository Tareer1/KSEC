"""onesixtyone adapter — SNMP community-string discovery (snmp_enum).

Alternate tool for the ``snmp_enum`` capability, selected with
``--options '{"tool": "onesixtyone"}'``. Tries community names against an
authorized host and reports any that respond.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target

DEFAULT_COMMUNITIES = "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"


class OnesixyoneAdapter(ToolAdapter):
    name = "onesixtyone"
    capability = "snmp_enum"
    description = "SNMP community-string discovery (onesixtyone)."
    safety = "ACTIVE_SAFE"
    default_parser = "onesixtyone"

    def build_command(self, request: CommandRequest) -> list[str]:
        target = validate_target(request.target)
        opts = request.options or {}
        community = str(opts.get("community") or opts.get("communities") or DEFAULT_COMMUNITIES)
        cmd = ["onesixtyone", "-c", community, target]
        if opts.get("timeout"):
            cmd.insert(1, "-w")
            cmd.insert(2, str(int(opts["timeout"])))
        return cmd