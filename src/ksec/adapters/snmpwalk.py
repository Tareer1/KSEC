"""snmpwalk adapter — SNMP enumeration (capability: snmp_enum).

Walks the public tree of an authorized SNMP-enabled device using v2c with a
community string (default ``public``). Numeric OIDs keep output stable
without local MIBs.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target

DEFAULT_OID = "1.3.6.1.2.1.1"  # system group


class SnmpwalkAdapter(ToolAdapter):
    name = "snmpwalk"
    capability = "snmp_enum"
    description = "SNMP MIB tree enumeration (snmpwalk)."
    safety = "ACTIVE_SAFE"
    default_parser = "snmpwalk"

    def build_command(self, request: CommandRequest) -> list[str]:
        target = validate_target(request.target)
        opts = request.options or {}
        cmd = [
            "snmpwalk",
            "-v2c",
            "-c", str(opts.get("community") or "public"),
            "-On",
            "-t", str(opts.get("timeout") or "5"),
        ]
        cmd.append(target)
        cmd.append(str(opts.get("oid") or DEFAULT_OID))
        return cmd