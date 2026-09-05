"""whois adapter — domain registration intelligence (capability: whois_lookup)."""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target


class WhoisAdapter(ToolAdapter):
    name = "whois"
    capability = "whois_lookup"
    description = "Domain registration intelligence (whois)."
    safety = "PASSIVE"
    default_parser = "whois"

    def build_command(self, request: CommandRequest) -> list[str]:
        return ["whois", validate_target(request.target)]