"""iwlist adapter — wireless AP discovery (capability: wifi_scan).

Scans nearby access points on an authorized wireless interface. The
interface is passed through ``options.interface`` (default ``wlan0``);
wireless testing must still be authorized in an engagement scope.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target


class IwlistAdapter(ToolAdapter):
    name = "iwlist"
    capability = "wifi_scan"
    description = "Wireless access-point scan (iwlist)."
    safety = "ACTIVE_SAFE"
    default_parser = "iwlist"

    def build_command(self, request: CommandRequest) -> list[str]:
        iface = str((request.options or {}).get("interface") or "wlan0")
        return ["iwlist", validate_target(iface), "scan"]