"""aircrack-ng adapter — WPA/WEP key recovery (capability: wifi_crack).

Operates on a captured handshake file (the job target) with a wordlist from
``options.wordlist``. Only authorized engagements may supply capture files.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"


class AircrackNgAdapter(ToolAdapter):
    name = "aircrack-ng"
    capability = "wifi_crack"
    description = "WPA/WEP key recovery from captured handshakes (aircrack-ng)."
    safety = "ACTIVE_AGGRESSIVE"
    default_parser = "aircrack_ng"

    def build_command(self, request: CommandRequest) -> list[str]:
        capture = validate_target(request.target)  # path to .cap/.pcap file
        opts = request.options or {}
        wordlist = str(opts.get("wordlist") or DEFAULT_WORDLIST)
        cmd = ["aircrack-ng", "-w", wordlist, capture]
        if opts.get("bssid"):
            cmd += ["-b", str(opts["bssid"])]
        return cmd