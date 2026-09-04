"""gobuster adapter — web directory/file enumeration (capability: directory_brute)."""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class GobusterAdapter(ToolAdapter):
    name = "gobuster"
    capability = "directory_brute"
    description = "Web directory/file brute-forcing (gobuster)."
    safety = "ACTIVE_SAFE"
    default_parser = "gobuster"

    def build_command(self, request: CommandRequest) -> list[str]:
        url = request.target.strip()
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        opts = request.options or {}
        wordlist = str(opts.get("wordlist") or DEFAULT_WORDLIST)
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"]
        if opts.get("status_codes"):
            cmd += ["-s", str(opts["status_codes"])]
        return cmd
