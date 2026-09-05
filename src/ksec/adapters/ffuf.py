"""ffuf adapter — fast web content fuzzing (capability: web_fuzz).

Enumerates directories/files on an authorized web target using ffuf with a
wordlist. Defaults stay conservative (common wordlist, quiet JSON output)
and the policy gate applies before any run.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class FfufAdapter(ToolAdapter):
    name = "ffuf"
    capability = "web_fuzz"
    description = "Fast web directory/file fuzzing (ffuf)."
    safety = "ACTIVE_SAFE"
    default_parser = "ffuf"

    def build_command(self, request: CommandRequest) -> list[str]:
        opts = request.options or {}
        url = request.target.strip()
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        wordlist = str(opts.get("wordlist") or DEFAULT_WORDLIST)
        cmd = [
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-mc", str(opts.get("match_codes") or "200,204,301,302,307,403"),
            "-o", "-",      # JSON result to stdout
            "-of", "json",
        ]
        if opts.get("threads"):
            cmd += ["-t", str(int(opts["threads"]))]
        if opts.get("rate"):
            cmd += ["-rate", str(int(opts["rate"]))]
        return cmd