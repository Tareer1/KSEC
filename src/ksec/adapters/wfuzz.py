"""wfuzz adapter — web content fuzzing (capability: web_fuzz, alternate tool).

Selected with ``--options '{"tool": "wfuzz"}'``; the preferred ``web_fuzz``
adapter stays ffuf. Uses a conservative wordlist and parses the default
text table.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class WfuzzAdapter(ToolAdapter):
    name = "wfuzz"
    capability = "web_fuzz"
    description = "Web content fuzzing (wfuzz)."
    safety = "ACTIVE_SAFE"
    default_parser = "wfuzz"

    def build_command(self, request: CommandRequest) -> list[str]:
        opts = request.options or {}
        url = request.target.strip()
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
        wordlist = str(opts.get("wordlist") or DEFAULT_WORDLIST)
        cmd = [
            "wfuzz",
            "-w", wordlist,
            "-u", url,
            "--hc", str(opts.get("hide_codes") or "404"),
            "--hw", str(opts.get("hide_words") or ""),
        ]
        if opts.get("threads"):
            cmd += ["-t", str(int(opts["threads"]))]
        if opts.get("rate"):
            cmd += ["-R", str(int(opts["rate"]))]
        return cmd