"""whatweb adapter — web technology fingerprinting (capability: web_fingerprint).

whatweb identifies the technologies behind a website: server, HTTP headers,
frameworks (WordPress, jQuery, ...), titles and IPs. Plain text output is
parsed by the WhatwebParser.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter


class WhatwebAdapter(ToolAdapter):
    name = "whatweb"
    capability = "web_fingerprint"
    description = "Web technology fingerprinting (whatweb)."
    safety = "ACTIVE_SAFE"
    default_parser = "whatweb"

    def build_command(self, request: CommandRequest) -> list[str]:
        url = request.target.strip()
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        cmd = ["whatweb", "--color=never", "--no-errors", url]
        opts = request.options or {}
        if opts.get("max_threads"):
            cmd += ["--max-threads", str(opts["max_threads"])]
        if opts.get("follow_redirects"):
            cmd.append("--follow-redirect=never")
        return cmd
