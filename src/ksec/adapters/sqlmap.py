"""sqlmap adapter — authorized SQL injection testing (capability: sqli_test).

Runs sqlmap against a URL the engagement scope authorizes. Defaults are
conservative (batch mode, no tampering, no crawling of other hosts) and the
normal policy gate applies before any job executes. Use it only against
targets you are licensed to test.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter


class SqlmapAdapter(ToolAdapter):
    name = "sqlmap"
    capability = "sqli_test"
    description = "SQL injection testing on authorized URLs (sqlmap)."
    safety = "ACTIVE_AGGRESSIVE"
    default_parser = "sqlmap"

    def build_command(self, request: CommandRequest) -> list[str]:
        opts = request.options or {}
        url = request.target.strip()
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--disable-coloring",
            "--level", str(int(opts.get("level") or 1)),
            "--risk", str(int(opts.get("risk") or 1)),
        ]
        if opts.get("technique"):
            cmd += ["--technique", str(opts["technique"])]
        if opts.get("crawl"):
            cmd += ["--crawl", str(int(opts["crawl"]))]
        if opts.get("forms"):
            cmd += ["--forms"]
        if opts.get("data"):
            cmd += ["--data", str(opts["data"])]
        return cmd