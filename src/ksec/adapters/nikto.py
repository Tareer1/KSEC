"""nikto adapter — web server vulnerability scanning (capability: web_vuln_scan)."""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter


class NiktoAdapter(ToolAdapter):
    name = "nikto"
    capability = "web_vuln_scan"
    description = "Web server vulnerability scanner (nikto)."
    safety = "ACTIVE_AGGRESSIVE"
    default_parser = "nikto"

    def build_command(self, request: CommandRequest) -> list[str]:
        url = request.target.strip()
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        cmd = ["nikto", "-h", url, "-nointeractive"]
        opts = request.options or {}
        if opts.get("ssl"):
            cmd.append("-ssl")
        if opts.get("tuning"):
            cmd += ["-Tuning", str(opts["tuning"])]
        return cmd
