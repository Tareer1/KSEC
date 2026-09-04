"""wpscan adapter — WordPress vulnerability scanning (capability: wpscan)."""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter


class WpscanAdapter(ToolAdapter):
    name = "wpscan"
    capability = "wpscan"
    description = "WordPress vulnerability scanner (wpscan)."
    safety = "ACTIVE_AGGRESSIVE"
    default_parser = "wpscan"

    def build_command(self, request: CommandRequest) -> list[str]:
        url = request.target.strip()
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        cmd = ["wpscan", "--url", url, "--format", "json", "--no-banner"]
        opts = request.options or {}
        if opts.get("enumerate"):
            # e.g. vp (vulnerable plugins), ap (all plugins), vt, u
            cmd += ["--enumerate", str(opts["enumerate"])]
        if opts.get("plugins_detection"):
            cmd += ["--plugins-detection", str(opts["plugins_detection"])]
        if opts.get("api_token"):
            cmd += ["--api-token", str(opts["api_token"])]
        if opts.get("disable_tls_checks"):
            cmd.append("--disable-tls-checks")
        return cmd
