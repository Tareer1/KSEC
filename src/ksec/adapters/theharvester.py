"""theHarvester adapter — passive OSINT harvesting (capability: osint_harvest).

theHarvester collects emails, hosts/subdomains and IPs about a domain from
public sources. Default source ``crtsh`` (certificate transparency) needs no
API key and is fast; other sources can be selected via options.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter


class TheHarvesterAdapter(ToolAdapter):
    name = "theHarvester"
    capability = "osint_harvest"
    description = "Passive OSINT email/host/IP harvesting (theHarvester)."
    safety = "PASSIVE"
    default_parser = "theharvester"

    def build_command(self, request: CommandRequest) -> list[str]:
        domain = request.target.strip().lower()
        if domain.startswith(("http://", "https://")):
            from urllib.parse import urlparse

            domain = urlparse(domain).netloc or domain
        opts = request.options or {}
        source = str(opts.get("source") or "crtsh")
        limit = int(opts.get("limit") or 100)
        cmd = [
            "theHarvester",
            "-d", domain,
            "-b", source,
            "-l", str(limit),
        ]
        if opts.get("dns_server"):
            cmd += ["-s", str(opts["dns_server"])]
        return cmd
