"""dnsrecon adapter — DNS enumeration (capability: dns_enum).

Default mode performs standard DNS queries only (like ``dig``). Brute-force
subdomain enumeration or zone-transfer attempts must be requested through
``options`` and remain gated by KSEC engagement scope like every capability.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter


class DnsreconAdapter(ToolAdapter):
    name = "dnsrecon"
    capability = "dns_enum"
    description = "DNS record enumeration (dnsrecon)."
    safety = "PASSIVE"
    default_parser = "dnsrecon"
    output_stream = "stderr"  # dnsrecon >= 1.6 logs record lines to stderr

    def build_command(self, request: CommandRequest) -> list[str]:
        target = request.target.strip()
        cmd = ["dnsrecon", "-d", target]
        opts = request.options or {}
        if opts.get("type"):  # std | rv | brd | srv | etc.
            cmd += ["-t", str(opts["type"])]
        if opts.get("dictionary"):
            cmd += ["-D", str(opts["dictionary"])]
        if opts.get("threads"):
            cmd += ["-c", str(opts["threads"])]
        if opts.get("zone_transfer"):
            cmd.append("-z")
        if opts.get("json_file"):
            cmd += ["-j", str(opts["json_file"])]
        return cmd
