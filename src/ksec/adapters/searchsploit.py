"""searchsploit adapter — local Exploit-DB lookup (capability: exploit_search).

Queries the local Exploit-DB database (installed with ``exploitdb`` on Kali)
for public exploits matching a product/version/CVE. This is exactly what
professional red teams do to move from \"version found\" to \"known public
exploit exists\": a read-only local database query, nothing executed against
the target. Every job still passes the normal scope policy gate.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter


class SearchsploitAdapter(ToolAdapter):
    name = "searchsploit"
    capability = "exploit_search"
    description = "Local Exploit-DB lookup: version/product/CVE -> public exploits (searchsploit)."
    safety = "PASSIVE"
    default_parser = "searchsploit"

    def build_command(self, request: CommandRequest) -> list[str]:
        opts = request.options or {}
        query = request.target.strip()
        # searchsploit queries the product/version expression directly.
        terms = [query]
        if opts.get("exclude"):
            terms += ["--exclude", str(opts["exclude"])]
        if opts.get("cve"):
            terms = [str(opts["cve"]), "--cve"]
        cmd = ["searchsploit", "--json", *terms]
        return cmd