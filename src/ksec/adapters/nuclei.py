"""nuclei adapter — template-based CVE/vulnerability scanning (capability: cve_scan).

nuclei is the modern template-driven scanner: 7000+ public templates match
CVEs and misconfigurations (exposures, default logins, CVEs, takeovers,
misconfigs). Output is JSONL so every match becomes a structured finding.
Only authorized engagement targets are scanned — the policy gate applies
before any run. Defaults are rate-limited and skip info-only noise.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter

VALID_SEVERITY = ("info", "low", "medium", "high", "critical")


class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    capability = "cve_scan"
    description = "Template-based CVE/vulnerability scanning on authorized targets (nuclei)."
    safety = "ACTIVE_SAFE"
    default_parser = "nuclei"

    def build_command(self, request: CommandRequest) -> list[str]:
        opts = request.options or {}
        target = request.target.strip()
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        cmd = [
            "nuclei",
            "-u", target,
            "-jsonl",
            "-duc",                 # disable unused-custom template update check
            "-rate-limit", str(int(opts.get("rate_limit") or 10)),
            "-timeout", str(int(opts.get("timeout") or 10)),
        ]
        severity = opts.get("severity")
        if severity:
            chosen = [s for s in str(severity).split(",") if s.strip() in VALID_SEVERITY]
            if chosen:
                cmd += ["-severity", ",".join(chosen)]
        if opts.get("tags"):
            cmd += ["-tags", str(opts["tags"])]
        if opts.get("templates"):
            cmd += ["-t", str(opts["templates"])]
        return cmd