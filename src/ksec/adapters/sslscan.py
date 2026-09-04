"""sslscan adapter — TLS/SSL protocol & cipher enumeration (capability: tls_scan)."""
from __future__ import annotations

import re

from ksec.adapters.base import CommandRequest, ToolAdapter

_HOST_PORT_RE = re.compile(r"^[a-z0-9.\-\[\]:]+$", re.IGNORECASE)


class SslScanAdapter(ToolAdapter):
    name = "sslscan"
    capability = "tls_scan"
    description = "TLS/SSL protocol and cipher enumeration (sslscan)."
    safety = "ACTIVE_SAFE"
    default_parser = "tls_scan"

    def build_command(self, request: CommandRequest) -> list[str]:
        host = (request.target or "").strip()
        if "://" in host:
            host = host.split("://", 1)[1].split("/", 1)[0]
        if ":" in host and not host.startswith("["):
            pass  # host:port form is accepted by sslscan
        if not _HOST_PORT_RE.match(host):
            raise ValueError(f"invalid tls_scan target {request.target!r}")
        opts = request.options or {}
        port = opts.get("port")
        cmd = ["sslscan", "--no-colour"]
        if port:
            cmd += ["--port", str(int(port))]
        cmd.append(host)
        return cmd
