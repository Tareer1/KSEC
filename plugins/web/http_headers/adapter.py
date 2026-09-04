"""Plugin adapter: capability ``http_headers`` via curl.

Follows the same :class:`ToolAdapter` interface as built-in adapters, so the
core engine (command builder, scheduler, parsers) works unchanged.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target


class HttpHeadersAdapter(ToolAdapter):
    name = "curl"
    capability = "http_headers"
    description = "Collect HTTP response headers from a URL (plugin)."
    safety = "ACTIVE_SAFE"
    default_parser = "http_headers"

    def build_command(self, request: CommandRequest) -> list[str]:
        target = validate_target(request.target)
        if not target.lower().startswith(("http://", "https://")):
            target = f"http://{target}"
        return [
            "curl",
            "-sSI",
            "--max-time",
            str(max(1, min(request.timeout, 30))),
            target,
        ]