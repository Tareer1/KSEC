"""curl adapter: capability ``http_probe``."""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target


class CurlAdapter(ToolAdapter):
    name = "curl"
    capability = "http_probe"
    description = "HTTP probing: fetch status and content type of a URL."
    safety = "ACTIVE_SAFE"
    default_parser = "http_probe"

    def build_command(self, request: CommandRequest) -> list[str]:
        target = validate_target(request.target)
        # Normalize a bare host into an HTTP URL when no scheme is given.
        if not target.lower().startswith(("http://", "https://")):
            target = f"http://{target}"
        return [
            "curl",
            "-sS",
            "-L",
            "--max-time",
            str(max(1, min(request.timeout, 30))),
            "-o",
            "/dev/null",
            "-w",
            "%{http_code} %{content_type}",
            target,
        ]