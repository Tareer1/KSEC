"""Null adapter: used for tests and non-destructive validation runs.

With ``options["sleep"]`` it runs ``sleep``, which makes concurrency,
pause/resume and cancel behavior testable.
"""
from __future__ import annotations

from ksec.adapters.base import CommandRequest, ToolAdapter


class NullAdapter(ToolAdapter):
    name = "null"
    capability = "test_scan"
    description = "No-op adapter for tests and validation runs."
    safety = "PASSIVE"

    def build_command(self, request: CommandRequest) -> list[str]:
        opts = request.options or {}
        if opts.get("sleep"):
            return ["sleep", str(int(opts["sleep"]))]
        return ["true"]