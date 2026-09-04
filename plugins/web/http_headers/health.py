"""Plugin health check: verify curl is available (spec: PLUGIN HEALTH)."""

from __future__ import annotations

import shutil


def check() -> dict:
    curl = shutil.which("curl")
    return {
        "ok": curl is not None,
        "tool": "curl",
        "binary": curl,
    }