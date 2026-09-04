"""Dynamic Kali tool/capability discovery (spec: TOOL DISCOVERY ENGINE).

Discovers installed binaries and versions from the live system, records a
snapshot in ``tool_registry``, and reports which capabilities are available
or missing.
"""
from __future__ import annotations

import shutil
import sqlite3
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone

from ksec.capabilities.catalog import TOOLS, ToolDefinition
from ksec.db.connection import Database


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tool_version(binary: str) -> str:
    try:
        proc = subprocess.run(
            [binary, "--version"], capture_output=True, text=True, timeout=5
        )
        text = (proc.stdout or proc.stderr or "").strip()
        return text.splitlines()[0][:120] if text else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


@dataclass(frozen=True)
class DiscoveredTool:
    name: str
    package: str
    category: str
    capability: str
    binary_path: str | None
    version: str
    ready: bool
    description: str


class CapabilityRegistry:
    def __init__(self, db: Database | None = None):
        self.db = db

    def definitions(self) -> list[ToolDefinition]:
        return list(TOOLS)

    def discover(self, persist: bool = True) -> list[DiscoveredTool]:
        results: list[DiscoveredTool] = []
        for tool in TOOLS:
            path = shutil.which(tool.binary)
            version = _tool_version(tool.binary) if path else ""
            results.append(
                DiscoveredTool(
                    name=tool.name,
                    package=tool.package,
                    category=tool.category,
                    capability=tool.capability,
                    binary_path=path,
                    version=version,
                    ready=path is not None,
                    description=tool.description,
                )
            )
        if persist and self.db is not None:
            self._persist(results)
        return results

    def _persist(self, results: list[DiscoveredTool]) -> None:
        self.db.executemany(
            "INSERT OR REPLACE INTO tool_registry (tool, package, category, binary_path,"
            " version, capability, ready, last_checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    r.name,
                    r.package,
                    r.category,
                    r.binary_path,
                    r.version,
                    r.capability,
                    1 if r.ready else 0,
                    _now(),
                )
                for r in results
            ],
        )

    def available_capabilities(self) -> list[str]:
        return sorted({t.capability for t in self.discover(persist=False) if t.ready})

    def missing_capabilities(self) -> dict[str, list[str]]:
        missing: dict[str, list[str]] = {}
        for tool in TOOLS:
            if shutil.which(tool.binary) is None:
                missing.setdefault(tool.capability, []).append(tool.name)
        return missing

    def tool_health(self, name: str) -> dict:
        path = shutil.which(name)
        return {
            "tool": name,
            "binary": path,
            "ready": path is not None,
            "checked_at": _now(),
        }

    def list_persisted(self) -> list[sqlite3.Row]:
        if self.db is None:
            return []
        return self.db.query_all("SELECT * FROM tool_registry ORDER BY tool")