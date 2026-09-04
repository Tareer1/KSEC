"""Plugin manifest parsing and validation (spec: PLUGIN MANIFEST).

A plugin is a directory containing ``manifest.json`` plus optional Python
modules (adapter, parser, health check). The manifest declares everything the
plugin needs — and everything it is allowed to do. Validation is strict:
malformed, incomplete or over-privileged manifests are rejected.

Required manifest keys:

* ``id`` — unique dotted identifier, e.g. ``org.example.http-headers``
* ``name`` — human-readable name
* ``version`` — semantic version
* ``description``
* ``author``
* ``category`` — one of the spec 04#52 categories
* ``trust_level`` — CORE_TRUSTED | VERIFIED | LOCAL | THIRD_PARTY | UNTRUSTED | BLOCKED
* ``permissions`` — list of declared permissions (spec 06#44)
* ``capabilities`` — list of capability identifiers this plugin provides
* ``dependencies`` — optional: tools, python, plugins
* ``adapters`` — optional list of adapter descriptors
* ``parsers`` — optional list of parser descriptors
* ``health_check`` — optional module/class for ``ksec plugin check``
* ``safety`` — optional safety classification (default ACTIVE_SAFE)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ksec.core.errors import KSECError

# Trust levels (spec 06#45). UNTRUSTED and BLOCKED plugins must not execute.
TRUST_LEVELS = (
    "CORE_TRUSTED",
    "VERIFIED",
    "LOCAL",
    "THIRD_PARTY",
    "UNTRUSTED",
    "BLOCKED",
)
EXECUTABLE_TRUST_LEVELS = ("CORE_TRUSTED", "VERIFIED", "LOCAL", "THIRD_PARTY")

# Declared permission set (spec 06#44). Plugins may not receive undeclared
# privileges, so the manifest is validated against this exact list.
PERMISSIONS = (
    "network.access",
    "network.listen",
    "filesystem.read",
    "filesystem.write",
    "tool.execute",
    "database.read",
    "database.write",
)

# Categories from spec 04#52 / 01#31.
CATEGORIES = (
    "discovery",
    "network",
    "web",
    "api",
    "wireless",
    "vulnerability",
    "cloud",
    "containers",
    "endpoint",
    "dfir",
    "malware",
    "threat_intel",
    "reporting",
    "compliance",
    "integrations",
    "other",
)

SAFETY_CLASSES = ("PASSIVE", "ACTIVE_SAFE", "ACTIVE_AGGRESSIVE")

# Which permissions each safety class requires (enforced at load time).
SAFETY_PERMISSION_MAP: dict[str, tuple[str, ...]] = {
    "PASSIVE": ("network.access", "filesystem.read"),
    "ACTIVE_SAFE": ("network.access", "tool.execute"),
    "ACTIVE_AGGRESSIVE": ("network.access", "tool.execute", "network.listen"),
}

MANIFEST_NAME = "manifest.json"
_VERSION_RE = re.compile(r"^\d+\.\d+(\.\d+)?([-+][0-9A-Za-z.-]+)?$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")


@dataclass(frozen=True)
class AdapterDescriptor:
    capability: str
    module: str
    class_name: str
    tool: str = ""
    safety: str = "ACTIVE_SAFE"
    parser: str = ""


@dataclass(frozen=True)
class ParserDescriptor:
    name: str
    module: str
    class_name: str


@dataclass(frozen=True)
class PluginManifest:
    id: str
    name: str
    version: str
    description: str
    author: str
    category: str
    trust_level: str
    permissions: tuple[str, ...]
    capabilities: tuple[str, ...]
    dependencies: dict = field(default_factory=dict)
    adapters: tuple[AdapterDescriptor, ...] = ()
    parsers: tuple[ParserDescriptor, ...] = ()
    health_check: dict | None = None
    safety: str = "ACTIVE_SAFE"

    @property
    def is_executable(self) -> bool:
        """True when the trust level permits execution (spec 06#45)."""
        return self.trust_level in EXECUTABLE_TRUST_LEVELS

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "category": self.category,
            "trust_level": self.trust_level,
            "permissions": list(self.permissions),
            "capabilities": list(self.capabilities),
            "dependencies": self.dependencies,
            "safety": self.safety,
            "adapters": [
                {
                    "capability": a.capability,
                    "tool": a.tool,
                    "safety": a.safety,
                    "parser": a.parser,
                    "module": a.module,
                    "class": a.class_name,
                }
                for a in self.adapters
            ],
            "parsers": [
                {"name": p.name, "module": p.module, "class": p.class_name}
                for p in self.parsers
            ],
        }


def load_manifest(plugin_dir: Path) -> PluginManifest:
    """Load and validate the manifest at ``plugin_dir/manifest.json``.

    Raises :class:`KSECError` with a precise reason when validation fails.
    """
    manifest_path = plugin_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        raise KSECError(f"plugin {plugin_dir}: missing {MANIFEST_NAME}")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KSECError(f"plugin {plugin_dir}: invalid manifest JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise KSECError(f"plugin {plugin_dir}: manifest must be a JSON object")

    errors = _validate(raw)
    if errors:
        raise KSECError(f"plugin {plugin_dir.name!r} manifest invalid: {'; '.join(errors)}")
    return _build(raw)


def _validate(raw: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    plugin_id = raw.get("id")
    if not isinstance(plugin_id, str) or not _ID_RE.fullmatch(plugin_id):
        errors.append("'id' must be a lowercase dotted identifier (e.g. org.example.http-headers)")

    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append("'name' is required")

    version = raw.get("version")
    if not isinstance(version, str) or not _VERSION_RE.fullmatch(version):
        errors.append("'version' must be semantic (e.g. 1.0.0)")

    for key in ("description", "author"):
        if not isinstance(raw.get(key, ""), str):
            errors.append(f"'{key}' must be a string")

    category = raw.get("category", "other")
    if category not in CATEGORIES:
        errors.append(f"'category' must be one of {', '.join(CATEGORIES)}")

    trust = raw.get("trust_level")
    if trust not in TRUST_LEVELS:
        errors.append(f"'trust_level' must be one of {', '.join(TRUST_LEVELS)}")

    permissions = raw.get("permissions", [])
    if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions):
        errors.append("'permissions' must be a list of strings")
    else:
        unknown = sorted(set(permissions) - set(PERMISSIONS))
        if unknown:
            errors.append(
                f"undeclared privilege(s) not in the permission set: {', '.join(unknown)}"
            )

    capabilities = raw.get("capabilities", [])
    if not isinstance(capabilities, list) or not all(isinstance(c, str) for c in capabilities):
        errors.append("'capabilities' must be a list of strings")
    elif not capabilities and not raw.get("adapters"):
        errors.append("plugin must declare at least one capability or adapter")

    safety = raw.get("safety", "ACTIVE_SAFE")
    if safety not in SAFETY_CLASSES:
        errors.append(f"'safety' must be one of {', '.join(SAFETY_CLASSES)}")
    elif trust in EXECUTABLE_TRUST_LEVELS:
        # A plugin that will execute must declare the permissions its safety
        # class requires (spec 06#44: no undeclared privileges).
        required = SAFETY_PERMISSION_MAP[safety]
        missing = [p for p in required if p not in permissions]
        if missing:
            errors.append(
                f"safety class {safety} requires permission(s): {', '.join(missing)}"
            )

    for key in ("dependencies",):
        if key in raw and not isinstance(raw[key], dict):
            errors.append(f"'{key}' must be an object")

    adapters = raw.get("adapters", [])
    if not isinstance(adapters, list):
        errors.append("'adapters' must be a list")
    else:
        for i, adapter in enumerate(adapters):
            if not isinstance(adapter, dict):
                errors.append(f"adapters[{i}]: must be an object")
                continue
            if not isinstance(adapter.get("capability"), str) or not adapter.get("capability"):
                errors.append(f"adapters[{i}]: 'capability' is required")
            if not isinstance(adapter.get("module"), str) or not adapter.get("module"):
                errors.append(f"adapters[{i}]: 'module' is required")
            if not isinstance(adapter.get("class"), str) or not adapter.get("class"):
                errors.append(f"adapters[{i}]: 'class' is required")
            a_safety = adapter.get("safety", "ACTIVE_SAFE")
            if a_safety not in SAFETY_CLASSES:
                errors.append(f"adapters[{i}]: invalid safety {a_safety!r}")

    parsers = raw.get("parsers", [])
    if not isinstance(parsers, list):
        errors.append("'parsers' must be a list")
    else:
        for i, parser in enumerate(parsers):
            if not isinstance(parser, dict):
                errors.append(f"parsers[{i}]: must be an object")
                continue
            if not isinstance(parser.get("name"), str) or not parser.get("name"):
                errors.append(f"parsers[{i}]: 'name' is required")
            if not isinstance(parser.get("module"), str) or not parser.get("module"):
                errors.append(f"parsers[{i}]: 'module' is required")
            if not isinstance(parser.get("class"), str) or not parser.get("class"):
                errors.append(f"parsers[{i}]: 'class' is required")

    return errors


def _build(raw: dict[str, Any]) -> PluginManifest:
    return PluginManifest(
        id=raw["id"],
        name=raw["name"],
        version=raw["version"],
        description=raw.get("description", ""),
        author=raw.get("author", ""),
        category=raw.get("category", "other"),
        trust_level=raw["trust_level"],
        permissions=tuple(raw.get("permissions", [])),
        capabilities=tuple(raw.get("capabilities", [])),
        dependencies=raw.get("dependencies", {}),
        adapters=tuple(
            AdapterDescriptor(
                capability=a["capability"],
                module=a["module"],
                class_name=a["class"],
                tool=a.get("tool", ""),
                safety=a.get("safety", "ACTIVE_SAFE"),
                parser=a.get("parser", ""),
            )
            for a in raw.get("adapters", [])
        ),
        parsers=tuple(
            ParserDescriptor(name=p["name"], module=p["module"], class_name=p["class"])
            for p in raw.get("parsers", [])
        ),
        health_check=raw.get("health_check"),
        safety=raw.get("safety", "ACTIVE_SAFE"),
    )