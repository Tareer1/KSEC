"""Plugin lifecycle manager (spec: PLUGIN ARCHITECTURE).

Responsibilities:

* discover plugins in the bundled ``plugins/`` tree and the user plugins
  directory (``<data_dir>/plugins``)
* validate manifests and record installations in the ``plugin_registry`` table
* load enabled, trusted plugins: dynamically import their adapter/parser
  modules and register them with the core registries
* gate execution: a capability provided by a plugin only runs when the plugin
  is ENABLED, has an executable trust level and declares the ``tool.execute``
  permission (spec 06#43-45).

Untrusted plugins are never loaded and never execute.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ksec.adapters.base import ToolAdapter
from ksec.adapters.registry import AdapterRegistry
from ksec.audit.service import AuditService
from ksec.config.loader import KsecConfig
from ksec.core.errors import KSECError
from ksec.db.connection import Database
from ksec.identity.users import now_utc
from ksec.parsers.base import OutputParser
from ksec.plugins.manifest import (
    EXECUTABLE_TRUST_LEVELS,
    MANIFEST_NAME,
    PluginManifest,
    load_manifest,
)

# Status values in plugin_registry.status.
STATUS_INSTALLED = "INSTALLED"
STATUS_ENABLED = "ENABLED"
STATUS_DISABLED = "DISABLED"
STATUS_BLOCKED = "BLOCKED"
STATUS_UNINSTALLED = "UNINSTALLED"


@dataclass(frozen=True)
class PluginInfo:
    plugin_id: str
    name: str
    version: str
    description: str
    author: str
    category: str
    trust_level: str
    status: str
    source: str
    path: str
    permissions: tuple[str, ...]
    capabilities: tuple[str, ...]
    manifest_sha256: str
    installed_by: str
    installed_at: str

    @property
    def executable(self) -> bool:
        return (
            self.status == STATUS_ENABLED
            and self.trust_level in EXECUTABLE_TRUST_LEVELS
            and "tool.execute" in self.permissions
        )

    def to_dict(self) -> dict:
        return {
            "plugin_id": self.plugin_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "category": self.category,
            "trust_level": self.trust_level,
            "status": self.status,
            "source": self.source,
            "path": self.path,
            "permissions": list(self.permissions),
            "capabilities": list(self.capabilities),
            "manifest_sha256": self.manifest_sha256,
            "installed_by": self.installed_by,
            "installed_at": self.installed_at,
            "executable": self.executable,
        }


class PluginManager:
    def __init__(
        self,
        db: Database,
        config: KsecConfig,
        adapters: AdapterRegistry,
        audit: AuditService,
        bundled_dir: Path | None = None,
    ):
        self.db = db
        self.config = config
        self.adapters = adapters
        self.audit = audit
        # Bundled plugins ship with KSEC and are CORE_TRUSTED by default.
        self.bundled_dir = Path(bundled_dir) if bundled_dir else Path("plugins")
        self.user_dir = config.data_dir / "plugins"
        self._manifests: dict[str, PluginManifest] = {}
        self._loaded_adapters: set[str] = set()  # plugin_ids whose adapters are registered
        self._loaded_parsers: set[str] = set()

    # -- paths ------------------------------------------------------------

    def plugin_dirs(self) -> list[Path]:
        """Search path: bundled tree first, then the user plugins directory."""
        dirs: list[Path] = []
        if self.bundled_dir.is_dir():
            for child in sorted(self.bundled_dir.iterdir()):
                if child.is_dir() and (child / MANIFEST_NAME).is_file():
                    dirs.append(child)
                elif child.is_dir():
                    # Category directory (web/, network/, ...) containing plugins.
                    for sub in sorted(child.iterdir()):
                        if sub.is_dir() and (sub / MANIFEST_NAME).is_file():
                            dirs.append(sub)
        if self.user_dir.is_dir():
            for child in sorted(self.user_dir.iterdir()):
                if child.is_dir() and (child / MANIFEST_NAME).is_file():
                    dirs.append(child)
        return dirs

    # -- discovery / validation ------------------------------------------

    def discover(self) -> list[PluginInfo]:
        """Validate every plugin on disk and return its registry row."""
        for path in self.plugin_dirs():
            try:
                manifest = load_manifest(path)
            except KSECError:
                continue  # invalid plugins are reported by `ksec plugin check`
            self._manifests[manifest.id] = manifest
            self._ensure_registry_row(manifest, path)
        rows = self.db.query_all(
            "SELECT * FROM plugin_registry WHERE status != ? ORDER BY name",
            (STATUS_UNINSTALLED,),
        )
        return [self._from_row(row) for row in rows]

    def _ensure_registry_row(self, manifest: PluginManifest, path: Path) -> None:
        source = "bundled" if str(path).startswith(str(self.bundled_dir)) else "user"
        sha = _sha256_dir(path)
        row = self.db.query_one(
            "SELECT * FROM plugin_registry WHERE plugin_id = ?", (manifest.id,)
        )
        now = now_utc()
        if row is None:
            # Bundled plugins are CORE_TRUSTED and start ENABLED; user plugins
            # start INSTALLED (require explicit approval to enable).
            status = STATUS_ENABLED if source == "bundled" else STATUS_INSTALLED
            self.db.execute(
                "INSERT INTO plugin_registry (plugin_id, name, version, description, author,"
                " category, trust_level, status, source, path, permissions, capabilities,"
                " manifest_sha256, installed_by, installed_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    manifest.id,
                    manifest.name,
                    manifest.version,
                    manifest.description,
                    manifest.author,
                    manifest.category,
                    manifest.trust_level,
                    status,
                    source,
                    str(path),
                    json.dumps(list(manifest.permissions)),
                    json.dumps(list(manifest.capabilities)),
                    sha,
                    "bundled" if source == "bundled" else "",
                    now,
                    now,
                ),
            )
        else:
            self.db.execute(
                "UPDATE plugin_registry SET name = ?, version = ?, description = ?, author = ?,"
                " category = ?, trust_level = ?, path = ?, permissions = ?, capabilities = ?,"
                " manifest_sha256 = ?, updated_at = ? WHERE plugin_id = ?",
                (
                    manifest.name,
                    manifest.version,
                    manifest.description,
                    manifest.author,
                    manifest.category,
                    manifest.trust_level,
                    str(path),
                    json.dumps(list(manifest.permissions)),
                    json.dumps(list(manifest.capabilities)),
                    sha,
                    now,
                    manifest.id,
                ),
            )

    # -- loading ----------------------------------------------------------

    def load_enabled(self) -> list[str]:
        """Load adapters/parsers for every enabled, trusted plugin.

        Returns the list of successfully loaded plugin ids.
        """
        loaded: list[str] = []
        for path in self.plugin_dirs():
            try:
                manifest = load_manifest(path)
            except KSECError:
                continue
            info = self.get(manifest.id)
            if info is None or not info.executable:
                continue
            if not self._load_plugin(manifest, Path(info.path)):
                continue
            loaded.append(manifest.id)
        return loaded

    def _load_plugin(self, manifest: PluginManifest, path: Path) -> bool:
        """Dynamically import and register one plugin's adapters/parsers."""
        ok = True
        for adapter_desc in manifest.adapters:
            if adapter_desc.capability in self.adapters.capabilities():
                continue  # built-in wins; do not shadow core capabilities
            adapter_cls = _import_class(path, adapter_desc.module, adapter_desc.class_name)
            if adapter_cls is None:
                ok = False
                continue
            # The manifest points at a ToolAdapter class; instantiate it (and
            # skip modules that fail to construct).
            try:
                adapter = adapter_cls() if isinstance(adapter_cls, type) else adapter_cls
            except Exception:
                ok = False
                continue
            if not isinstance(adapter, ToolAdapter):
                ok = False
                continue
            adapter.name = adapter_desc.tool or adapter_desc.capability
            adapter.capability = adapter_desc.capability
            adapter.default_parser = adapter_desc.parser
            if adapter_desc.safety:
                adapter.safety = adapter_desc.safety
            self.adapters.register(adapter, plugin_id=manifest.id)
        for parser_desc in manifest.parsers:
            parser = _import_class(path, parser_desc.module, parser_desc.class_name)
            if parser is None:
                ok = False
                continue
            _register_parser(parser_desc.name, parser)
        if ok:
            self._loaded_adapters.add(manifest.id)
            self._loaded_parsers.add(manifest.id)
        return ok

    # -- install / uninstall ---------------------------------------------

    def install(
        self,
        source_path: Path,
        *,
        trust_level: str = "THIRD_PARTY",
        installed_by: str = "",
        approve: bool = False,
    ) -> PluginInfo:
        """Install a plugin from ``source_path`` (a plugin directory).

        The plugin is copied into the user plugins directory, recorded in the
        registry and (when approved) enabled. Installation requires valid
        source, a valid manifest and declared permissions (spec 06#43).
        """
        source_path = Path(source_path).resolve()
        if not source_path.is_dir() or not (source_path / MANIFEST_NAME).is_file():
            raise KSECError(
                f"not a plugin directory (missing {MANIFEST_NAME}): {source_path}"
            )
        manifest = load_manifest(source_path)

        if manifest.id in {p.plugin_id for p in self.discover()}:
            raise KSECError(f"plugin {manifest.id!r} is already installed")

        target = self.user_dir / manifest.id
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise KSECError(f"plugin directory already exists: {target}")
        shutil.copytree(source_path, target)

        status = STATUS_ENABLED if (approve and manifest.is_executable) else STATUS_INSTALLED
        sha = _sha256_dir(target)
        now = now_utc()
        try:
            self.db.execute(
                "INSERT INTO plugin_registry (plugin_id, name, version, description, author,"
                " category, trust_level, status, source, path, permissions, capabilities,"
                " manifest_sha256, installed_by, installed_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'user', ?, ?, ?, ?, ?, ?, ?)",
                (
                    manifest.id,
                    manifest.name,
                    manifest.version,
                    manifest.description,
                    manifest.author,
                    manifest.category,
                    trust_level,
                    status,
                    str(target),
                    json.dumps(list(manifest.permissions)),
                    json.dumps(list(manifest.capabilities)),
                    sha,
                    installed_by,
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            shutil.rmtree(target, ignore_errors=True)
            raise KSECError(f"plugin {manifest.id!r} already registered") from exc

        self.audit.record(
            event_type="plugin.install",
            actor=installed_by or None,
            action="plugin.install",
            target=manifest.id,
            payload={
                "version": manifest.version,
                "trust_level": trust_level,
                "permissions": list(manifest.permissions),
                "capabilities": list(manifest.capabilities),
            },
        )
        info = self.get(manifest.id)
        assert info is not None
        # Approved, enabled installs register their adapters immediately.
        if status == STATUS_ENABLED and info.executable:
            self._load_plugin(manifest, target)
            info = self.get(manifest.id)
            assert info is not None
        return info

    def set_status(self, plugin_id: str, status: str, actor: str = "") -> PluginInfo:
        info = self.get(plugin_id)
        if info is None:
            raise KSECError(f"unknown plugin: {plugin_id}")
        if status not in (STATUS_ENABLED, STATUS_DISABLED, STATUS_BLOCKED):
            raise KSECError(f"invalid status: {status}")
        if status == STATUS_ENABLED:
            manifest = self._manifests.get(plugin_id)
            if manifest is None:
                try:
                    manifest = load_manifest(Path(info.path))
                except KSECError as exc:
                    raise KSECError(f"cannot enable {plugin_id}: {exc.message}") from exc
            if not manifest.is_executable:
                raise KSECError(
                    f"cannot enable {plugin_id}: trust level {manifest.trust_level}"
                    " is not executable"
                )
        self.db.execute(
            "UPDATE plugin_registry SET status = ?, updated_at = ? WHERE plugin_id = ?",
            (status, now_utc(), plugin_id),
        )
        self.audit.record(
            event_type="plugin.status",
            actor=actor or None,
            action=f"plugin.{status.lower()}",
            target=plugin_id,
        )
        # Register adapters when enabling; unregister when no longer executable.
        # ``info`` above reflects the OLD status, so test the new one directly.
        if status == STATUS_ENABLED and manifest.is_executable:
            self._load_plugin(manifest, Path(info.path))
        else:
            self._unregister_plugin(plugin_id)
        updated = self.get(plugin_id)
        assert updated is not None
        return updated

    def uninstall(self, plugin_id: str, actor: str = "") -> None:
        info = self.get(plugin_id)
        if info is None:
            raise KSECError(f"unknown plugin: {plugin_id}")
        if info.source == "bundled":
            raise KSECError(f"cannot uninstall bundled plugin {plugin_id}")
        self._unregister_plugin(plugin_id)
        path = Path(info.path)
        shutil.rmtree(path, ignore_errors=True)
        self.db.execute(
            "UPDATE plugin_registry SET status = ?, updated_at = ? WHERE plugin_id = ?",
            (STATUS_UNINSTALLED, now_utc(), plugin_id),
        )
        self.audit.record(
            event_type="plugin.uninstall",
            actor=actor or None,
            action="plugin.uninstall",
            target=plugin_id,
        )

    def _unregister_plugin(self, plugin_id: str) -> None:
        for capability in list(self.adapters.capabilities()):
            if self.adapters.plugin_of(capability) == plugin_id:
                self.adapters.unregister(capability)
        self._loaded_adapters.discard(plugin_id)
        self._loaded_parsers.discard(plugin_id)

    # -- execution gate ---------------------------------------------------

    def assert_capability_allowed(self, capability: str) -> None:
        """Raise unless the plugin providing ``capability`` may execute.

        Called by the scheduler before running any job. Built-in adapters are
        always allowed; plugin adapters must come from an ENABLED, trusted
        plugin that declared the ``tool.execute`` permission (spec 06#44-45).
        """
        plugin_id = self.adapters.plugin_of(capability)
        if plugin_id is None:
            return  # built-in adapter
        info = self.get(plugin_id)
        if info is None:
            raise KSECError(f"capability {capability!r} is provided by unknown plugin {plugin_id}")
        if info.status != STATUS_ENABLED:
            raise KSECError(
                f"capability {capability!r} is provided by plugin {plugin_id}"
                f" which is {info.status} — enable it first"
            )
        if info.trust_level not in EXECUTABLE_TRUST_LEVELS:
            raise KSECError(
                f"capability {capability!r} is provided by untrusted plugin {plugin_id}"
                f" (trust level {info.trust_level}) — cannot execute"
            )
        if "tool.execute" not in info.permissions:
            raise KSECError(
                f"plugin {plugin_id} does not declare the 'tool.execute' permission"
                " — execution denied (spec: no undeclared privileges)"
            )

    # -- health / check ---------------------------------------------------

    def check(self) -> list[dict]:
        """Validate every plugin directory: manifest, hash, loadability."""
        results: list[dict] = []
        for path in self.plugin_dirs():
            manifest = None
            errors: list[str] = []
            try:
                manifest = load_manifest(path)
            except KSECError as exc:
                errors.append(exc.message)
            info = self.get(manifest.id) if manifest else None
            row = {
                "plugin_id": manifest.id if manifest else path.name,
                "path": str(path),
                "ok": False,
                "errors": errors,
                "trust_level": manifest.trust_level if manifest else None,
                "executable": manifest.is_executable if manifest else False,
                "hash_matches": None,
                "adapters_loaded": False,
            }
            if manifest and info is None:
                errors.append("not present in plugin registry")
            if manifest and info is not None:
                actual = _sha256_dir(path)
                row["hash_matches"] = actual == info.manifest_sha256
                if not row["hash_matches"]:
                    errors.append("directory hash changed since install (tampered?)")
                row["adapters_loaded"] = bool(
                    manifest.adapters
                    and all(
                        self.adapters.get(a.capability) is not None for a in manifest.adapters
                    )
                )
            row["ok"] = not errors
            row["errors"] = errors
            results.append(row)
        return results

    # -- queries ----------------------------------------------------------

    def get(self, plugin_id: str) -> PluginInfo | None:
        row = self.db.query_one(
            "SELECT * FROM plugin_registry WHERE plugin_id = ? AND status != ?",
            (plugin_id, STATUS_UNINSTALLED),
        )
        return self._from_row(row) if row else None

    def list_all(self) -> list[PluginInfo]:
        return self.discover()

    def capabilities(self) -> dict[str, str]:
        """Map of capability -> plugin_id for plugin-provided capabilities."""
        return {
            capability: plugin_id
            for capability, plugin_id in (
                (cap, self.adapters.plugin_of(cap)) for cap in self.adapters.capabilities()
            )
            if plugin_id is not None
        }

    @staticmethod
    def _from_row(row: sqlite3.Row) -> PluginInfo:
        return PluginInfo(
            plugin_id=row["plugin_id"],
            name=row["name"],
            version=row["version"],
            description=row["description"],
            author=row["author"],
            category=row["category"],
            trust_level=row["trust_level"],
            status=row["status"],
            source=row["source"],
            path=row["path"],
            permissions=tuple(json.loads(row["permissions"] or "[]")),
            capabilities=tuple(json.loads(row["capabilities"] or "[]")),
            manifest_sha256=row["manifest_sha256"],
            installed_by=row["installed_by"],
            installed_at=row["installed_at"],
        )


def _sha256_dir(path: Path) -> str:
    """Stable hash over the plugin's files (manifest + code)."""
    digest = hashlib.sha256()
    for file in sorted(path.rglob("*")):
        if not file.is_file():
            continue
        rel = str(file.relative_to(path))
        digest.update(rel.encode("utf-8"))
        digest.update(file.read_bytes())
    return digest.hexdigest()


def _import_class(path: Path, module_name: str, class_name: str):
    """Import ``class_name`` from ``module_name`` inside a plugin directory.

    Only modules inside the plugin directory are loadable, so a manifest
    cannot point at arbitrary paths outside the plugin (spec: plugin isolation).
    """
    module_path = (path / module_name).resolve()
    plugin_root = path.resolve()
    if not str(module_path).startswith(str(plugin_root)) or module_path.suffix != ".py":
        return None
    if not module_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(
        f"ksec_plugin_{path.name}_{module_name}", module_path
    )
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        return None
    return getattr(module, class_name, None)


def _register_parser(name: str, parser_cls: type) -> None:
    """Register a plugin parser in the parser registry."""
    from ksec.parsers import registry as parser_registry

    try:
        instance = parser_cls() if isinstance(parser_cls, type) else parser_cls
    except Exception:
        return
    if not isinstance(instance, OutputParser):
        return
    parser_registry._PARSERS[name] = instance