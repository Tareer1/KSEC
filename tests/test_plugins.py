from __future__ import annotations

import io
import json
import shutil
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository
from ksec.plugins.manager import PluginManager, _sha256_dir
from ksec.plugins.manifest import (
    MANIFEST_NAME,
    PluginManifest,
    load_manifest,
)
from tests import KsecTestCase

# A minimal valid user plugin used for install tests (curl-based, like the
# bundled http_headers plugin but with a distinct id).
PLUGIN_FILES = {
    "manifest.json": json.dumps(
        {
            "id": "test.example-probe",
            "name": "Example Probe",
            "version": "1.0.0",
            "description": "Test plugin.",
            "author": "tests",
            "category": "web",
            "trust_level": "THIRD_PARTY",
            "permissions": ["network.access", "tool.execute"],
            "capabilities": ["example_probe"],
            "safety": "ACTIVE_SAFE",
            "adapters": [
                {
                    "capability": "example_probe",
                    "tool": "curl",
                    "safety": "ACTIVE_SAFE",
                    "parser": "",
                    "module": "adapter.py",
                    "class": "ExampleProbeAdapter",
                }
            ],
            "health_check": {"module": "health.py", "class": "check"},
        }
    ),
    "adapter.py": (
        "from ksec.adapters.base import CommandRequest, ToolAdapter\n"
        "from ksec.execution.command_builder import validate_target\n"
        "class ExampleProbeAdapter(ToolAdapter):\n"
        "    name = 'curl'\n"
        "    capability = 'example_probe'\n"
        "    safety = 'ACTIVE_SAFE'\n"
        "    def build_command(self, request):\n"
        "        target = validate_target(request.target)\n"
        "        return ['curl', '-sS', '-o', '/dev/null', target]\n"
    ),
    "health.py": (
        "import shutil\n"
        "def check():\n"
        "    return {'ok': shutil.which('curl') is not None, 'tool': 'curl'}\n"
    ),
}


class ManifestValidationTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.plugin_dir = Path(self.tmp_dir) / "src-plugin"
        self.plugin_dir.mkdir()

    def _write(self, files: dict) -> None:
        for name, content in files.items():
            (self.plugin_dir / name).write_text(content, encoding="utf-8")

    def test_valid_manifest_loads(self):
        self._write(PLUGIN_FILES)
        manifest = load_manifest(self.plugin_dir)
        self.assertIsInstance(manifest, PluginManifest)
        self.assertEqual(manifest.id, "test.example-probe")
        self.assertTrue(manifest.is_executable)
        self.assertEqual(manifest.permissions, ("network.access", "tool.execute"))

    def test_missing_manifest_rejected(self):
        with self.assertRaises(KSECError):
            load_manifest(self.plugin_dir)

    def test_invalid_trust_level_rejected(self):
        files = dict(PLUGIN_FILES)
        files["manifest.json"] = files["manifest.json"].replace(
            '"THIRD_PARTY"', '"NOT_A_TRUST"'
        )
        self._write(files)
        with self.assertRaises(KSECError) as ctx:
            load_manifest(self.plugin_dir)
        self.assertIn("trust_level", ctx.exception.message)

    def test_undeclared_permission_rejected(self):
        files = dict(PLUGIN_FILES)
        files["manifest.json"] = files["manifest.json"].replace(
            '"tool.execute"', '"tool.execute", "root.access"'
        )
        self._write(files)
        with self.assertRaises(KSECError) as ctx:
            load_manifest(self.plugin_dir)
        self.assertIn("undeclared privilege", ctx.exception.message)

    def test_safety_permission_mismatch_rejected(self):
        files = dict(PLUGIN_FILES)
        # ACTIVE_AGGRESSIVE requires network.listen, which is not declared.
        files["manifest.json"] = files["manifest.json"].replace(
            '"ACTIVE_SAFE"', '"ACTIVE_AGGRESSIVE"'
        )
        self._write(files)
        with self.assertRaises(KSECError) as ctx:
            load_manifest(self.plugin_dir)
        self.assertIn("network.listen", ctx.exception.message)

    def test_versions_validated(self):
        files = dict(PLUGIN_FILES)
        files["manifest.json"] = files["manifest.json"].replace('"1.0.0"', '"abc"')
        self._write(files)
        with self.assertRaises(KSECError):
            load_manifest(self.plugin_dir)

    def test_untrusted_plugin_not_executable(self):
        files = dict(PLUGIN_FILES)
        files["manifest.json"] = files["manifest.json"].replace(
            '"THIRD_PARTY"', '"UNTRUSTED"'
        )
        self._write(files)
        manifest = load_manifest(self.plugin_dir)
        self.assertFalse(manifest.is_executable)


class PluginManagerTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.users = UserRepository(self.ctx.db)
        self.admin = self.users.create("admin", "pw123")
        self.ctx.rbac.assign_role(self.admin.id, "admin")
        self._plugin_src = Path(self.tmp_dir) / "user-plugin"
        self._plugin_src.mkdir()
        for name, content in PLUGIN_FILES.items():
            (self._plugin_src / name).write_text(content, encoding="utf-8")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_bundled_plugin_discovered_and_enabled(self):
        info = self.ctx.plugins.get("ksec.http-headers")
        self.assertIsNotNone(info)
        self.assertEqual(info.source, "bundled")
        self.assertEqual(info.status, "ENABLED")
        self.assertEqual(info.trust_level, "CORE_TRUSTED")
        # Its adapter is registered at bootstrap.
        adapter = self.ctx.adapters.get("http_headers")
        self.assertIsNotNone(adapter)
        self.assertEqual(self.ctx.adapters.plugin_of("http_headers"), "ksec.http-headers")

    def test_bundled_plugin_executable_and_gated(self):
        """The http_headers plugin capability passes the execution gate."""
        plugin = self.ctx.plugins.get("ksec.http-headers")
        self.assertTrue(plugin.executable)
        # The gate permits it: enabled + CORE_TRUSTED + tool.execute declared.
        self.ctx.plugins.assert_capability_allowed("http_headers")

    def test_bundled_plugin_adapter_is_instance(self):
        """Registered plugin adapters are instances, not classes, so the
        scheduler can build commands (regression: class vs instance)."""
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("http_headers")
        self.assertIsNotNone(adapter)
        command = adapter.build_command(
            CommandRequest(capability="http_headers", target="example.com")
        )
        self.assertEqual(command[0], "curl")
        self.assertTrue(any("example.com" in part for part in command))

    def test_install_copies_and_registers(self):
        info = self.ctx.plugins.install(
            self._plugin_src, trust_level="THIRD_PARTY", installed_by="admin", approve=True
        )
        self.assertEqual(info.plugin_id, "test.example-probe")
        self.assertEqual(info.status, "ENABLED")
        self.assertTrue(info.executable)
        # Copied under data_dir/plugins.
        stored = Path(info.path)
        self.assertTrue(stored.is_dir())
        self.assertTrue((stored / MANIFEST_NAME).is_file())
        self.assertIn(str(Path(self.ctx.config.data_dir) / "plugins"), str(stored))

    def test_install_requires_approval_to_enable(self):
        info = self.ctx.plugins.install(
            self._plugin_src, trust_level="THIRD_PARTY", installed_by="admin", approve=False
        )
        self.assertEqual(info.status, "INSTALLED")
        self.assertFalse(info.executable)

    def test_double_install_rejected(self):
        self.ctx.plugins.install(
            self._plugin_src, trust_level="THIRD_PARTY", installed_by="admin", approve=True
        )
        with self.assertRaises(KSECError):
            self.ctx.plugins.install(
                self._plugin_src, trust_level="THIRD_PARTY", installed_by="admin"
            )

    def test_disable_unregisters_adapter(self):
        self.ctx.plugins.install(
            self._plugin_src, trust_level="THIRD_PARTY", installed_by="admin", approve=True
        )
        self.assertIsNotNone(self.ctx.adapters.get("example_probe"))
        self.ctx.plugins.set_status("test.example-probe", "DISABLED", actor="admin")
        self.assertIsNone(self.ctx.adapters.get("example_probe"))
        # Re-enable registers again.
        self.ctx.plugins.set_status("test.example-probe", "ENABLED", actor="admin")
        self.assertIsNotNone(self.ctx.adapters.get("example_probe"))

    def test_uninstall_removes_from_disk(self):
        info = self.ctx.plugins.install(
            self._plugin_src, trust_level="THIRD_PARTY", installed_by="admin", approve=True
        )
        self.ctx.plugins.uninstall("test.example-probe", actor="admin")
        self.assertFalse(Path(info.path).exists())
        self.assertIsNone(self.ctx.plugins.get("test.example-probe"))
        self.assertIsNone(self.ctx.adapters.get("example_probe"))

    def test_cannot_uninstall_bundled(self):
        with self.assertRaises(KSECError):
            self.ctx.plugins.uninstall("ksec.http-headers")

    def test_execution_gate_blocks_disabled_plugin(self):
        """Gate guards the race where the registry still holds the adapter but
        the plugin's status was changed (e.g. by another process)."""
        self.ctx.plugins.install(
            self._plugin_src, trust_level="THIRD_PARTY", installed_by="admin", approve=True
        )
        # Flip the DB status directly without unregistering, simulating a
        # stale in-memory registry after an external disable/block.
        self.ctx.db.execute(
            "UPDATE plugin_registry SET status = 'DISABLED' WHERE plugin_id = ?",
            ("test.example-probe",),
        )
        with self.assertRaises(KSECError) as exc:
            self.ctx.plugins.assert_capability_allowed("example_probe")
        self.assertIn("DISABLED", exc.exception.message)

    def test_execution_gate_allows_builtin(self):
        # Built-in capabilities have no plugin owner: always allowed.
        self.ctx.plugins.assert_capability_allowed("dns_lookup")
        self.ctx.plugins.assert_capability_allowed("port_scan")

    def test_check_reports_health(self):
        results = self.ctx.plugins.check()
        bundled = [r for r in results if r["plugin_id"] == "ksec.http-headers"]
        self.assertTrue(bundled)
        self.assertTrue(bundled[0]["ok"])
        self.assertTrue(bundled[0]["hash_matches"])
        self.assertTrue(bundled[0]["adapters_loaded"])

    def test_tamper_detection(self):
        info = self.ctx.plugins.install(
            self._plugin_src, trust_level="THIRD_PARTY", installed_by="admin", approve=True
        )
        plugin_path = Path(info.path)
        # Modify the manifest after install -> hash no longer matches.
        manifest_path = plugin_path / MANIFEST_NAME
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["description"] = "tampered"
        manifest_path.write_text(json.dumps(data), encoding="utf-8")
        results = self.ctx.plugins.check()
        plugin_result = [r for r in results if r["plugin_id"] == "test.example-probe"][0]
        self.assertFalse(plugin_result["hash_matches"])
        self.assertFalse(plugin_result["ok"])

    def test_audit_records_install(self):
        self.ctx.plugins.install(
            self._plugin_src, trust_level="THIRD_PARTY", installed_by="admin", approve=True
        )
        events = self.ctx.audit.list(event_type="plugin.install")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["target"], "test.example-probe")


class PluginCliTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.users = UserRepository(self.ctx.db)
        self.admin = self.users.create("admin", "pw123")
        self.ctx.rbac.assign_role(self.admin.id, "admin")
        self._plugin_src = Path(self.tmp_dir) / "cli-plugin"
        self._plugin_src.mkdir()
        for name, content in PLUGIN_FILES.items():
            (self._plugin_src / name).write_text(content, encoding="utf-8")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _common(self, **overrides):
        defaults = dict(json=True, quiet=False, user="admin", password="pw123")
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_plugin_list_cli(self):
        from ksec.cli.plugin import cmd_plugin_list

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_plugin_list(self.ctx, self._common())
        self.assertEqual(code, 0)
        data = json.loads(buffer.getvalue())
        ids = [p["plugin_id"] for p in data]
        self.assertIn("ksec.http-headers", ids)

    def test_plugin_install_cli_requires_approval(self):
        from ksec.cli.plugin import cmd_plugin_install

        args = SimpleNamespace(
            path=str(self._plugin_src), trust="THIRD_PARTY", user="admin",
            password="pw123", yes=False, json=True, quiet=False,
        )
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_plugin_install(self.ctx, args)
        self.assertEqual(code, 1)
        data = json.loads(buffer.getvalue())
        self.assertIn("requests trust level", data["message"])
        self.assertIn("rerun with --yes", data["message"])

    def test_plugin_install_cli_with_yes(self):
        from ksec.cli.plugin import cmd_plugin_install

        args = SimpleNamespace(
            path=str(self._plugin_src), trust="THIRD_PARTY", user="admin",
            password="pw123", yes=True, json=True, quiet=False,
        )
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_plugin_install(self.ctx, args)
        self.assertEqual(code, 0)
        data = json.loads(buffer.getvalue())
        self.assertTrue(data["installed"])
        self.assertEqual(data["status"], "ENABLED")

    def test_plugin_check_cli(self):
        from ksec.cli.plugin import cmd_plugin_check

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_plugin_check(self.ctx, self._common())
        self.assertEqual(code, 0)
        data = json.loads(buffer.getvalue())
        self.assertTrue(all(r["ok"] for r in data))

    def test_non_admin_cannot_manage(self):
        from ksec.cli.plugin import cmd_plugin_install

        operator = self.users.create("operator", "pw123")
        self.ctx.rbac.assign_role(operator.id, "operator")
        args = SimpleNamespace(
            path=str(self._plugin_src), trust="THIRD_PARTY", user="operator",
            password="pw123", yes=True, json=True, quiet=False,
        )
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_plugin_install(self.ctx, args)
        self.assertEqual(code, 1)
        data = json.loads(buffer.getvalue())
        self.assertIn("authorization denied", data["error"])


class ScaffoldTest(KsecTestCase):
    """ksec plugin new — generated skeleton validates out of the box."""

    def setUp(self):
        super().setUp()
        from ksec.plugins.scaffold import scaffold_plugin

        self.scaffold = scaffold_plugin
        self.base = Path(self.tmp_dir) / "gen"

    def test_scaffold_creates_valid_plugin(self):
        path = self.scaffold(
            "http-headers",
            target_dir=self.base,
            capability="http-headers",
            tool="curl",
            category="web",
            author="REBEL",
        )
        self.assertTrue((path / MANIFEST_NAME).is_file())
        self.assertTrue((path / "adapter.py").is_file())
        self.assertTrue((path / "parser.py").is_file())
        manifest = load_manifest(path)
        self.assertEqual(manifest.id, "http-headers")
        # Capability normalized to core underscore convention.
        self.assertEqual(manifest.capabilities, ("http_headers",))
        self.assertEqual(manifest.adapters[0].capability, "http_headers")
        self.assertIn("tool.execute", manifest.permissions)

    def test_scaffold_adapter_and_parser_importable(self):
        path = self.scaffold(
            "port-probe", target_dir=self.base, tool="nc", category="network"
        )
        import importlib.util

        for module, class_suffix in (("adapter.py", "Adapter"), ("parser.py", "Parser")):
            spec = importlib.util.spec_from_file_location(
                f"scaffold_{module.replace('.', '_')}", path / module
            )
            module_obj = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module_obj)
            class_name = "PortProbe" + class_suffix
            cls = getattr(module_obj, class_name)
            self.assertTrue(cls)

    def test_scaffold_rejects_bad_input(self):
        with self.assertRaises(KSECError):
            self.scaffold("!!!", target_dir=self.base)  # no slugifiable id
        with self.assertRaises(KSECError):
            self.scaffold("ok", target_dir=self.base, category="nope")
        with self.assertRaises(KSECError):
            self.scaffold("ok", target_dir=self.base, safety="BANANAS")
        with self.assertRaises(KSECError):
            self.scaffold("ok", target_dir=self.base, trust_level="ROOT")

    def test_scaffold_refuses_existing_dir(self):
        path = self.scaffold("dup", target_dir=self.base)
        with self.assertRaises(KSECError):
            self.scaffold("dup", target_dir=self.base)
        self.assertTrue(path.is_dir())

    def test_scaffold_perspective_permissions(self):
        passive = self.scaffold("looker", target_dir=self.base, safety="PASSIVE")
        manifest = load_manifest(passive)
        self.assertIn("filesystem.read", manifest.permissions)
        self.assertNotIn("tool.execute", manifest.permissions)
        aggressive = self.scaffold("hitter", target_dir=self.base, safety="ACTIVE_AGGRESSIVE")
        manifest = load_manifest(aggressive)
        self.assertIn("network.listen", manifest.permissions)


if __name__ == "__main__":
    import unittest

    unittest.main()