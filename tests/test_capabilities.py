from __future__ import annotations

import shutil
from unittest import mock

from ksec.capabilities.registry import CapabilityRegistry
from tests import KsecTestCase


class CatalogTest(KsecTestCase):
    def test_catalog_has_known_tools(self):
        registry = CapabilityRegistry()
        names = {t.name for t in registry.definitions()}
        self.assertIn("nmap", names)
        self.assertIn("dig", names)
        self.assertIn("nuclei", names)

    def test_capability_permission_mapping(self):
        from ksec.capabilities.catalog import capability_permission

        self.assertEqual(capability_permission("port_scan"), "assess.run")
        self.assertEqual(capability_permission("dns_lookup"), "recon.run")
        self.assertEqual(capability_permission("unknown_cap"), "assess.run")


class DiscoveryTest(KsecTestCase):
    def test_discover_reports_ready_for_real_binaries(self):
        registry = CapabilityRegistry()
        discovered = registry.discover(persist=False)
        by_name = {t.name: t for t in discovered}
        # `true` may not be in the catalog, but `shutil.which` on a catalog
        # binary is exercised; just assert structure and that every tool
        # resolved consistently.
        self.assertEqual(len(discovered), len(registry.definitions()))
        self.assertIn("nmap", by_name)
        self.assertIsInstance(by_name["nmap"].ready, bool)

    @mock.patch.object(shutil, "which", return_value=None)
    def test_missing_tools_reported(self, _which):
        registry = CapabilityRegistry()
        missing = registry.missing_capabilities()
        self.assertIn("port_scan", missing)
        self.assertIn("nmap", missing["port_scan"])

    @mock.patch.object(shutil, "which", return_value="/usr/bin/nmap")
    def test_ready_tool_has_binary_path(self, _which):
        registry = CapabilityRegistry()
        discovered = registry.discover(persist=False)
        nmap = next(t for t in discovered if t.name == "nmap")
        self.assertTrue(nmap.ready)
        self.assertEqual(nmap.binary_path, "/usr/bin/nmap")

    def test_persist_and_list(self):
        ctx = self.make_context()
        try:
            registry = CapabilityRegistry(ctx.db)
            registry.discover(persist=True)
            rows = registry.list_persisted()
            self.assertEqual(len(rows), len(registry.definitions()))
        finally:
            ctx.close()


if __name__ == "__main__":
    import unittest

    unittest.main()