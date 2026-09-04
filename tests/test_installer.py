from __future__ import annotations

from unittest import mock

from ksec.core.errors import KSECError
from tests import KsecTestCase


class InstallerTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.manager = self.ctx.installer

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_find_providers(self):
        providers = self.manager.find_providers("port_scan")
        self.assertTrue(providers)
        self.assertTrue(any(p.name == "nmap" for p in providers))

    def test_unknown_capability_rejected(self):
        with self.assertRaises(KSECError):
            self.manager.plan("no_such_capability")

    @mock.patch("ksec.installer.service.shutil.which", return_value=None)
    def test_dry_run_plan(self, _which):
        plan = self.manager.plan("dns_lookup", dry_run=True)
        self.assertEqual(plan.capability, "dns_lookup")
        self.assertEqual(plan.provider, "dig")
        self.assertEqual(plan.package, "dnsutils")
        self.assertTrue(plan.dry_run)
        self.assertIn("--dry-run", plan.command)

    @mock.patch("ksec.installer.service.shutil.which", return_value=None)
    def test_install_without_approval_refused(self, _which):
        result = self.manager.install("dns_lookup", approved=False)
        self.assertFalse(result.installed)
        self.assertIn("approval", result.message)

    @mock.patch("ksec.installer.service.shutil.which", return_value=None)
    def test_install_dry_run_does_not_install(self, _which):
        result = self.manager.install("dns_lookup", approved=True, dry_run=True)
        self.assertFalse(result.installed)
        self.assertIn("dry-run", result.message)


if __name__ == "__main__":
    import unittest

    unittest.main()