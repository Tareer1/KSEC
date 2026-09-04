from __future__ import annotations

from ksec.authorization.service import AuthorizationService, target_matches
from tests import KsecTestCase


class TargetMatchTest(KsecTestCase):
    def test_exact(self):
        self.assertTrue(target_matches("example.com", "example.com"))
        self.assertFalse(target_matches("example.org", "example.com"))

    def test_wildcard(self):
        self.assertTrue(target_matches("anything", "*"))

    def test_subdomain_suffix(self):
        self.assertTrue(target_matches("sub.example.com", "example.com"))
        self.assertTrue(target_matches("sub.example.com", ".example.com"))
        self.assertFalse(target_matches("example.com", ".example.com"))
        self.assertFalse(target_matches("example.com.evil.com", "example.com"))

    def test_cidr(self):
        self.assertTrue(target_matches("10.0.0.5", "10.0.0.0/8"))
        self.assertTrue(target_matches("192.168.1.1", "192.168.1.0/24"))
        self.assertFalse(target_matches("192.168.2.1", "192.168.1.0/24"))

    def test_url_and_port_forms(self):
        self.assertTrue(target_matches("https://example.com/path", "example.com"))
        self.assertTrue(target_matches("http://sub.example.com:8080/x", "example.com"))
        self.assertTrue(target_matches("example.com:443", "example.com"))
        self.assertTrue(target_matches("10.0.0.5:8080", "10.0.0.0/8"))
        self.assertFalse(target_matches("https://example.org/", "example.com"))

    def test_ipv6_left_intact(self):
        self.assertTrue(target_matches("2001:db8::1", "2001:db8::/32"))


class AuthorizationServiceTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.service = AuthorizationService(self.ctx.db)

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_authorization_lifecycle(self):
        engagement = self.service.create_engagement("Test engagement", "scope test")
        self.service.add_authorization(engagement.id, "10.0.0.0/8")
        self.service.add_authorization(engagement.id, "*.example.com")
        self.service.add_authorization(engagement.id, "192.168.1.10", effect="deny")

        self.assertTrue(self.service.is_target_authorized(engagement.id, "10.1.2.3")[0])
        self.assertTrue(self.service.is_target_authorized(engagement.id, "api.example.com")[0])
        self.assertFalse(self.service.is_target_authorized(engagement.id, "example.org")[0])

    def test_authorization_changes_recorded_in_audit(self):
        # Regression: engagement + scope changes used to be invisible in the
        # audit log even though they change what tools are allowed to run.
        engagement = self.ctx.authz.create_engagement("Audited engagement")
        self.ctx.authz.add_authorization(engagement.id, "example.com", effect="allow")
        self.ctx.authz.add_authorization(engagement.id, "10.0.0.0/8", effect="deny")
        types = [r["event_type"] for r in self.ctx.audit.list(limit=10)]
        self.assertIn("authz.engagement.create", types)
        self.assertIn("authz.scope.add", types)

    def test_no_authorization_denied(self):
        engagement = self.service.create_engagement("Empty")
        authorized, reason = self.service.is_target_authorized(engagement.id, "10.0.0.1")
        self.assertFalse(authorized)
        self.assertIn("no matching", reason)


if __name__ == "__main__":
    import unittest

    unittest.main()