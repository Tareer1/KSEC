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
        # Deny wins over allow.
        self.assertFalse(self.service.is_target_authorized(engagement.id, "192.168.1.10")[0])

    def test_no_authorization_denied(self):
        engagement = self.service.create_engagement("Empty")
        authorized, reason = self.service.is_target_authorized(engagement.id, "10.0.0.1")
        self.assertFalse(authorized)
        self.assertIn("no matching", reason)


if __name__ == "__main__":
    import unittest

    unittest.main()