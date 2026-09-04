from __future__ import annotations

from ksec.normalization.service import (
    normalize_cidr,
    normalize_domain,
    normalize_ip,
    normalize_port,
    normalize_target,
)
from tests import KsecTestCase


class NormalizationTest(KsecTestCase):
    def test_ip(self):
        self.assertEqual(normalize_ip(" 10.0.0.1 "), "10.0.0.1")
        self.assertIsNone(normalize_ip("not-an-ip"))
        self.assertIsNone(normalize_ip("999.0.0.1"))
        # Leading zeros are rejected by modern ipaddress (security fix).
        self.assertIsNone(normalize_ip("010.0.0.1"))

    def test_cidr(self):
        self.assertEqual(normalize_cidr("10.0.0.1/24"), "10.0.0.0/24")
        self.assertIsNone(normalize_cidr("10.0.0.1"))

    def test_domain(self):
        self.assertEqual(normalize_domain("Example.COM."), "example.com")
        self.assertEqual(normalize_domain("sub.example.com"), "sub.example.com")
        self.assertIsNone(normalize_domain("not a domain"))
        self.assertIsNone(normalize_domain("10.0.0.1"))

    def test_port(self):
        self.assertEqual(normalize_port("80"), 80)
        self.assertEqual(normalize_port(65535), 65535)
        self.assertIsNone(normalize_port("0"))
        self.assertIsNone(normalize_port("70000"))
        self.assertIsNone(normalize_port("abc"))

    def test_target_classification(self):
        self.assertEqual(normalize_target("10.0.0.5"), ("10.0.0.5", "ip"))
        self.assertEqual(normalize_target("10.0.0.0/24"), ("10.0.0.0/24", "cidr"))
        self.assertEqual(normalize_target("example.com"), ("example.com", "domain"))
        self.assertEqual(normalize_target("https://example.com/x"), ("example.com", "url"))
        self.assertEqual(normalize_target("???"), (None, "host"))


if __name__ == "__main__":
    import unittest

    unittest.main()