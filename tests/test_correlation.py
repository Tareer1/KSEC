from __future__ import annotations

from tests import KsecTestCase


class CorrelationTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.engagement = self.ctx.authz.create_engagement("corr")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_host_entities_become_assets(self):
        entities = [
            {
                "type": "host",
                "addresses": ["10.0.0.5"],
                "hostnames": ["target.example.com"],
                "ports": [],
            }
        ]
        self.ctx.correlation.ingest_entities(
            entities, tool="nmap", engagement_id=self.engagement.id
        )
        targets = {a.target for a in self.ctx.assets.list(self.engagement.id)}
        self.assertIn("10.0.0.5", targets)
        self.assertIn("target.example.com", targets)

    def test_dns_entities_become_assets(self):
        entities = [
            {"type": "dns_record", "name": "example.com", "record_type": "A", "value": "93.184.216.34"}
        ]
        self.ctx.correlation.ingest_entities(
            entities, tool="dig", engagement_id=self.engagement.id
        )
        targets = {a.target for a in self.ctx.assets.list(self.engagement.id)}
        self.assertIn("example.com", targets)
        self.assertIn("93.184.216.34", targets)

    def test_deduplication(self):
        entities = [
            {"type": "host", "addresses": ["10.0.0.5"], "hostnames": [], "ports": []}
        ] * 3
        self.ctx.correlation.ingest_entities(
            entities, tool="nmap", engagement_id=self.engagement.id
        )
        self.assertEqual(len(self.ctx.assets.list(self.engagement.id)), 1)


if __name__ == "__main__":
    import unittest

    unittest.main()