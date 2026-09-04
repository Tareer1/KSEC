from __future__ import annotations

from tests import KsecTestCase


class ThreatIntelTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.intel = self.ctx.intel

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_ioc_normalization(self):
        ioc = self.intel.register_ioc("10.0.0.5", "IP", confidence="high")
        self.assertEqual(ioc.normalized_value, "10.0.0.5")
        domain = self.intel.register_ioc("Evil-Example.COM.", "DOMAIN")
        self.assertEqual(domain.normalized_value, "evil-example.com")
        hash_ioc = self.intel.register_ioc("ABC123DEF", "HASH")
        self.assertEqual(hash_ioc.normalized_value, "abc123def")

    def test_register_is_idempotent(self):
        first = self.intel.register_ioc("evil.example.com", "DOMAIN")
        second = self.intel.register_ioc("EVIL.EXAMPLE.COM", "DOMAIN")
        self.assertEqual(first.id, second.id)
        self.assertEqual(len(self.intel.list_iocs()), 1)

    def test_invalid_ioc_rejected(self):
        with self.assertRaises(ValueError):
            self.intel.register_ioc("x", "NOT_A_TYPE")
        with self.assertRaises(ValueError):
            self.intel.register_ioc("x", "IP", confidence="super")

    def test_correlate(self):
        self.intel.register_ioc("10.0.0.5", "IP")
        self.intel.register_ioc("evil.example.com", "DOMAIN")
        self.assertEqual(len(self.intel.correlate("10.0.0.5")), 1)
        self.assertEqual(len(self.intel.correlate("10.0.0.6")), 0)
        self.assertEqual(len(self.intel.correlate("EVIL.EXAMPLE.COM")), 1)

    def test_correlate_finding(self):
        self.intel.register_ioc("evil.example.com", "DOMAIN")
        finding = self.ctx.findings.create(
            title="C2 beaconing observed",
            description="Traffic to evil.example.com from host",
        )
        matches = self.intel.correlate_finding(finding)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].value, "evil.example.com")

    def test_actor_campaign_ttp_links(self):
        actor = self.intel.add_actor("APT-X", aliases=["Group Y"], description="state actor")
        campaign = self.intel.add_campaign("Operation Night", actor_id=actor.id)
        ttp = self.intel.add_ttp("T1059", "Command and Scripting Interpreter", tactic="execution")
        self.intel.link_ttp(campaign.id, ttp.id)
        linked = self.intel.campaign_ttps(campaign.id)
        self.assertEqual([t.technique_id for t in linked], ["T1059"])

    def test_enrich(self):
        actor = self.intel.add_actor("APT-X")
        campaign = self.intel.add_campaign("Op Night", actor_id=actor.id)
        ttp = self.intel.add_ttp("T1059", "Command and Scripting Interpreter")
        self.intel.link_ttp(campaign.id, ttp.id)
        ioc = self.intel.register_ioc("evil.example.com", "DOMAIN", source="research")
        self.intel.link_ioc_actor(ioc.id, actor.id)
        # link campaign via direct update path used by enrichment
        self.ctx.db.execute(
            "UPDATE iocs SET campaign_id = ? WHERE id = ?", (campaign.id, ioc.id)
        )
        self.ctx.findings.create(title="Hit evil.example.com")
        enriched = self.intel.enrich(ioc.id)
        self.assertEqual(enriched["actor"].name, "APT-X")
        self.assertEqual(enriched["campaign"].name, "Op Night")
        self.assertEqual([t.technique_id for t in enriched["ttps"]], ["T1059"])
        self.assertGreaterEqual(len(enriched["related_findings"]), 1)

    def test_actor_duplicate_rejected(self):
        self.intel.add_actor("APT-X")
        with self.assertRaises(ValueError):
            self.intel.add_actor("APT-X")


if __name__ == "__main__":
    import unittest

    unittest.main()