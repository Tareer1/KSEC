from __future__ import annotations

from ksec.identity.users import UserRepository
from ksec.risk.engine import calculate_risk
from tests import KsecTestCase


class AssetServiceTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_register_deduplicates(self):
        first = self.ctx.assets.register("example.com", asset_type="domain")
        second = self.ctx.assets.register("EXAMPLE.COM", asset_type="domain")
        self.assertEqual(first.id, second.id)
        self.assertEqual(len(self.ctx.assets.list()), 1)

    def test_invalid_inputs_rejected(self):
        with self.assertRaises(ValueError):
            self.ctx.assets.register("", asset_type="host")
        with self.assertRaises(ValueError):
            self.ctx.assets.register("x", asset_type="bogus")
        with self.assertRaises(ValueError):
            self.ctx.assets.register("x", criticality="bogus")


class FindingServiceTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_create_and_list_with_risk(self):
        risk = calculate_risk(severity="high", asset_criticality="high")
        finding = self.ctx.findings.create(
            title="Open SSH with default credentials",
            severity="high",
            risk=risk,
        )
        self.assertEqual(finding.status, "open")
        self.assertEqual(finding.risk_level, risk.level)
        self.assertEqual(finding.risk_score, risk.score)

    def test_status_lifecycle(self):
        finding = self.ctx.findings.create(title="x", severity="medium")
        updated = self.ctx.findings.update_status(finding.id, "verified")
        self.assertEqual(updated.status, "verified")
        listed = self.ctx.findings.list(status="verified")
        self.assertEqual([f.id for f in listed], [finding.id])

    def test_filters(self):
        self.ctx.findings.create(title="a", severity="high")
        self.ctx.findings.create(title="b", severity="low")
        self.assertEqual(len(self.ctx.findings.list(severity="high")), 1)


class CaseServiceTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_create_close_and_link_finding(self):
        case = self.ctx.cases.create(title="Incident 1", severity="high", owner="alice")
        finding = self.ctx.findings.create(title="Suspicious login", severity="medium")
        self.ctx.cases.add_finding(case.id, finding.id)
        linked = self.ctx.cases.findings(case.id)
        self.assertEqual([f["id"] for f in linked], [finding.id])
        closed = self.ctx.cases.close(case.id)
        self.assertEqual(closed.status, "closed")


if __name__ == "__main__":
    import unittest

    unittest.main()