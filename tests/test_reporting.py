from __future__ import annotations

from ksec.risk.engine import calculate_risk
from tests import KsecTestCase


class ReportingTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.engagement = self.ctx.authz.create_engagement("Pentest scope")
        self.ctx.authz.add_authorization(self.engagement.id, "10.0.0.0/8")
        self.ctx.assets.register("10.0.0.5", asset_type="ip", engagement_id=self.engagement.id)
        risk = calculate_risk(severity="high", asset_criticality="high")
        self.ctx.findings.create(
            title="Default SSH credentials",
            severity="high",
            risk=risk,
            recommendation="Rotate credentials",
            engagement_id=self.engagement.id,
        )

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_markdown_report(self):
        report = self.ctx.reports.generate(self.engagement.id, fmt="markdown")
        self.assertIn("# ", report.content)
        self.assertIn("Pentest scope", report.content)
        self.assertIn("10.0.0.0/8", report.content)
        self.assertIn("Default SSH credentials", report.content)
        self.assertIn("Rotate credentials", report.content)

    def test_html_report(self):
        report = self.ctx.reports.generate(self.engagement.id, fmt="html")
        self.assertIn("<html>", report.content)
        self.assertIn("Default SSH credentials", report.content)
        self.assertIn("10.0.0.0/8", report.content)

    def test_invalid_format_rejected(self):
        with self.assertRaises(ValueError):
            self.ctx.reports.generate(self.engagement.id, fmt="odt")

    def test_list_and_get(self):
        first = self.ctx.reports.generate(self.engagement.id, fmt="markdown")
        second = self.ctx.reports.generate(self.engagement.id, fmt="html")
        reports = self.ctx.reports.list()
        self.assertEqual(len(reports), 2)
        fetched = self.ctx.reports.get(first.id)
        self.assertEqual(fetched.format, "markdown")
        self.assertEqual(second.format, "html")


if __name__ == "__main__":
    import unittest

    unittest.main()