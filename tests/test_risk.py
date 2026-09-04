from __future__ import annotations

from ksec.risk.engine import RISK_VERSION, calculate_risk, level_for_score
from tests import KsecTestCase


class RiskEngineTest(KsecTestCase):
    def test_deterministic(self):
        kwargs = dict(
            severity="high",
            asset_criticality="high",
            exploitability="high",
            exposure="internet",
            business_impact="critical",
            confidence="high",
            evidence_quality="verified",
        )
        first = calculate_risk(**kwargs)
        second = calculate_risk(**kwargs)
        self.assertEqual(first, second)
        self.assertEqual(first.version, RISK_VERSION)

    def test_high_risk_is_high_or_critical(self):
        result = calculate_risk(
            severity="critical",
            asset_criticality="critical",
            exploitability="high",
            exposure="internet",
            business_impact="critical",
            confidence="high",
            evidence_quality="verified",
        )
        self.assertIn(result.level, ("High", "Critical"))
        self.assertGreaterEqual(result.score, 7.0)

    def test_low_risk_is_low_or_info(self):
        result = calculate_risk(
            severity="info",
            asset_criticality="low",
            exploitability="none",
            exposure="internal",
            business_impact="low",
            confidence="low",
            evidence_quality="none",
        )
        self.assertIn(result.level, ("Info", "Low"))
        self.assertLessEqual(result.score, 4.0)

    def test_unknown_inputs_fall_back(self):
        result = calculate_risk(severity="nonsense", exposure="nonsense")
        self.assertIn(result.level, ("Info", "Low", "Medium"))

    def test_reasoning_includes_version_and_factors(self):
        result = calculate_risk(severity="high", confidence="high")
        self.assertIn(RISK_VERSION, result.reasoning)
        self.assertIn("severity=high", result.reasoning)
        self.assertIn("confidence=high", result.reasoning)

    def test_level_boundaries(self):
        self.assertEqual(level_for_score(9.5), "Critical")
        self.assertEqual(level_for_score(7.5), "High")
        self.assertEqual(level_for_score(5.0), "Medium")
        self.assertEqual(level_for_score(2.5), "Low")
        self.assertEqual(level_for_score(1.0), "Info")


if __name__ == "__main__":
    import unittest

    unittest.main()