from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from types import SimpleNamespace

from ksec.cli.soc import (
    cmd_soc_alert_action,
    cmd_soc_alert_list,
    cmd_soc_ingest,
    cmd_soc_rule_add,
    cmd_soc_rule_list,
)
from ksec.soc.normalizer import EventNormalizer, normalize_severity
from ksec.soc.rules import RuleStore
from tests import KsecTestCase


class NormalizeTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.normalizer = EventNormalizer()

    def test_canonicalizes_fields(self):
        event = self.normalizer.normalize(
            {
                "event_id": "ev-1",
                "source": "ids",
                "type": "port_scan",
                "severity": 7,
                "ip": "10.0.0.5",
                "domain": "EVIL.EXAMPLE.COM",
                "details": {"src_port": 443},
            }
        )
        self.assertEqual(event.ip, "10.0.0.5")
        self.assertEqual(event.domain, "evil.example.com")
        self.assertEqual(event.event_type, "port_scan")
        self.assertEqual(event.severity, "high")

    def test_severity_mapping(self):
        self.assertEqual(normalize_severity("10"), "critical")
        self.assertEqual(normalize_severity(7), "high")
        self.assertEqual(normalize_severity("warning"), "low")
        self.assertEqual(normalize_severity("garbage"), "medium")

    def test_extracts_ip_from_details(self):
        event = self.normalizer.normalize(
            {"event_id": "ev-2", "event_type": "beacon", "details": {"dst_ip": "198.51.100.9"}}
        )
        self.assertEqual(event.ip, "198.51.100.9")

    def test_missing_required_fields(self):
        with self.assertRaises(ValueError):
            self.normalizer.normalize({"event_type": "x"})
        with self.assertRaises(ValueError):
            self.normalizer.normalize({"event_id": "ev-3"})


class EventStoreTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_ingest_is_idempotent(self):
        event, created = self.ctx.soc_events.ingest(
            {"event_id": "dup-1", "event_type": "login", "severity": "medium"}
        )
        self.assertTrue(created)
        again, created_again = self.ctx.soc_events.ingest(
            {"event_id": "dup-1", "event_type": "login", "severity": "medium"}
        )
        self.assertFalse(created_again)
        self.assertEqual(again.event_id, "dup-1")
        self.assertEqual(len(self.ctx.soc_events.list()), 1)


class RuleEngineTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.rules = RuleStore(self.ctx.db)

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_create_and_match_eq(self):
        rule = self.rules.create("blocked-ip", field="ip", operator="eq", value="10.0.0.5")
        self.assertEqual(rule.name, "blocked-ip")
        event = self.ctx.soc.events.normalizer.normalize(
            {"event_id": "e1", "event_type": "login", "ip": "10.0.0.5"}
        )
        self.assertTrue(rule.matches(event))
        other = self.ctx.soc.events.normalizer.normalize(
            {"event_id": "e2", "event_type": "login", "ip": "10.0.0.6"}
        )
        self.assertFalse(rule.matches(other))

    def test_rule_event_type_filter(self):
        rule = self.rules.create(
            "brute-force", event_type="auth_failure", field="username",
            operator="contains", value="root",
        )
        auth = self.ctx.soc.events.normalizer.normalize(
            {"event_id": "e3", "event_type": "auth_failure", "username": "root"}
        )
        self.assertTrue(rule.matches(auth))
        login = self.ctx.soc.events.normalizer.normalize(
            {"event_id": "e4", "event_type": "login", "username": "root"}
        )
        self.assertFalse(rule.matches(login))

    def test_min_severity_operator(self):
        rule = self.rules.create("gate", operator="min_severity", value="high")
        medium = self.ctx.soc.events.normalizer.normalize(
            {"event_id": "e5", "event_type": "x", "severity": "medium"}
        )
        critical = self.ctx.soc.events.normalizer.normalize(
            {"event_id": "e6", "event_type": "x", "severity": "critical"}
        )
        self.assertFalse(rule.matches(medium))
        self.assertTrue(rule.matches(critical))

    def test_duplicate_name_rejected(self):
        self.rules.create("r1", field="ip")
        from ksec.core.errors import KSECError

        with self.assertRaises(KSECError):
            self.rules.create("r1", field="ip")


class SocPipelineTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        # A known IOC and a known asset enrich the pipeline.
        self.ctx.intel.register_ioc("203.0.113.7", "IP", confidence="high", source="test")
        self.ctx.assets.register("203.0.113.7", asset_type="ip", criticality="critical")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_low_severity_no_rule_no_alert(self):
        report = self.ctx.soc.ingest(
            {"event_id": "soc-1", "source": "firewall", "event_type": "dns",
             "severity": "low", "ip": "10.1.1.1"}
        )
        self.assertTrue(report["created"])
        self.assertFalse(report["alerted"])
        self.assertIn("no rule matched", report["reason_not_alerted"])

    def test_severity_gate_alerts_and_opens_case(self):
        report = self.ctx.soc.ingest(
            {"event_id": "soc-2", "source": "ids", "event_type": "beacon",
             "severity": "high", "ip": "203.0.113.7"}
        )
        self.assertTrue(report["alerted"])
        alert = report["alert"]
        self.assertEqual(alert["asset_id"], 1)  # enriched asset
        self.assertIsNotNone(alert["ioc_id"])    # enriched IOC
        # Risk score raised by asset criticality + IOC confidence
        # (base 7 + critical asset 2 + high IOC 2 => >= 9, escalated).
        self.assertGreaterEqual(alert["risk_score"], 9)
        self.assertEqual(alert["severity"], "critical")  # escalated from high
        case = report["case"]
        self.assertIsNotNone(case)
        self.assertEqual(case["id"], alert["case_id"])
        linked = self.ctx.db.query_one(
            "SELECT case_id FROM alerts WHERE alert_id = ?", (alert["alert_id"],)
        )
        self.assertEqual(linked["case_id"], case["id"])

    def test_rule_fires_alert_with_boost(self):
        self.ctx.soc_rules.create(
            "bad-domain", event_type="dns", field="domain",
            operator="eq", value="malware.example.org", severity="critical",
            risk_boost=1.0,
        )
        report = self.ctx.soc.ingest(
            {"event_id": "soc-3", "source": "siem", "event_type": "dns",
             "severity": "medium", "domain": "malware.example.org"}
        )
        self.assertTrue(report["alerted"])
        alert = report["alert"]
        self.assertEqual(alert["severity"], "critical")
        self.assertIn("bad-domain", alert["source"])
        self.assertIsNotNone(alert["rule_id"])

    def test_correlation_volume_raises_risk(self):
        # Ingest 3 prior medium events on the same IP, then a 4th.
        for i in range(3):
            self.ctx.soc.ingest(
                {"event_id": f"corr-{i}", "source": "firewall",
                 "event_type": "auth_failure", "severity": "medium",
                 "ip": "198.51.100.5"}
            )
        report = self.ctx.soc.ingest(
            {"event_id": "corr-4", "source": "ids", "event_type": "port_scan",
             "severity": "medium", "ip": "198.51.100.5"}
        )
        corr = report["correlation"]
        self.assertGreaterEqual(corr["related_event_count"], 3)
        # Base 4 + volume >=1.0 => >=5; still no rule -> no alert (medium).
        self.assertGreaterEqual(report["risk_score"], 5.0)
        self.assertFalse(report["alerted"])

    def test_duplicate_ingest_no_second_alert(self):
        first = self.ctx.soc.ingest(
            {"event_id": "soc-dup", "event_type": "beacon", "severity": "critical",
             "ip": "203.0.113.7"}
        )
        self.assertTrue(first["alerted"])
        second = self.ctx.soc.ingest(
            {"event_id": "soc-dup", "event_type": "beacon", "severity": "critical",
             "ip": "203.0.113.7"}
        )
        self.assertFalse(second["created"])
        self.assertEqual(self.ctx.soc_alerts.count(), 1)

    def test_alert_lifecycle(self):
        report = self.ctx.soc.ingest(
            {"event_id": "soc-lc", "event_type": "beacon", "severity": "high",
             "ip": "203.0.113.7"}
        )
        alert_id = report["alert"]["id"]
        acked = self.ctx.soc_alerts.acknowledge(alert_id)
        self.assertEqual(acked.status, "acknowledged")
        self.assertIsNotNone(acked.acknowledged_at)
        resolved = self.ctx.soc_alerts.resolve(alert_id)
        self.assertEqual(resolved.status, "resolved")
        self.assertIsNotNone(resolved.resolved_at)


class SocCliTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _ingest_args(self, **overrides):
        defaults = dict(
            event_id=None, source="manual", event_type=None, severity="medium",
            ip=None, domain=None, host=None, username=None, process=None,
            details_json=None, event_json=None, json=True, quiet=False,
        )
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_ingest_cli_json(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_soc_ingest(
                self.ctx,
                self._ingest_args(event_id="cli-1", event_type="login", ip="10.0.0.9"),
            )
        self.assertEqual(code, 0)
        data = json.loads(buffer.getvalue())
        self.assertTrue(data["created"])
        self.assertEqual(data["normalized"]["ip"], "10.0.0.9")

    def test_ingest_event_json_merges_cli_flags(self):
        # Regression: CLI flags used to be silently dropped when
        # --event-json was present, so the event failed intake.
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_soc_ingest(
                self.ctx,
                self._ingest_args(
                    event_id="cli-json-1",
                    source="firewall",
                    event_type="auth_failure",
                    severity="low",
                    ip="203.0.113.9",
                    username="root",
                    event_json='{"src_port": 55123, "proto": "tcp"}',
                ),
            )
        self.assertEqual(code, 0)
        data = json.loads(buffer.getvalue())
        self.assertTrue(data["created"])
        self.assertEqual(data["normalized"]["ip"], "203.0.113.9")
        self.assertEqual(data["normalized"]["username"], "root")

    def test_soc_actions_recorded_in_audit(self):
        report = self.ctx.soc.ingest(
            {"event_id": "aud-soc", "event_type": "beacon", "severity": "high",
             "ip": "203.0.113.7"}
        )
        alert_id = report["alert"]["id"]
        self.ctx.soc_alerts.acknowledge(alert_id)
        self.ctx.cases.close(report["case"]["id"])
        types = [r["event_type"] for r in self.ctx.audit.list(limit=20)]
        self.assertIn("alert.create", types)
        self.assertIn("alert.acknowledged", types)
        self.assertIn("case.create", types)
        self.assertIn("case.status", types)

    def test_rule_add_cli(self):
        args = SimpleNamespace(
            name="cli-rule", description=None, event_type=None, field="ip",
            operator="eq", value="1.2.3.4", severity="high", risk_boost=None,
            no_case=False, json=True, quiet=False,
        )
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_soc_rule_add(self.ctx, args)
        self.assertEqual(code, 0)
        self.assertEqual(len(self.ctx.soc_rules.list()), 1)

    def test_alert_action_cli(self):
        report = self.ctx.soc.ingest(
            {"event_id": "cli-act", "event_type": "beacon", "severity": "critical",
             "ip": "203.0.113.7"}
        )
        alert_id = report["alert"]["id"]
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_soc_alert_action(
                self.ctx,
                SimpleNamespace(action="ack", id=alert_id, case=None, json=True, quiet=False),
            )
        self.assertEqual(code, 0)
        self.assertEqual(self.ctx.soc_alerts.get(alert_id).status, "acknowledged")

    def test_alert_list_cli_empty(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_soc_alert_list(
                self.ctx,
                SimpleNamespace(limit=50, status=None, severity=None, json=True, quiet=False),
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buffer.getvalue()), [])


if __name__ == "__main__":
    import unittest

    unittest.main()