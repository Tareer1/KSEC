"""Tests for the "perfect tool" round: recurring schedules, report
executive summary, and actor-attributed SOC audit."""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from datetime import datetime
from types import SimpleNamespace

from ksec.cli.soc import cmd_soc_alert_action
from ksec.reporting.service import ReportService
from ksec.scheduler.schedules import (
    ScheduleStore,
    cron_matches,
    current_cron_minute,
)
from tests import KsecTestCase


class CronMatcherTest(KsecTestCase):
    def test_star_matches_anything(self):
        when = datetime(2026, 9, 4, 6, 0)
        self.assertTrue(cron_matches("* * * * *", when))

    def test_exact_fields(self):
        self.assertTrue(cron_matches("0 6 * * *", datetime(2026, 9, 4, 6, 0)))
        self.assertFalse(cron_matches("0 6 * * *", datetime(2026, 9, 4, 6, 5)))
        self.assertFalse(cron_matches("0 6 * * *", datetime(2026, 9, 4, 7, 0)))

    def test_step_and_lists(self):
        self.assertTrue(cron_matches("*/15 * * * *", datetime(2026, 9, 4, 6, 30)))
        self.assertFalse(cron_matches("*/15 * * * *", datetime(2026, 9, 4, 6, 20)))
        self.assertTrue(cron_matches("0 6 * * 1,3,5", datetime(2026, 9, 7, 6, 0)))  # Monday
        self.assertFalse(cron_matches("0 6 * * 1,3,5", datetime(2026, 9, 5, 6, 0)))  # Saturday

    def test_ranges(self):
        self.assertTrue(cron_matches("0 9-17 * * *", datetime(2026, 9, 4, 12, 0)))
        self.assertFalse(cron_matches("0 9-17 * * *", datetime(2026, 9, 4, 18, 0)))

    def test_bad_cron_never_matches(self):
        self.assertFalse(cron_matches("not a cron", datetime(2026, 9, 4, 6, 0)))

    def test_current_cron_minute_matches_now(self):
        self.assertTrue(cron_matches(current_cron_minute(), datetime.utcnow()))


class ScheduleStoreTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.store = ScheduleStore(self.ctx.db)

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_create_list_remove(self):
        schedule = self.store.create(
            capability="dns_lookup", target="example.com", cron="0 6 * * *"
        )
        self.assertEqual(schedule.cron, "0 6 * * *")
        self.assertTrue(schedule.enabled)
        self.assertEqual(len(self.store.list()), 1)
        self.assertTrue(self.store.remove(schedule.id))
        self.assertEqual(self.store.list(), [])
        self.assertFalse(self.store.remove(999))

    def test_mark_run_updates_last_run_at(self):
        schedule = self.store.create(
            capability="port_scan", target="10.0.0.5", cron="*/5 * * * *"
        )
        self.assertIsNone(schedule.last_run_at)
        self.store.mark_run(schedule.id)
        self.assertIsNotNone(self.store.get(schedule.id).last_run_at)

    def test_scheduler_fires_due_schedule(self):
        schedule = self.store.create(
            capability="test_scan", target="10.0.0.1", cron=current_cron_minute()
        )
        self.ctx.scheduler._run_due_schedules()
        jobs = self.ctx.scheduler.jobs.list()
        self.assertTrue(any(j.capability == "test_scan" for j in jobs))
        # Marked as run: firing again does not duplicate in the same minute.
        self.ctx.scheduler._run_due_schedules()
        again = [j for j in self.ctx.scheduler.jobs.list() if j.capability == "test_scan"]
        self.assertEqual(len(again), 1)


class ReportExecSummaryTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _findings(self):
        from ksec.risk.engine import calculate_risk

        f1 = self.ctx.findings.create(
            title="Critical RCE", severity="critical", description="bad",
            recommendation="patch",
            risk=calculate_risk(severity="critical", exploitability="high", exposure="internet"),
        )
        f2 = self.ctx.findings.create(
            title="Missing HSTS", severity="medium", description="meh",
            recommendation="add header",
            risk=calculate_risk(severity="medium"),
        )
        return [f1, f2]

    def test_markdown_has_executive_summary(self):
        findings = self._findings()
        report = ReportService(
            self.ctx.db, self.ctx.authz, self.ctx.assets,
            self.ctx.findings, self.ctx.evidence, self.ctx.cases,
        )
        md = report._render_markdown(
            "Test report", None, [], [], findings, [], []
        )
        self.assertIn("## Executive Summary", md)
        self.assertIn("Critical RCE", md)
        self.assertIn("1 critical, 1 medium", md)
        self.assertIn("remediate critical/high findings immediately", md)

    def test_empty_report_has_no_summary(self):
        report = ReportService(
            self.ctx.db, self.ctx.authz, self.ctx.assets,
            self.ctx.findings, self.ctx.evidence, self.ctx.cases,
        )
        md = report._render_markdown("Empty", None, [], [], [], [], [])
        self.assertNotIn("Executive Summary", md)


class ActorAuditTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        from ksec.identity.users import UserRepository

        self.users = UserRepository(self.ctx.db)
        self.analyst = self.users.create("analyst", "pw123")
        self.ctx.rbac.assign_role(self.analyst.id, "operator")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _alert(self):
        report = self.ctx.soc.ingest(
            {"event_id": "aud-act", "event_type": "beacon", "severity": "high",
             "ip": "203.0.113.9"}
        )
        return report["alert"]["id"], report["case"]["id"]

    def test_alert_action_records_actor(self):
        alert_id, _ = self._alert()
        buffer = io.StringIO()
        args = SimpleNamespace(
            action="ack", id=alert_id, case=None,
            user="analyst", password="pw123", json=False, quiet=False,
        )
        with redirect_stdout(buffer):
            code = cmd_soc_alert_action(self.ctx, args)
        self.assertEqual(code, 0)
        events = self.ctx.audit.list(event_type="alert.acknowledged")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["actor"], "analyst")

    def test_case_close_records_actor(self):
        _, case_id = self._alert()
        self.ctx.cases.close(case_id, actor="analyst")
        events = self.ctx.audit.list(event_type="case.status")
        self.assertTrue(any(e["actor"] == "analyst" for e in events))

    def test_alert_action_bad_credentials_rejected(self):
        alert_id, _ = self._alert()
        buffer = io.StringIO()
        args = SimpleNamespace(
            action="ack", id=alert_id, case=None,
            user="analyst", password="wrong", json=False, quiet=False,
        )
        with redirect_stdout(buffer):
            code = cmd_soc_alert_action(self.ctx, args)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    import unittest

    unittest.main()