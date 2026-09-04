from __future__ import annotations

from ksec.dfir.service import normalize_time
from tests import KsecTestCase


class DfirTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.case = self.ctx.cases.create(title="Incident 42", severity="high")
        self.evidence = self.ctx.evidence.add("raw log line", tool="collector")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_normalize_time(self):
        self.assertEqual(normalize_time("2026-09-04T10:00:00Z"), "2026-09-04T10:00:00+00:00")
        self.assertIsNone(normalize_time("not-a-time"))

    def test_artifact_add_and_list(self):
        artifact = self.ctx.dfir.add_artifact(
            self.case.id,
            "/var/log/auth.log",
            "log",
            host="web-01",
            details="authentication log",
            tool="log2timeline",
            evidence_id=self.evidence.id,
        )
        self.assertEqual(artifact.artifact_type, "log")
        self.assertEqual(artifact.evidence_id, self.evidence.id)
        artifacts = self.ctx.dfir.list_artifacts(case_id=self.case.id)
        self.assertEqual(len(artifacts), 1)
        by_host = self.ctx.dfir.list_artifacts(host="web-01")
        self.assertEqual(len(by_host), 1)

    def test_invalid_artifact_rejected(self):
        with self.assertRaises(ValueError):
            self.ctx.dfir.add_artifact(self.case.id, "x", "not-a-type")
        with self.assertRaises(ValueError):
            self.ctx.dfir.add_artifact(self.case.id, "", "log")

    def test_timeline_is_chronological(self):
        self.ctx.dfir.add_event(
            self.case.id, "2026-09-04T09:00:00Z", "login", actor="alice"
        )
        self.ctx.dfir.add_event(
            self.case.id, "2026-09-04T08:00:00Z", "auth_failure", actor="alice",
            details="brute force",
        )
        self.ctx.dfir.add_event(
            self.case.id, "2026-09-04T10:00:00Z", "exfiltration",
            details="large outbound transfer",
        )
        timeline = self.ctx.dfir.timeline(case_id=self.case.id)
        self.assertEqual(len(timeline), 3)
        times = [e.event_time for e in timeline]
        self.assertEqual(times, sorted(times))
        self.assertEqual(timeline[0].event_type, "auth_failure")

    def test_timeline_filters(self):
        self.ctx.dfir.add_event(self.case.id, "2026-09-04T09:00:00Z", "login")
        self.ctx.dfir.add_event(self.case.id, "2026-09-04T10:00:00Z", "network")
        only_login = self.ctx.dfir.list_events(case_id=self.case.id, event_type="login")
        self.assertEqual(len(only_login), 1)
        since = self.ctx.dfir.list_events(case_id=self.case.id, since="2026-09-04T09:30:00Z")
        self.assertEqual([e.event_type for e in since], ["network"])

    def test_invalid_event_rejected(self):
        with self.assertRaises(ValueError):
            self.ctx.dfir.add_event(self.case.id, "2026-09-04T09:00:00Z", "nope")
        with self.assertRaises(ValueError):
            self.ctx.dfir.add_event(self.case.id, "yesterday", "login")

    def test_unknown_case_rejected_cleanly(self):
        # Regression: these used to surface a raw sqlite3.IntegrityError.
        with self.assertRaises(ValueError) as exc:
            self.ctx.dfir.add_artifact(999, "probe", "log")
        self.assertIn("Unknown case", str(exc.exception))
        with self.assertRaises(ValueError) as exc:
            self.ctx.dfir.add_event(999, "2026-09-04T09:00:00Z", "login")
        self.assertIn("Unknown case", str(exc.exception))

    def test_unknown_evidence_rejected(self):
        with self.assertRaises(ValueError) as exc:
            self.ctx.dfir.add_artifact(self.case.id, "probe", "log", evidence_id=999)
        self.assertIn("Unknown evidence", str(exc.exception))

    def test_unknown_artifact_rejected(self):
        with self.assertRaises(ValueError) as exc:
            self.ctx.dfir.add_event(
                self.case.id, "2026-09-04T09:00:00Z", "login", artifact_id=999
            )
        self.assertIn("Unknown artifact", str(exc.exception))

    def test_actions_recorded_in_audit(self):
        before = self.ctx.audit.count()
        self.ctx.dfir.add_artifact(self.case.id, "conn.log", "log")
        self.ctx.dfir.add_event(self.case.id, "2026-09-04T09:00:00Z", "login")
        types = [
            r["event_type"]
            for r in self.ctx.audit.list(limit=10)
        ]
        self.assertGreaterEqual(self.ctx.audit.count(), before + 2)
        self.assertIn("dfir.artifact.add", types)
        self.assertIn("dfir.event.add", types)


if __name__ == "__main__":
    import unittest

    unittest.main()