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


class DfirHashExportTest(KsecTestCase):
    """Artifact hashing and case chronology export."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.case = self.ctx.cases.create(title="Hash case", severity="medium")
        self.artifact = self.ctx.dfir.add_artifact(
            self.case.id, "collected.bin", "file", tool="collector",
        )

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _sample_file(self, content: bytes) -> str:
        import hashlib
        import os

        path = os.path.join(self.tmp_dir, "evidence.bin")
        with open(path, "wb") as handle:
            handle.write(content)
        return path

    def test_hash_artifact_records_sha256(self):
        import hashlib

        content = b"forensic-copy-data-1234"
        path = self._sample_file(content)
        result = self.ctx.dfir.hash_artifact(self.artifact.id, path)
        self.assertEqual(result["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(result["size"], len(content))
        # Hash block persisted on the artifact details.
        stored = self.ctx.dfir.get_artifact(self.artifact.id)
        self.assertIn("sha256=" + result["sha256"], stored.details)

    def test_hash_unknown_artifact_and_missing_file(self):
        with self.assertRaises(ValueError):
            self.ctx.dfir.hash_artifact(999, "/nonexistent")
        with self.assertRaises(ValueError):
            self.ctx.dfir.hash_artifact(self.artifact.id, "/nonexistent/file")

    def test_chronology_merges_artifacts_and_events_sorted(self):
        self.ctx.dfir.add_event(
            self.case.id, "2026-09-04T10:00:00Z", "executed",
            actor="attacker", details="payload ran",
        )
        rows = self.ctx.dfir.chronology(case_id=self.case.id)
        kinds = [r["kind"] for r in rows]
        self.assertIn("artifact", kinds)
        self.assertIn("event", kinds)
        times = [r["time"] or "" for r in rows]
        self.assertEqual(times, sorted(times))

    def test_export_csv_and_jsonl(self):
        import io
        from contextlib import redirect_stdout
        from types import SimpleNamespace

        from ksec.cli.dfir import cmd_export

        self.ctx.dfir.add_event(
            self.case.id, "2026-09-04T10:00:00Z", "executed", actor="attacker",
        )
        for fmt in ("csv", "jsonl"):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cmd_export(
                    self.ctx,
                    SimpleNamespace(case=self.case.id, format=fmt, out=None,
                                    json=False, quiet=False),
                )
            self.assertEqual(code, 0)
            text = buffer.getvalue()
            self.assertIn("artifact", text)
            self.assertIn("event", text)

    def test_export_to_file(self):
        import os
        from types import SimpleNamespace

        from ksec.cli.dfir import cmd_export

        out = os.path.join(self.tmp_dir, "case.jsonl")
        code = cmd_export(
            self.ctx,
            SimpleNamespace(case=self.case.id, format="jsonl", out=out,
                            json=False, quiet=False),
        )
        self.assertEqual(code, 0)
        with open(out, encoding="utf-8") as handle:
            self.assertTrue(handle.read().strip())

    def test_export_unknown_case(self):
        from types import SimpleNamespace

        from ksec.cli.dfir import cmd_export

        code = cmd_export(
            self.ctx,
            SimpleNamespace(case=999, format="csv", out=None, json=False, quiet=False),
        )
        self.assertEqual(code, 1)


if __name__ == "__main__":
    import unittest

    unittest.main()