"""Tests for the gap-closing round (safety controls, data model completion,
GRC, malware and endpoint modules). All AI-free, stdlib only.
"""
from __future__ import annotations

import json
import os
import pathlib
import tempfile

from ksec.core.errors import KSECError
from tests import KsecTestCase


class EmergencyStopTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_stop_blocks_new_submissions(self):
        result = self.ctx.scheduler.emergency_stop(actor="test")
        self.assertTrue(result["stopped"])
        self.assertTrue(self.ctx.scheduler.is_emergency_stopped())
        with self.assertRaises(KSECError):
            self.ctx.scheduler.submit(capability="test_scan", target="10.0.0.5")

    def test_stop_cancels_queued_jobs(self):
        job = self.ctx.scheduler.submit(capability="test_scan", target="10.0.0.5")
        result = self.ctx.scheduler.emergency_stop(actor="test")
        self.assertIn(job.id, result["cancelled_jobs"])
        updated = self.ctx.jobs.get(job.id)
        self.assertEqual(updated.state, "CANCELLED")

    def test_stop_reset_reopens_submissions(self):
        self.ctx.scheduler.emergency_stop(actor="test")
        self.ctx.scheduler.emergency_stop_clear(actor="test")
        self.assertFalse(self.ctx.scheduler.is_emergency_stopped())
        job = self.ctx.scheduler.submit(capability="test_scan", target="10.0.0.5")
        self.assertIsNotNone(job)

    def test_stop_persists_across_restart(self):
        """The emergency stop survives a fresh bootstrap (process restart)."""
        self.ctx.scheduler.emergency_stop(actor="test")
        self.ctx.close()
        fresh = self.make_context()
        try:
            self.assertTrue(fresh.scheduler.is_emergency_stopped())
            with self.assertRaises(KSECError):
                fresh.scheduler.submit(capability="test_scan", target="10.0.0.5")
        finally:
            fresh.close()


class RateLimitTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context({"safety": {"rate_limit_per_user": 2}})
        from ksec.identity.users import UserRepository

        users = UserRepository(self.ctx.db)
        self.user1 = users.create("user1", "pw1")
        self.user2 = users.create("user2", "pw2")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_per_user_rate_limit_blocks_third_submission(self):
        self.ctx.scheduler.submit(capability="test_scan", target="10.0.0.1", user_id=self.user1.id)
        self.ctx.scheduler.submit(capability="test_scan", target="10.0.0.2", user_id=self.user1.id)
        with self.assertRaises(KSECError):
            self.ctx.scheduler.submit(capability="test_scan", target="10.0.0.3", user_id=self.user1.id)

    def test_rate_limit_is_per_user(self):
        self.ctx.scheduler.submit(capability="test_scan", target="10.0.0.1", user_id=self.user1.id)
        self.ctx.scheduler.submit(capability="test_scan", target="10.0.0.2", user_id=self.user1.id)
        # A different user is not blocked by user 1's limit.
        job = self.ctx.scheduler.submit(capability="test_scan", target="10.0.0.3", user_id=self.user2.id)
        self.assertIsNotNone(job)


class EvidenceCustodyTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_capture_and_verify_record_custody(self):
        evidence = self.ctx.evidence.add("port 22 open", tool="nmap", operator="alice")
        ok, _ = self.ctx.evidence.verify(evidence.id)
        self.assertTrue(ok)
        events = self.ctx.evidence.custody_log(evidence.id)
        actions = [e.action for e in events]
        self.assertIn("CAPTURED", actions)
        self.assertIn("VERIFIED", actions)

    def test_verify_failure_records_integrity_failure(self):
        evidence = self.ctx.evidence.add("intact content", tool="manual", operator="bob")
        # Tamper with the stored content directly (simulates external change).
        self.ctx.db.execute(
            "UPDATE evidence SET content = ? WHERE id = ?",
            ("modified content", evidence.id),
        )
        ok, _ = self.ctx.evidence.verify(evidence.id)
        self.assertFalse(ok)
        events = self.ctx.evidence.custody_log(evidence.id)
        self.assertEqual(events[-1].new_state, "integrity_failure")


class CaseNotesTimelineTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_notes_and_timeline(self):
        case = self.ctx.cases.create(title="incident-1", owner="alice")
        note = self.ctx.cases.add_note(case.id, "first observation", author="alice")
        self.assertIsNotNone(note.id)
        self.assertEqual(len(self.ctx.cases.notes(case.id)), 1)
        events = self.ctx.cases.events(case.id)
        types = [e.event_type for e in events]
        self.assertIn("created", types)
        self.assertIn("note", types)

    def test_reopen_records_reason(self):
        case = self.ctx.cases.create(title="incident-2")
        self.ctx.cases.close(case.id)
        reopened = self.ctx.cases.reopen(case.id, reason="new evidence arrived")
        self.assertEqual(reopened.status, "open")
        events = self.ctx.cases.events(case.id)
        self.assertEqual(events[-1].event_type, "reopen")
        self.assertIn("new evidence", events[-1].details)


class RemediationTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_remediation_lifecycle(self):
        finding = self.ctx.findings.create(title="weak tls", severity="high")
        rem = self.ctx.findings.add_remediation(
            finding.id, description="upgrade tls", owner="ops", priority="high"
        )
        self.assertEqual(rem.status, "open")
        verification = self.ctx.findings.verify_remediation(
            rem.id, method="retest", result="verified", verified_by="analyst"
        )
        self.assertEqual(verification.result, "verified")
        updated = self.ctx.findings.get(finding.id)
        self.assertEqual(updated.status, "verified")

    def test_verify_failed_keeps_finding_open(self):
        finding = self.ctx.findings.create(title="still broken", severity="high")
        rem = self.ctx.findings.add_remediation(finding.id, description="fix")
        self.ctx.findings.verify_remediation(rem.id, result="failed", verified_by="analyst")
        self.assertEqual(self.ctx.findings.get(finding.id).status, "open")

    def test_verifications_list(self):
        finding = self.ctx.findings.create(title="x", severity="low")
        rem = self.ctx.findings.add_remediation(finding.id, description="fix")
        self.ctx.findings.verify_remediation(rem.id, result="verified")
        self.assertEqual(len(self.ctx.findings.verifications(rem.id)), 1)


class GrcTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_frameworks_and_controls(self):
        from ksec.grc.frameworks import controls, frameworks

        fws = frameworks()
        self.assertIn("NIST 800-53", fws)
        self.assertIn("PCI DSS", fws)
        self.assertGreater(len(controls("OWASP")), 0)

    def test_snapshot_stores_evidence_and_audit(self):
        result = self.ctx.grc.snapshot(actor="test")
        self.assertIsNotNone(result["evidence_id"])
        self.assertGreater(len(result["payload"]["checks"]), 0)
        events = self.ctx.audit.list(event_type="grc.snapshot")
        self.assertEqual(len(events), 1)

    def test_status_counts(self):
        data = self.ctx.grc.status()
        self.assertIn("passed", data)
        self.assertIn("failed", data)
        self.assertIn("controls", data)


class MalwareTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _write_sample(self, content: bytes) -> str:
        path = os.path.join(self.tmp_dir, "sample.bin")
        with open(path, "wb") as fh:
            fh.write(content)
        return path

    def test_analyze_pe_sample(self):
        # Minimal MZ+PE header stub: e_lfanew (at 0x3C) = 0x40, then the PE
        # signature at 0x40 followed by machine=0x14c (x86) at 0x44.
        stub = (b"MZ" + b"\x00" * 0x3A + b"\x40\x00\x00\x00"
                + b"PE\x00\x00" + b"\x4c\x01" + b"\x00" * 100)
        path = self._write_sample(stub)
        result = self.ctx.malware.analyze(path, actor="test")
        self.assertEqual(result.file_format, "PE")
        self.assertEqual(result.pe_machine, "x86")
        self.assertEqual(len(result.sha256), 64)

    def test_analyze_registers_iocs_and_evidence(self):
        path = self._write_sample(b"#!/bin/sh\necho evil-c2.top\nexfil data\n" * 10)
        result = self.ctx.malware.analyze(path, actor="test")
        iocs = self.ctx.intel.list_iocs(ioc_type="HASH")
        self.assertGreaterEqual(len(iocs), 3)  # sha256 + sha1 + md5
        evidence = self.ctx.evidence.list()
        self.assertGreaterEqual(len(evidence), 1)

    def test_analyze_script_detects_strings(self):
        path = self._write_sample(b"#!/usr/bin/python3\nprint('call home http://c2.example/x')\n")
        result = self.ctx.malware.analyze(path, actor="test")
        self.assertEqual(result.file_format, "SCRIPT")
        self.assertTrue(any("c2.example" in s for s in result.strings_ascii))

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.ctx.malware.analyze(os.path.join(self.tmp_dir, "nope.bin"), actor="test")


class EndpointTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_host_inventory(self):
        host = self.ctx.endpoint.host_inventory()
        self.assertTrue(host.hostname)
        self.assertGreaterEqual(host.cpu_count, 1)
        self.assertIn(host.architecture, ("x86_64", "amd64", "aarch64", "arm64", "armv7l", "i386", "x86", "ppc64le", "s390x", "riscv64", "loongarch64"))

    def test_process_and_user_inventory(self):
        procs = self.ctx.endpoint.processes()
        self.assertGreater(len(procs), 0)
        users = self.ctx.endpoint.users()
        self.assertGreater(len(users), 0)

    def test_check_runs_without_error(self):
        data = self.ctx.endpoint.check(create_findings=False)
        self.assertIn("host", data)
        self.assertIn("observations", data)


class DbCliTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_version_and_health(self):
        from ksec.bootstrap import MIGRATIONS_DIR
        from ksec.cli.db import cmd_db_health, cmd_db_version
        from ksec.db.migrations import MigrationRunner

        runner = MigrationRunner(self.ctx.db, MIGRATIONS_DIR)

        class Args:
            json = True
            quiet = False

        import io
        import sys

        old = sys.stdout
        sys.stdout = io.StringIO()
        try:
            rc = cmd_db_version(self.ctx, Args())
            rc_health = cmd_db_health(self.ctx, Args())
        finally:
            sys.stdout = old
        self.assertEqual(rc, 0)
        self.assertEqual(rc_health, 0)
        latest = max(int(f.name.split("_")[0]) for f in MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.sql"))
        self.assertEqual(runner.current_version(), latest)

    def test_repair_without_yes_reports_but_returns_ok_when_healthy(self):
        from ksec.cli.db import cmd_db_repair

        class Args:
            json = True
            quiet = False
            yes = False

        import io
        import sys

        old = sys.stdout
        sys.stdout = io.StringIO()
        try:
            rc = cmd_db_repair(self.ctx, Args())
        finally:
            sys.stdout = old
        self.assertEqual(rc, 0)


class ExportTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_export_findings_and_evidence(self):
        from ksec.cli.export import cmd_export_evidence, cmd_export_findings

        self.ctx.findings.create(title="tls weak", severity="high")
        self.ctx.evidence.add("output", tool="nmap", operator="alice")

        import io
        import sys

        class Args:
            engagement = None
            out = None
            json = True
            quiet = False

        out_buf = io.StringIO()
        old = sys.stdout
        sys.stdout = out_buf
        try:
            rc_f = cmd_export_findings(self.ctx, Args())
            rc_e = cmd_export_evidence(self.ctx, Args())
        finally:
            sys.stdout = old
        self.assertEqual(rc_f, 0)
        self.assertEqual(rc_e, 0)
        # Both exports are valid JSON with a source field. The CLI prints one
        # indented JSON document per export, so parse them separately.
        captured = out_buf.getvalue().strip()
        docs = json.JSONDecoder().raw_decode(captured)[0]
        self.assertIn("source_system", docs)
        self.assertIn("records", docs)
        # A second export follows the first (whitespace + another document).
        rest = captured[json.JSONDecoder().raw_decode(captured)[1]:].strip()
        self.assertTrue(rest)
        second = json.JSONDecoder().raw_decode(rest)[0]
        self.assertIn("source_system", second)

    def test_export_case_unknown(self):
        from ksec.cli.export import cmd_export_case

        class Args:
            case = 999
            out = None
            json = True
            quiet = False

        import io
        import sys

        old = sys.stdout
        sys.stdout = io.StringIO()
        try:
            rc = cmd_export_case(self.ctx, Args())
        finally:
            sys.stdout = old
        self.assertEqual(rc, 1)

class TimeBoundEngagementTest(KsecTestCase):
    """Time-bound authorization windows (spec 06#54)."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_engagement_with_no_window_is_active(self):
        eng = self.ctx.authz.create_engagement("always")
        self.assertEqual(eng.window_status, "no-window")

    def test_future_window_not_yet_valid(self):
        eng = self.ctx.authz.create_engagement(
            "future", valid_from="2999-01-01", valid_until="2999-12-31"
        )
        self.assertEqual(eng.window_status, "not-yet-valid")
        ok, reason = self.ctx.authz.is_target_authorized(eng.id, "10.0.0.5")
        self.assertFalse(ok)
        self.assertIn("not valid until", reason)

    def test_past_window_expired(self):
        eng = self.ctx.authz.create_engagement(
            "past", valid_until="2020-01-01"
        )
        self.assertEqual(eng.window_status, "expired")
        ok, reason = self.ctx.authz.is_target_authorized(eng.id, "10.0.0.5")
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_open_window_allows_scope_match(self):
        eng = self.ctx.authz.create_engagement(
            "current", valid_until="2999-12-31"
        )
        self.ctx.authz.add_authorization(eng.id, "10.0.0.0/8")
        ok, reason = self.ctx.authz.is_target_authorized(eng.id, "10.0.0.5")
        self.assertTrue(ok, reason)

    def test_invalid_timestamp_rejected(self):
        with self.assertRaises(Exception):
            self.ctx.authz.create_engagement("bad", valid_until="not-a-date")


class LabModeTest(KsecTestCase):
    """Lab/CTF mode restricts targets to lab ranges (spec 06#56)."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context(
            {"safety": {"lab_mode": True}}
        )
        self.user = self._admin()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _admin(self):
        from ksec.identity.users import UserRepository

        users = UserRepository(self.ctx.db)
        user = users.create("labadmin", "lab123", display_name="Lab Admin")
        self.ctx.rbac.assign_role(user.id, "admin")
        return user

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context({"safety": {"lab_mode": True}})
        self.user = self._admin()
        # A lab-scoped engagement so policy reaches the lab gate (the scope
        # check runs before it, as in the real CLI flow).
        self.eng = self.ctx.authz.create_engagement("lab")
        self.ctx.authz.add_authorization(self.eng.id, "*")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _admin(self):
        from ksec.identity.users import UserRepository

        users = UserRepository(self.ctx.db)
        user = users.create("labadmin", "lab123", display_name="Lab Admin")
        self.ctx.rbac.assign_role(user.id, "admin")
        return user

    def _decision(self, target):
        return self.ctx.policy.evaluate(
            user=self.user,
            action="recon.run",
            target=target,
            engagement_id=self.eng.id,
        )

    def test_public_target_denied(self):
        result = self._decision("example.com")
        self.assertNotEqual(result.decision.value, "ALLOW")
        self.assertIn("Lab/CTF", result.reason)

    def test_private_ip_allowed(self):
        result = self._decision("10.0.0.5")
        self.assertEqual(result.decision.value, "ALLOW")

    def test_lab_hostname_allowed(self):
        result = self._decision("vulnlab.test")
        self.assertEqual(result.decision.value, "ALLOW")

    def test_lab_off_public_allowed(self):
        from ksec.identity.users import UserRepository

        ctx = self.make_context({"safety": {"lab_mode": False}})
        try:
            users = UserRepository(ctx.db)
            user = users.create("openadmin", "open123")
            ctx.rbac.assign_role(user.id, "admin")
            eng = ctx.authz.create_engagement("lab")
            ctx.authz.add_authorization(eng.id, "*")
            result = ctx.policy.evaluate(
                user=user,
                action="recon.run",
                target="example.com",
                engagement_id=eng.id,
            )
            # Without lab mode the public target passes policy.
            self.assertNotIn("Lab/CTF", result.reason)
            self.assertEqual(result.decision.value, "ALLOW")
        finally:
            ctx.close()


class WorkflowDagTest(KsecTestCase):
    """Workflow DAG dependencies, retry and versioning (spec 07)."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.store = self.ctx.workflow_store

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_workflow_with_depends_on_created_at_version_1(self):
        wf = self.store.create(
            "dagflow",
            [
                {"capability": "dns_lookup", "name": "step1"},
                {"capability": "port_scan", "name": "step2", "depends_on": ["step1"]},
            ],
        )
        self.assertEqual(wf.version, 1)

    def test_edit_bumps_version(self):
        self.store.create("dagflow", [{"capability": "dns_lookup", "name": "step1"}])
        updated = self.store.update("dagflow", description="changed")
        self.assertEqual(updated.version, 2)

    def test_cycle_rejected(self):
        with self.assertRaises(KSECError) as cm:
            self.store.create(
                "cyclic",
                [
                    {"capability": "dns_lookup", "name": "a", "depends_on": ["b"]},
                    {"capability": "port_scan", "name": "b", "depends_on": ["a"]},
                ],
            )
        self.assertIn("cycle", str(cm.exception))

    def test_unknown_dep_rejected(self):
        with self.assertRaises(KSECError) as cm:
            self.store.create(
                "baddep",
                [{"capability": "dns_lookup", "name": "a", "depends_on": ["ghost"]}],
            )
        self.assertIn("ghost", str(cm.exception))

    def test_to_definition_preserves_dag_fields(self):
        wf = self.store.create(
            "dagflow",
            [
                {"capability": "dns_lookup", "name": "s1"},
                {"capability": "port_scan", "name": "s2", "depends_on": ["s1"], "retry": 3, "retry_delay": 2.5},
            ],
        )
        definition = wf.to_definition()
        self.assertEqual(definition.version, 1)
        self.assertEqual(definition.steps[1].depends_on, ("s1",))
        self.assertEqual(definition.steps[1].retry, 3)
        self.assertEqual(definition.steps[1].retry_delay, 2.5)
        snapshot = definition.as_snapshot()
        self.assertEqual(snapshot["steps"][1]["depends_on"], ["s1"])

    def test_topological_order_respects_dependencies(self):
        from ksec.workflows.definitions import WorkflowDefinition, WorkflowStep

        definition = WorkflowDefinition(
            name="dag",
            description="",
            steps=(
                WorkflowStep("dns_lookup", name="first"),
                WorkflowStep("port_scan", name="last", depends_on=("first",)),
                WorkflowStep("http_probe", name="mid", depends_on=("first",)),
            ),
        )
        ordered = self.ctx.workflows._topological_order(definition)
        positions = {step.name: i for i, (idx, step) in enumerate(ordered)}
        self.assertLess(positions["first"], positions["last"])
        self.assertLess(positions["first"], positions["mid"])

    def test_definition_snapshot_version_recorded_in_run(self):
        """An executed run records definition version + immutable snapshot."""
        from ksec.identity.users import UserRepository

        users = UserRepository(self.ctx.db)
        user = users.create("wfuser", "wf123")
        self.ctx.rbac.assign_role(user.id, "admin")
        eng = self.ctx.authz.create_engagement("wf")
        self.ctx.authz.add_authorization(eng.id, "10.0.0.5")
        self.store.create(
            "dagflow",
            [
                {"capability": "test_scan", "name": "s1"},
                {"capability": "test_scan", "name": "s2", "depends_on": ["s1"]},
            ],
        )
        definition = self.store.resolve("dagflow")
        session = self.ctx.sessions.open(user, "RED_TEAM", role_name="admin")
        run = self.ctx.workflows.run(
            definition, user=user, session=session, target="10.0.0.5", engagement_id=eng.id
        )
        self.assertEqual(run.status, "completed")
        rows = self.ctx.workflows.runs()
        self.assertEqual(rows[0]["definition_version"], 1)
        snapshot = json.loads(rows[0]["definition_snapshot"])
        self.assertEqual(snapshot["name"], "dagflow")
        self.assertEqual([s["name"] for s in snapshot["steps"]], ["s1", "s2"])


class SessionSwitchTest(KsecTestCase):
    """ksec session switch / reconnect (spec 07#31-32)."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        from ksec.identity.users import UserRepository

        users = UserRepository(self.ctx.db)
        self.user = users.create("swuser", "sw123")
        self.ctx.rbac.assign_role(self.user.id, "admin")
        self.s1 = self.ctx.sessions.open(self.user, "RED_TEAM", role_name="admin")
        self.s2 = self.ctx.sessions.open(self.user, "BLUE_TEAM", role_name="admin")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_switch_activates_target_and_pauses_others(self):
        switched = self.ctx.sessions.switch(self.user, self.s2.id)
        self.assertEqual(switched.state, "ACTIVE")
        first = self.ctx.sessions.get(self.s1.id)
        self.assertEqual(first.state, "PAUSED")

    def test_reconnect_resumes_paused_session(self):
        self.ctx.sessions.switch(self.user, self.s2.id)
        reconnected = self.ctx.sessions.reconnect(self.user, self.s1.id)
        self.assertEqual(reconnected.state, "ACTIVE")

    def test_switch_rejects_foreign_session(self):
        from ksec.core.errors import SessionError

        users = self.ctx.rbac.db  # noqa - keep reference pattern simple
        from ksec.identity.users import UserRepository

        other_repo = UserRepository(self.ctx.db)
        other = other_repo.create("other", "other123")
        self.ctx.rbac.assign_role(other.id, "operator")
        foreign = self.ctx.sessions.open(other, "LEARN_WORK", role_name="operator")
        with self.assertRaises(SessionError):
            self.ctx.sessions.switch(self.user, foreign.id)


class ModeCliTest(KsecTestCase):
    """ksec mode status + set toggling the config file."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _run(self, argv):
        from ksec.main import build_parser

        parser = build_parser()
        args = parser.parse_args(argv)
        return args.func(self.ctx, args)

    def test_mode_status_lists_safety_flags(self):
        import io
        import sys

        from ksec.cli.mode import cmd_mode_status

        class Args:
            json = True
            quiet = False
            mode = None

        buffer = io.StringIO()
        old = sys.stdout
        sys.stdout = buffer
        try:
            rc = cmd_mode_status(self.ctx, Args())
        finally:
            sys.stdout = old
        self.assertEqual(rc, 0)
        data = json.loads(buffer.getvalue())
        self.assertIn("lab_mode", data["safety"])

    def test_mode_toggle_writes_config_and_reloads(self):
        from ksec.config.loader import KsecConfig

        path = self.ctx.config.source or pathlib.Path(self.tmp_dir) / "config.toml"
        from ksec.cli.mode import _toggle_config

        _toggle_config(pathlib.Path(path), "lab_mode", True)
        reloaded = KsecConfig.load()
        self.assertTrue(reloaded.lab_mode)

    def test_mode_set_via_cli_persists_without_duplicate_tables(self):
        """Toggling two keys on the same file keeps one [safety] table."""
        from ksec.cli.mode import _toggle_config

        path = self.ctx.config.source or pathlib.Path(self.tmp_dir) / "config.toml"
        pathlib.Path(path).write_text(
            "[safety]\nsafe_mode = false\n", encoding="utf-8"
        )
        _toggle_config(path, "lab_mode", True)
        _toggle_config(path, "read_only", True)
        text = pathlib.Path(path).read_text(encoding="utf-8")
        self.assertEqual(text.count("[safety]"), 1)
        self.assertIn("lab_mode = true", text)
        self.assertIn("read_only = true", text)


def _suggest(ctx, role):
    from ksec.suggestions.service import suggestions

    return suggestions(ctx, role)


class RoleSuggestionsTest(KsecTestCase):
    """State-aware role suggestions (ksec suggest / role trailers)."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        from ksec.identity.users import UserRepository

        users = UserRepository(self.ctx.db)
        self.user = users.create("sugadmin", "sug123")
        self.ctx.rbac.assign_role(self.user.id, "admin")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_fresh_install_suggests_engagement_first(self):
        data = _suggest(self.ctx, "red")
        steps = [i["step"] for i in data["items"]]
        self.assertEqual(data["role"], "red")
        self.assertTrue(any("engagement" in s.lower() for s in steps))
        # The very first pending step is engagement creation.
        self.assertIn("Create your first engagement", steps[0])

    def test_engagement_created_drops_that_step(self):
        eng = self.ctx.authz.create_engagement("assessment")
        data = _suggest(self.ctx, "red")
        steps = [i["step"] for i in data["items"]]
        self.assertFalse(any("Create your first engagement" == s for s in steps))
        # Now the next gap is scope rules.
        self.assertTrue(any("scope" in s.lower() for s in steps))
        self.assertIn(eng.id, [eng.id])

    def test_fully_scoped_suggests_running_recon(self):
        eng = self.ctx.authz.create_engagement("assessment")
        self.ctx.authz.add_authorization(eng.id, "10.0.0.0/8")
        data = _suggest(self.ctx, "red")
        steps = [i["step"] for i in data["items"]]
        self.assertTrue(any("recon" in s.lower() for s in steps))
        self.assertFalse(any("scope rule" in s.lower() for s in steps))

    def test_learner_role_suggests_lessons(self):
        data = _suggest(self.ctx, "learner")
        steps = " ".join(i["step"].lower() for i in data["items"])
        self.assertIn("lesson", steps)

    def test_blue_role_suggests_siem_demo_when_no_alerts(self):
        data = _suggest(self.ctx, "blue")
        steps = [i["step"] for i in data["items"]]
        self.assertTrue(any("sample telemetry" in s.lower() for s in steps))

    def test_state_reported(self):
        data = _suggest(self.ctx, "red")
        self.assertEqual(data["state"]["users"], 1)
        self.assertIn("tools_ready", data["state"])

    def test_canonical_alias(self):
        from ksec.suggestions.service import canonical_role

        self.assertEqual(canonical_role("black hat"), "blackhat")
        self.assertEqual(canonical_role("osint"), "purple")
        self.assertEqual(canonical_role("RESEARCHER"), "purple")
        self.assertIsNone(canonical_role("nope"))


class ModuleCommandsTest(KsecTestCase):
    """Domain modules: registry, tool readiness, deterministic checks."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_modules_listed(self):
        ids = [m["id"] for m in self.ctx.modules.list_modules()]
        for expected in ("api", "wireless", "cloud", "container", "kubernetes"):
            self.assertIn(expected, ids)

    def test_module_info_tools_ready(self):
        info = self.ctx.modules.info("api")
        self.assertIsNotNone(info)
        self.assertTrue(any(t["name"] == "curl" for t in info["tools"]))

    def test_module_check_deterministic_shape(self):
        payload = self.ctx.modules.check("cloud", actor="test")
        self.assertEqual(payload["module"], "cloud")
        ids = [c["check_id"] for c in payload["checks"]]
        self.assertIn("no_secret_in_cwd", ids)
        self.assertIn("metadata_guard", ids)

    def test_module_check_unknown(self):
        with self.assertRaises(ValueError):
            self.ctx.modules.check("nope")


class PurpleExerciseTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_full_lifecycle(self):
        exercise = self.ctx.purple.create(name="coord", description="red+blue")
        self.assertEqual(exercise.status, "planned")
        started = self.ctx.purple.start(exercise.id)
        self.assertEqual(started.status, "running")
        completed = self.ctx.purple.complete(exercise.id)
        self.assertEqual(completed.status, "completed")
        self.assertEqual(completed.red_findings, 0)

    def test_tallies_findings_and_alerts(self):
        eng = self.ctx.authz.create_engagement("purple-eng")
        self.ctx.findings.create(
            title="issue",
            engagement_id=eng.id,
            severity="high",
        )
        exercise = self.ctx.purple.create(name="tally", engagement_id=eng.id)
        completed = self.ctx.purple.complete(exercise.id)
        self.assertEqual(completed.red_findings, 1)

    def test_summary_after_complete(self):
        exercise = self.ctx.purple.create(name="sum")
        self.ctx.purple.complete(exercise.id)
        summary = self.ctx.purple.summary(exercise.id)
        self.assertIn("detection_coverage", summary)

    def test_unknown_raises(self):
        with self.assertRaises(ValueError):
            self.ctx.purple.complete(999)


class ChangeDetectionTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_baseline_clean_scan(self):
        eng = self.ctx.authz.create_engagement("change-eng")
        baseline = self.ctx.change.create_baseline(name="b", scope="assets", target=str(eng.id))
        self.assertEqual(baseline.scope, "assets")
        scan = self.ctx.change.scan(baseline.id)
        self.assertEqual(scan.status, "clean")
        self.assertEqual(scan.drift, [])

    def test_drift_detected_when_asset_appears(self):
        baseline = self.ctx.change.create_baseline(name="b", scope="assets")
        self.ctx.assets.register("new-host.internal", asset_type="host")
        scan = self.ctx.change.scan(baseline.id)
        self.assertEqual(scan.status, "drift")
        self.assertTrue(any(d["change"] == "added" for d in scan.drift))

    def test_invalid_scope_rejected(self):
        with self.assertRaises(ValueError):
            self.ctx.change.create_baseline(name="bad", scope="wat")

    def test_findings_scope_snapshot(self):
        eng = self.ctx.authz.create_engagement("f")
        self.ctx.findings.create(title="x", engagement_id=eng.id, severity="low")
        baseline = self.ctx.change.create_baseline(name="fb", scope="findings")
        self.assertIn("findings", baseline.snapshot)
        scan = self.ctx.change.scan(baseline.id)
        self.assertEqual(scan.status, "clean")


class JobOpsTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_scheduler_health_shape(self):
        health = self.ctx.scheduler.health()
        self.assertIn("worker_alive", health)
        self.assertIn("queued_jobs", health)
        self.assertIn("emergency_stop", health)

    def test_retry_terminal_job(self):
        job = self.ctx.scheduler.submit(capability="test_scan", target="10.0.0.5")
        self.ctx.scheduler.cancel(job.id)
        retried = self.ctx.scheduler.retry(job.id)
        self.assertNotEqual(retried.id, job.id)
        self.assertEqual(retried.state, "QUEUED")

    def test_retry_running_job_rejected(self):
        job = self.ctx.scheduler.submit(capability="test_scan", target="10.0.0.5")
        with self.assertRaises(KSECError):
            self.ctx.scheduler.retry(job.id)


class ReportPreviewExportTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_render_without_persist(self):
        eng = self.ctx.authz.create_engagement("preview-eng")
        rendered = self.ctx.reports.render(eng.id, fmt="markdown")
        self.assertIn("content", rendered)
        self.assertIn("counts", rendered)
        self.assertEqual(len(self.ctx.reports.list()), 0)  # nothing stored

    def test_pdf_report_generated(self):
        eng = self.ctx.authz.create_engagement("pdf-eng")
        report = self.ctx.reports.generate(eng.id, title="PDF", fmt="pdf")
        self.assertEqual(report.format, "pdf")
        pdf_bytes = self.ctx.reports.to_pdf(report)
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        self.assertIn(b"%%EOF", pdf_bytes)

    def test_invalid_format_rejected(self):
        with self.assertRaises(ValueError):
            self.ctx.reports.generate(None, fmt="odt")


class PracticeDrillsTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        from ksec.identity.users import UserRepository

        repo = UserRepository(self.ctx.db)
        self.user = repo.create("learner", "pw")
        self.ctx.rbac.assign_role(self.user.id, "learner")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_drills_listed(self):
        drills = self.ctx.learning.practice_drills(self.user.id)
        self.assertTrue(len(drills) >= 5)
        ids = [d["drill_id"] for d in drills]
        self.assertIn("practice.scope", ids)

    def test_pass_marks_drill(self):
        self.ctx.learning.practice_pass(self.user.id, "practice.scope")
        drills = self.ctx.learning.practice_drills(self.user.id)
        drill = next(d for d in drills if d["drill_id"] == "practice.scope")
        self.assertEqual(drill["status"], "passed")
        self.assertIsNotNone(drill["passed_at"])

    def test_start_increments_attempts(self):
        self.ctx.learning.practice_start(self.user.id, "practice.recon")
        self.ctx.learning.practice_start(self.user.id, "practice.recon")
        drills = self.ctx.learning.practice_drills(self.user.id)
        drill = next(d for d in drills if d["drill_id"] == "practice.recon")
        self.assertEqual(drill["attempts"], 2)

    def test_unknown_drill_rejected(self):
        with self.assertRaises(ValueError):
            self.ctx.learning.practice_pass(self.user.id, "nope")


class WorkflowTriggerTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_trigger_crud(self):
        trigger = self.ctx.triggers.create(
            name="on-fail", event_type="job.failed", workflow="recon",
            event_glob="*.local", created_by="test",
        )
        self.assertTrue(trigger.enabled)
        self.assertEqual(len(self.ctx.triggers.list()), 1)
        self.assertTrue(self.ctx.triggers.remove(trigger.id))

    def test_matches_glob_and_target_field(self):
        trigger = self.ctx.triggers.create(
            name="crit", event_type="soc.alert.critical", workflow="assess",
            event_glob="10.0.0.*",
        )
        hits = self.ctx.triggers.matches("soc.alert.critical", {"target": "10.0.0.9"})
        self.assertEqual(len(hits), 1)
        hits = self.ctx.triggers.matches("soc.alert.critical", {"target": "other"})
        self.assertEqual(len(hits), 0)

    def test_disabled_trigger_not_matched(self):
        trigger = self.ctx.triggers.create(
            name="off", event_type="job.completed", workflow="recon"
        )
        self.ctx.triggers.set_enabled(trigger.id, False)
        hits = self.ctx.triggers.matches("job.completed", {"target": "*"})
        self.assertEqual(hits, [])


class TopLevelShortcutsTest(KsecTestCase):
    """ksec recon|network|web|research|osint TARGET — top-level workflow aliases."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _shortcut(self, name):
        from ksec.main import build_parser

        parser = build_parser()
        args = parser.parse_args(
            [name, "10.0.0.9", "--user", "admin", "--password", "pw", "--dry-run"]
        )
        self.assertEqual(args.func.__name__, "cmd_workflow_run")
        self.assertEqual(args.name, name)
        return args

    def test_all_shortcuts_parse_to_workflow_run(self):
        for name in ("recon", "network", "web", "research", "osint"):
            self._shortcut(name)

    def test_shortcut_workflows_exist_and_are_policy_gated(self):
        from ksec.identity.users import UserRepository

        user = UserRepository(self.ctx.db).get_by_username("admin")
        for name in ("recon", "network", "web", "research", "osint"):
            definition = self.ctx.workflow_store.resolve(name)
            self.assertIsNotNone(definition, name)
            self.assertTrue(definition.steps)
            # Every step must be a capability the platform knows how to run.
            for step in definition.steps:
                self.assertIsNotNone(self.ctx.adapters.get(step.capability), step.capability)


class ExploitIntelligenceTest(KsecTestCase):
    """Real-world red team: searchsploit/sqlmap/ffuf/nxc integration."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_capabilities_registered(self):
        for cap in ("exploit_search", "sqli_test", "web_fuzz", "smb_cred_test"):
            self.assertIsNotNone(self.ctx.adapters.get(cap), cap)
        known = self.ctx.workflow_store.known_capabilities()
        for cap in ("exploit_search", "sqli_test", "web_fuzz", "smb_cred_test"):
            self.assertIn(cap, known)

    def test_catalog_tools_ready(self):
        found = {t.capability for t in self.ctx.capabilities.definitions()}
        self.assertIn("exploit_search", found)
        self.assertIn("sqli_test", found)
        self.assertIn("web_fuzz", found)
        self.assertIn("smb_cred_test", found)

    def test_searchsploit_adapter_builds_command(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("exploit_search")
        cmd = adapter.build_command(
            CommandRequest(capability="exploit_search", target="apache 2.4.49")
        )
        self.assertEqual(cmd[0], "searchsploit")
        self.assertIn("--json", cmd)

    def test_searchsploit_parser(self):
        from ksec.parsers.searchsploit import SearchsploitParser

        output = '{"RESULTS_EXPLOIT": [{"EDB-ID": "50383", "Title": "Apache 2.4.49 RCE", "Type": "remote", "Platform": "linux", "Codes": "CVE-2021-41773", "Verified": "1"}]}'
        result = SearchsploitParser().parse(output)
        self.assertEqual(len(result.entities), 1)
        entity = result.entities[0]
        self.assertEqual(entity["type"], "exploit")
        self.assertEqual(entity["edb_id"], "50383")
        self.assertIn("CVE-2021-41773", entity["cve"])
        self.assertTrue(entity["verified"])

    def test_sqlmap_adapter_and_parser(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("sqli_test")
        cmd = adapter.build_command(
            CommandRequest(capability="sqli_test", target="example.com")
        )
        self.assertEqual(cmd[0], "sqlmap")
        self.assertIn("--batch", cmd)
        self.assertTrue(any(a.startswith("http://") for a in cmd))

        from ksec.parsers.sqlmap import SqlmapParser

        output = (
            "sqlmap identified the following injection point(s):\n"
            "Parameter: id (GET)\n    Type: boolean-based blind\n"
            "    Title: AND boolean-based blind\n"
            "Parameter: user (POST)\n    Type: UNION query\n"
            "    Title: Generic UNION query\n"
        )
        result = SqlmapParser().parse(output)
        self.assertEqual(len(result.entities), 2)
        self.assertEqual(result.entities[0]["parameter"], "id")
        self.assertEqual(result.entities[0]["injection_type"], "boolean-based blind")

    def test_ffuf_adapter_and_parser(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("web_fuzz")
        cmd = adapter.build_command(
            CommandRequest(capability="web_fuzz", target="example.com")
        )
        self.assertEqual(cmd[0], "ffuf")
        self.assertIn("FUZZ", " ".join(cmd))

        from ksec.parsers.ffuf import FfufParser

        result = FfufParser().parse(
            '{"results": [{"url": "http://example.com/admin", "status": 200, "length": 123}]}'
        )
        self.assertEqual(len(result.entities), 1)
        self.assertEqual(result.entities[0]["status"], 200)

    def test_nxc_adapter_and_parser(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("smb_cred_test")
        cmd = adapter.build_command(
            CommandRequest(
                capability="smb_cred_test", target="10.0.0.5",
                options={"user": "admin", "password": "pw"},
            )
        )
        self.assertEqual(cmd[0], "nxc")
        self.assertIn("-u", cmd)

        from ksec.parsers.nxc import NxcParser

        output = (
            "SMB         10.0.0.5     445    HOST1     [*] Windows 10\n"
            "SMB         10.0.0.5     445    HOST1     [+] HOST1\\admin:pw (Pwn3d!)\n"
        )
        result = NxcParser().parse(output)
        self.assertTrue(any(e["type"] == "auth_finding" and e.get("admin") for e in result.entities))

    def test_exploit_lookup_workflow_defined(self):
        definition = self.ctx.workflow_store.resolve("exploit_lookup")
        self.assertIsNotNone(definition)
        caps = [s.capability for s in definition.steps]
        self.assertIn("exploit_search", caps)

    def test_exploit_map_creates_findings_for_verified(self):
        from ksec.identity.users import UserRepository

        repo = UserRepository(self.ctx.db)
        user = repo.create("red", "pw")
        self.ctx.rbac.assign_role(user.id, "operator")
        eng = self.ctx.authz.create_engagement("exploit-eng")

        import subprocess

        def fake_run(*args, **kwargs):
            return subprocess.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout=(
                    '{"RESULTS_EXPLOIT": [{"EDB-ID": "42", "Title": "T", "Type": "remote",'
                    ' "Platform": "linux", "Codes": "CVE-2021-1", "Verified": "1"}]}'
                ),
            )

        import ksec.cli.exploit as exploit_cli

        original = subprocess.run
        subprocess.run = fake_run
        try:
            from ksec.cli.exploit import cmd_exploit_map
            from types import SimpleNamespace

            args = SimpleNamespace(
                query="anything", engagement=eng.id, user="red", password="pw",
                json=False, quiet=False,
            )
            rc = cmd_exploit_map(self.ctx, args)
            self.assertEqual(rc, 0)
        finally:
            subprocess.run = original
        findings = self.ctx.findings.list(engagement_id=eng.id)
        self.assertEqual(len(findings), 1)
        self.assertIn("EDB-42", findings[0].title)


class NucleiCveScanTest(KsecTestCase):
    """nuclei template-based CVE scanning (capability: cve_scan)."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_cve_scan_registered(self):
        self.assertIsNotNone(self.ctx.adapters.get("cve_scan"))
        known = self.ctx.workflow_store.known_capabilities()
        self.assertIn("cve_scan", known)
        found = {t.capability for t in self.ctx.capabilities.definitions()}
        self.assertIn("cve_scan", found)

    def test_adapter_builds_command(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("cve_scan")
        cmd = adapter.build_command(
            CommandRequest(
                capability="cve_scan", target="example.com",
                options={"severity": "high,critical", "rate_limit": 5},
            )
        )
        self.assertEqual(cmd[0], "nuclei")
        self.assertIn("-jsonl", cmd)
        self.assertIn("-severity", cmd)
        joined = " ".join(cmd)
        self.assertIn("http://example.com", joined)

    def test_parser_extracts_cve_matches(self):
        from ksec.parsers.nuclei import NucleiParser

        output = (
            '{"template-id": "cves/2021/CVE-2021-41773", "info": {"name": "Apache 2.4.49 RCE",'
            ' "severity": "critical", "tags": ["apache", "cve"], "classification":'
            ' {"cve-id": ["CVE-2021-41773"], "exploit-db": ["50383"]}},'
            ' "matched-at": "http://example.com/cgi-bin", "matcher-name": "path-traversal"}\n'
            '[INF] nuclei engine started\n'
            '{"template-id": "exposures/configs/aws-keys", "info": {"name": "AWS key exposure",'
            ' "severity": "high"}}\n'
        )
        result = NucleiParser().parse(output)
        self.assertEqual(len(result.entities), 2)  # engine line skipped
        first = result.entities[0]
        self.assertEqual(first["type"], "cve_finding")
        self.assertIn("CVE-2021-41773", first["cve"])
        self.assertEqual(first["severity"], "critical")
        self.assertEqual(first["edb_id"], "50383")

    def test_web_workflow_includes_cve_scan(self):
        definition = self.ctx.workflow_store.resolve("web")
        caps = [s.capability for s in definition.steps]
        self.assertIn("cve_scan", caps)


class AlternateToolAdaptersTest(KsecTestCase):
    """masscan/amass/wfuzz/dnsenum/iwlist/aircrack-ng adapters + parsers."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_adapter_registry_tool_selection(self):
        reg = self.ctx.adapters
        # preferred providers unchanged
        self.assertEqual(reg.get("port_scan").name, "nmap")
        self.assertEqual(reg.get("web_fuzz").name, "ffuf")
        self.assertEqual(reg.get("dns_enum").name, "dnsrecon")
        # tool selection works
        self.assertEqual(reg.get("port_scan", tool="masscan").name, "masscan")
        self.assertEqual(reg.get("web_fuzz", tool="wfuzz").name, "wfuzz")
        self.assertEqual(reg.get("dns_enum", tool="dnsenum").name, "dnsenum")
        self.assertEqual(reg.get("subdomain_enum", tool="amass").name, "amass")
        self.assertEqual(reg.get("wifi_scan", tool="iwlist").name, "iwlist")
        self.assertEqual(reg.get("wifi_crack", tool="aircrack-ng").name, "aircrack-ng")
        # wrong tool for capability falls back to preferred
        self.assertEqual(reg.get("port_scan", tool="ffuf").name, "nmap")

    def test_masscan_build_and_parse(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("port_scan", tool="masscan")
        cmd = adapter.build_command(
            CommandRequest("port_scan", "10.0.0.0/24", {"ports": "1-1024", "rate": 1000})
        )
        self.assertEqual(cmd[0], "masscan")
        self.assertIn("-p", cmd)
        self.assertIn("--rate", cmd)
        parsed = adapter.parse_output(
            '[{"ip": "10.0.0.5", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]}]'
        )
        self.assertEqual(len(parsed.entities), 1)
        self.assertEqual(parsed.entities[0]["addresses"], ["10.0.0.5"])
        self.assertEqual(parsed.entities[0]["ports"][0]["port"], "80")

    def test_amass_build_and_parse(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("subdomain_enum", tool="amass")
        cmd = adapter.build_command(CommandRequest("subdomain_enum", "example.com"))
        self.assertEqual(cmd[0], "amass")
        self.assertIn("-passive", cmd)
        parsed = adapter.parse_output(
            "[DNS] Querying example.com\nmail.example.com\nwww.example.com (FQDN)\napi.example.com.\n"
        )
        names = sorted(e["name"] for e in parsed.entities)
        self.assertEqual(names, ["api.example.com", "mail.example.com", "www.example.com"])

    def test_wfuzz_build_and_parse(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("web_fuzz", tool="wfuzz")
        cmd = adapter.build_command(CommandRequest("web_fuzz", "http://example.com"))
        self.assertEqual(cmd[0], "wfuzz")
        self.assertIn("FUZZ", " ".join(cmd))
        parsed = adapter.parse_output(
            '000000001:   200        12 L      34 W      123 Ch   "admin"\n'
            '000000002:   301        9 L      28 W      194 Ch   "images"\n'
        )
        self.assertEqual(len(parsed.entities), 2)
        self.assertEqual(parsed.entities[0]["status"], 200)

    def test_dnsenum_build_and_parse(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("dns_enum", tool="dnsenum")
        cmd = adapter.build_command(CommandRequest("dns_enum", "example.com"))
        self.assertEqual(cmd[0], "dnsenum")
        parsed = adapter.parse_output(
            "example.com.  300 IN A 93.184.216.34\n"
            "ns1.example.com.  300 IN A 93.184.216.35\n"
        )
        self.assertEqual(len(parsed.entities), 2)
        self.assertEqual(parsed.entities[0]["record_type"], "A")

    def test_iwlist_build_and_parse(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("wifi_scan", tool="iwlist")
        cmd = adapter.build_command(CommandRequest("wifi_scan", "wlan0", {"interface": "wlan0"}))
        self.assertEqual(cmd, ["iwlist", "wlan0", "scan"])
        parsed = adapter.parse_output(
            "Cell 01 - Address: 00:11:22:33:44:55\n"
            "                    Channel:6\n"
            "                    Encryption key:on\n"
            '                    ESSID:"MyNetwork"\n'
            "Cell 02 - Address: AA:BB:CC:DD:EE:FF\n"
            "                    Encryption key:off\n"
            '                    ESSID:"OpenNet"\n'
        )
        self.assertEqual(len(parsed.entities), 2)
        self.assertEqual(parsed.entities[0]["essid"], "MyNetwork")
        self.assertEqual(parsed.entities[1]["encryption"], "off")

    def test_aircrack_build_and_parse(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("wifi_crack", tool="aircrack-ng")
        cmd = adapter.build_command(
            CommandRequest("wifi_crack", "/tmp/hs.cap", {"wordlist": "/usr/share/wordlists/rockyou.txt"})
        )
        self.assertEqual(cmd[0], "aircrack-ng")
        self.assertIn("-w", cmd)
        parsed = adapter.parse_output("                    KEY FOUND! [ mypassword ]\n")
        self.assertEqual(parsed.entities[0]["key"], "mypassword")
        self.assertEqual(parsed.entities[0]["status"], "recovered")

    def test_workflows_include_new_builtins(self):
        from ksec.workflows.definitions import get_workflow

        for name in ("subdomain", "wifi", "fast_scan"):
            wf = get_workflow(name)
            self.assertIsNotNone(wf, name)
        self.assertEqual(
            get_workflow("fast_scan").steps[0].options.get("tool"), "masscan"
        )
        self.assertEqual(get_workflow("wifi").steps[0].capability, "wifi_scan")


class DocxReportExportTest(KsecTestCase):
    """DOCX report export (zero-dependency writer)."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _run_cli(self, args: list[str]) -> tuple[int, str]:
        """Run the ksec CLI in-process with the isolated env."""
        import io
        import sys
        from contextlib import redirect_stdout
        from ksec.main import main

        buf = io.StringIO()
        with redirect_stdout(buf):
            try:
                rc = main(args)
            except SystemExit as exc:
                rc = exc.code or 0
        return int(rc), buf.getvalue()

    def test_docx_generation_valid_zip(self):
        import io
        import zipfile

        report = self.ctx.reports.generate(None, title="Docx Test", fmt="docx")
        self.assertEqual(report.format, "docx")
        data = self.ctx.reports.to_docx(report)
        self.assertGreater(len(data), 500)
        archive = zipfile.ZipFile(io.BytesIO(data))
        names = archive.namelist()
        self.assertIn("word/document.xml", names)
        doc = archive.read("word/document.xml").decode()
        self.assertIn("<w:document", doc)
        self.assertIn("Docx Test", doc)

    def test_docx_cli_create_with_out(self):
        from pathlib import Path

        out = Path(self.tmp_dir) / "report.docx"
        rc, _ = self._run_cli(
            ["report", "create", "--title", "Docx CLI", "--format", "docx",
             "--out", str(out), "--user", "admin"]
        )
        self.assertEqual(rc, 0)
        self.assertTrue(out.exists())
        self.assertGreater(out.stat().st_size, 500)

    def test_docx_export_command(self):
        from pathlib import Path

        report = self.ctx.reports.generate(None, title="Export Me", fmt="docx")
        out = Path(self.tmp_dir) / "exported.docx"
        rc, _ = self._run_cli(
            ["report", "export", str(report.id), "--format", "docx", "--out", str(out)]
        )
        self.assertEqual(rc, 0)
        self.assertTrue(out.exists())
        self.assertGreater(out.stat().st_size, 500)

    def test_catalog_has_new_tools(self):
        from ksec.capabilities.catalog import TOOLS

        names = {t.name for t in TOOLS}
        for expected in ("amass", "wfuzz", "dnsenum", "iwlist", "aircrack-ng"):
            self.assertIn(expected, names)
        caps = {t.capability for t in TOOLS}
        self.assertIn("wifi_scan", caps)
        self.assertIn("wifi_crack", caps)


class ServiceEnumerationAdaptersTest(KsecTestCase):
    """whois/traceroute/john/snmpwalk/onesixtyone/smtp-user-enum adapters."""

    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_all_five_gap_capabilities_registered(self):
        reg = self.ctx.adapters
        for cap in ("whois_lookup", "traceroute", "password_crack", "snmp_enum", "smtp_enum"):
            self.assertIsNotNone(reg.get(cap), cap)

    def test_whois_build_and_parse(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("whois_lookup")
        self.assertEqual(adapter.build_command(CommandRequest("whois_lookup", "example.com")),
                         ["whois", "example.com"])
        parsed = adapter.parse_output(
            "   Domain Name: EXAMPLE.COM\n   Creation Date: 1995-08-14T04:00:00Z\n"
            "   Name Server: NS1.EXAMPLE.COM\n"
        )
        self.assertEqual(parsed.entities[0]["domain"], "example.com")
        self.assertEqual(parsed.entities[0]["name_servers"], ["ns1.example.com"])

    def test_traceroute_build_and_parse(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("traceroute")
        cmd = adapter.build_command(
            CommandRequest("traceroute", "example.com", {"max_hops": 10})
        )
        self.assertEqual(cmd[:3], ["traceroute", "-m", "10"])
        parsed = adapter.parse_output(
            " 1  192.168.100.1 (192.168.100.1)  2.230 ms\n 2  100.127.32.1 (100.127.32.1)  14.8 ms\n"
        )
        self.assertEqual(len(parsed.entities), 2)
        self.assertEqual(parsed.entities[0]["hop"], 1)
        self.assertEqual(parsed.entities[0]["ip"], "192.168.100.1")

    def test_john_build_and_parse(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("password_crack")
        cmd = adapter.build_command(
            CommandRequest("password_crack", "/tmp/hashes.txt", {"wordlist": "/tmp/wl.txt"})
        )
        self.assertEqual(cmd[0], "john")
        self.assertIn("--wordlist=/tmp/wl.txt", cmd)
        parsed = adapter.parse_output("secret123       (admin)\npassword1       (root)\n")
        self.assertEqual(len(parsed.entities), 2)
        self.assertEqual(parsed.entities[0]["username"], "admin")
        self.assertEqual(parsed.entities[0]["password"], "secret123")
        self.assertEqual(parsed.entities[0]["status"], "cracked")

    def test_snmpwalk_build_and_parse(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("snmp_enum")
        cmd = adapter.build_command(CommandRequest("snmp_enum", "10.0.0.1"))
        self.assertEqual(cmd[0], "snmpwalk")
        self.assertIn("public", cmd)
        parsed = adapter.parse_output(
            ".1.3.6.1.2.1.1.1.0 = STRING: Linux demo 5.15.0\n"
            ".1.3.6.1.2.1.1.5.0 = STRING: router01\n"
        )
        self.assertEqual(len(parsed.entities), 2)
        self.assertEqual(parsed.entities[0]["value"], "Linux demo 5.15.0")

    def test_onesixtyone_alternate_for_snmp(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("snmp_enum", tool="onesixtyone")
        self.assertEqual(adapter.name, "onesixtyone")
        cmd = adapter.build_command(CommandRequest("snmp_enum", "10.0.0.1"))
        self.assertEqual(cmd[0], "onesixtyone")
        parsed = adapter.parse_output("10.0.0.1 [public] Linux test 5.4.0\n")
        self.assertEqual(parsed.entities[0]["ip"], "10.0.0.1")
        self.assertEqual(parsed.entities[0]["community"], "public")

    def test_smtp_enum_build_and_parse(self):
        from ksec.adapters.base import CommandRequest

        adapter = self.ctx.adapters.get("smtp_enum")
        cmd = adapter.build_command(
            CommandRequest("smtp_enum", "10.0.0.1", {"mode": "VRFY"})
        )
        self.assertEqual(cmd[0], "smtp-user-enum")
        self.assertIn("VRFY", cmd)
        parsed = adapter.parse_output(
            "10.0.0.1: root exists\n10.0.0.1: jdoe does not exist\n"
        )
        self.assertEqual(len(parsed.entities), 2)
        self.assertEqual(parsed.entities[0]["status"], "exists")
        self.assertEqual(parsed.entities[1]["status"], "not_found")

    def test_enumerate_workflow(self):
        from ksec.workflows.definitions import get_workflow

        wf = get_workflow("enumerate")
        self.assertIsNotNone(wf)
        caps = [s.capability for s in wf.steps]
        self.assertEqual(caps, ["snmp_enum", "smtp_enum"])

    def test_catalog_lists_new_tools(self):
        from ksec.capabilities.catalog import TOOLS

        names = {t.name for t in TOOLS}
        for expected in ("snmpwalk", "onesixtyone", "smtp-user-enum"):
            self.assertIn(expected, names)
        caps = {t.capability for t in TOOLS}
        self.assertIn("snmp_enum", caps)
        self.assertIn("smtp_enum", caps)
