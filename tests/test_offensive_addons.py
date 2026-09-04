"""Tests for the authorized offensive add-ons:

- ``ksec vuln`` deterministic checks (normalization, header logic, gating,
  finding creation, idempotency)
- ``ksec atomic`` red tests (library, policy gate, run path)
- adversary kill-chain ordering + phase reports
- new tool parsers (sslscan/gobuster/nikto) + adapter command building
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

from ksec.adapters.base import CommandRequest
from ksec.adapters.gobuster import GobusterAdapter
from ksec.adapters.nikto import NiktoAdapter
from ksec.adapters.sslscan import SslScanAdapter
from ksec.adversary.service import CHAIN_PHASES, TACTIC_MAP, _chain_index
from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository
from ksec.parsers.gobuster import GobusterParser
from ksec.parsers.nikto import NiktoParser
from ksec.parsers.tls_scan import TlsScanParser
from ksec.redteam import atomics
from ksec.vuln import checks as checklib
from tests import KsecTestCase


def _operator(ctx) -> SimpleNamespace:
    users = UserRepository(ctx.db)
    user = users.create("operator", "pw123")
    ctx.rbac.assign_role(user.id, "operator")
    return user


def _scope(ctx, target: str = "example.com") -> int:
    engagement = ctx.authz.create_engagement("scope")
    ctx.authz.add_authorization(engagement.id, target)
    return engagement.id


# ---------------------------------------------------------------------------
# vuln
# ---------------------------------------------------------------------------
class VulnNormalizeTest(unittest.TestCase):
    def test_host_defaults_https(self):
        ref = checklib.normalize_target("example.com")
        self.assertEqual((ref.host, ref.scheme, ref.port), ("example.com", "https", 443))

    def test_explicit_port_http(self):
        ref = checklib.normalize_target("127.0.0.1", port=8000)
        self.assertEqual((ref.host, ref.scheme, ref.port), ("127.0.0.1", "http", 8000))

    def test_url_forms(self):
        ref = checklib.normalize_target("https://example.com/path")
        self.assertEqual((ref.host, ref.scheme, ref.port), ("example.com", "https", 443))
        ref = checklib.normalize_target("http://sub.example.com:8080/x")
        self.assertEqual((ref.host, ref.scheme, ref.port), ("sub.example.com", "http", 8080))
        ref = checklib.normalize_target("example.com:8443")
        self.assertEqual((ref.host, ref.scheme, ref.port), ("example.com", "https", 8443))

    def test_invalid_rejected(self):
        with self.assertRaises(ValueError):
            checklib.normalize_target("https://exa mple.com/")
        with self.assertRaises(ValueError):
            checklib.normalize_target("", port=99999)


class VulnHeaderLogicTest(unittest.TestCase):
    def _headers(self, lines):
        return checklib._http_headers  # placeholder to keep linters quiet

    def test_dev_server_and_missing_headers(self):
        headers = [
            "server: SimpleHTTP/0.6 Python/3.14.6",
            "content-type: text/html",
        ]
        with mock.patch.object(checklib, "_http_headers", return_value=(headers, "raw")):
            ref = checklib.normalize_target("127.0.0.1", port=8000)
            outcomes = checklib.check_http_headers(ref)
        ids = {o.check_id for o in outcomes}
        self.assertIn("http-security-headers", ids)
        self.assertIn("http-server-disclosure", ids)
        self.assertIn("dev-server-exposed", ids)
        dev = [o for o in outcomes if o.check_id == "dev-server-exposed"][0]
        self.assertEqual(dev.severity, "medium")

    def test_hardened_server_no_findings(self):
        headers = [
            "server: nginx",
            "strict-transport-security: max-age=63072000",
            "content-security-policy: default-src 'self'",
            "x-frame-options: DENY",
            "x-content-type-options: nosniff",
            "referrer-policy: strict-origin",
        ]
        with mock.patch.object(checklib, "_http_headers", return_value=(headers, "raw")):
            ref = checklib.normalize_target("example.com")
            outcomes = checklib.check_http_headers(ref)
        ids = {o.check_id for o in outcomes}
        self.assertNotIn("http-security-headers", ids)
        self.assertNotIn("dev-server-exposed", ids)


class VulnServiceTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.user = _operator(self.ctx)
        self.engagement = _scope(self.ctx)

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_out_of_scope_denied(self):
        with self.assertRaises(KSECError):
            self.ctx.vuln.run(target="203.0.113.9", user=self.user, engagement_id=self.engagement)

    def test_creates_findings_idempotently(self):
        outcome = checklib.CheckOutcome(
            check_id="http-server-disclosure",
            title="Web server version disclosure",
            severity="low",
            description="banner leak",
            recommendation="hide it",
            evidence="Server: nginx/1.2",
            confidence="high",
        )
        with mock.patch.object(checklib, "run_checks", return_value=[outcome]):
            r1 = self.ctx.vuln.run(target="example.com", user=self.user, engagement_id=self.engagement)
            self.assertEqual(len(r1.findings_created), 1)
            row = self.ctx.db.query_one(
                "SELECT source FROM findings WHERE id = ?", (r1.findings_created[0],)
            )
            self.assertTrue(row["source"].startswith("vuln:"))
            r2 = self.ctx.vuln.run(target="example.com", user=self.user, engagement_id=self.engagement)
            self.assertEqual(r2.findings_created, [])
            self.assertEqual(r2.findings_existing, 1)


# ---------------------------------------------------------------------------
# atomic red tests
# ---------------------------------------------------------------------------
class AtomicTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context(overrides={"scheduler": {"max_concurrent_jobs": 1}})
        self.user = _operator(self.ctx)
        self.engagement = _scope(self.ctx)

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_library_complete(self):
        ids = [a.id for a in atomics()]
        self.assertGreaterEqual(len(ids), 4)
        for a in atomics():
            self.assertTrue(a.technique)
            self.assertTrue(a.tactic)
            self.assertTrue(a.capability)
            self.assertTrue(a.detection)

    def test_out_of_scope_denied(self):
        session = self.ctx.sessions.open(self.user, "ADVERSARY_SIMULATION")
        with self.assertRaises(KSECError):
            self.ctx.atomic.run(
                atomic_id="net-dns-lookup",
                target="203.0.113.9",
                user=self.user,
                session=session,
                engagement_id=self.engagement,
            )

    def test_run_path(self):
        session = self.ctx.sessions.open(self.user, "ADVERSARY_SIMULATION")
        fake_run = SimpleNamespace(
            status="completed", steps=[SimpleNamespace(job_id="j-1", entities=2)]
        )
        with mock.patch.object(self.ctx.atomic.workflows, "run", return_value=fake_run):
            result = self.ctx.atomic.run(
                atomic_id="net-dns-lookup",
                target="example.com",
                user=self.user,
                session=session,
                engagement_id=self.engagement,
            )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["job_id"], "j-1")
        self.assertIn("detection", result)

    def test_unknown_atomic(self):
        session = self.ctx.sessions.open(self.user, "ADVERSARY_SIMULATION")
        with self.assertRaises(KSECError):
            self.ctx.atomic.run(
                atomic_id="nope", target="example.com", user=self.user,
                session=session, engagement_id=self.engagement,
            )


# ---------------------------------------------------------------------------
# adversary kill-chain
# ---------------------------------------------------------------------------
class KillChainTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context(overrides={"scheduler": {"max_concurrent_jobs": 1}})
        self.user = _operator(self.ctx)
        self.engagement = _scope(self.ctx)
        self.profile = self.ctx.adversary.create_profile(
            "chain-apt",
            threat_actor="ChainAPT",
            steps=[
                {"technique_id": "T1071", "capability": "http_probe"},  # c2
                {"technique_id": "T1590", "capability": "dns_lookup"},  # recon
                {"technique_id": "T1046", "capability": "port_scan"},   # discovery
            ],
        )
        self.exercise_id = self.ctx.adversary.create_exercise(
            "chain-ex", profile_id=self.profile.id, engagement_id=self.engagement
        )

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_chain_orders_by_tactic(self):
        result = self.ctx.adversary.plan_exercise(
            self.exercise_id,
            user=self.user,
            target="example.com",
            engagement_id=self.engagement,
            policy=self.ctx.policy,
            dry_run=True,
            chain=True,
        )
        phases = [s["phase"] for s in result["steps"]]
        self.assertEqual(phases, ["reconnaissance", "discovery", "command-and-control"])

    def test_position_order_without_chain(self):
        result = self.ctx.adversary.plan_exercise(
            self.exercise_id,
            user=self.user,
            target="example.com",
            engagement_id=self.engagement,
            policy=self.ctx.policy,
            dry_run=True,
            chain=False,
        )
        # original position order: T1071 (c2) first
        self.assertEqual(result["steps"][0]["technique_id"], "T1071")
        self.assertNotIn("phase", result["steps"][0])

    def test_report_phases(self):
        self.ctx.adversary.plan_exercise(
            self.exercise_id,
            user=self.user,
            target="example.com",
            engagement_id=self.engagement,
            policy=self.ctx.policy,
            dry_run=True,
            chain=True,
        )
        report = self.ctx.adversary.report(self.exercise_id)
        self.assertIn("reconnaissance", report["phases"])
        self.assertIn("command-and-control", report["phases"])
        self.assertGreaterEqual(report["phase_count"], 3)

    def test_chain_helpers(self):
        self.assertEqual(_chain_index("reconnaissance"), 0)
        self.assertEqual(_chain_index("impact"), len(CHAIN_PHASES) - 1)
        self.assertEqual(_chain_index("unknown-tactic"), len(CHAIN_PHASES))
        self.assertEqual(TACTIC_MAP["T1046"], "discovery")


# ---------------------------------------------------------------------------
# new parsers + adapters (pure, no network)
# ---------------------------------------------------------------------------
class NewToolParserTest(unittest.TestCase):
    def test_tls_scan_parser(self):
        out = (
            "  Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384\n"
            "  Accepted  TLSv1.0  128 bits  ECDHE-RSA-AES128-SHA\n"
            "  Rejected  TLSv1.3  0 bits\n"
            "  TLSv1.0 enabled\n"
            "  TLSv1.3 enabled\n"
            "  SSLv2 disabled\n"
        )
        res = TlsScanParser().parse(out)
        ciphers = [e for e in res.entities if e["type"] == "tls_cipher"]
        protos = [e for e in res.entities if e["type"] == "tls_protocol"]
        self.assertEqual(len(ciphers), 2)
        self.assertEqual([p["protocol"] for p in protos], ["TLSV1.0", "TLSV1.3"])

    def test_gobuster_parser(self):
        out = "/admin (Status: 301) [Size: 0] [--> http://h/admin/]\n/backup.zip (Status: 200) [Size: 1234]\n"
        res = GobusterParser().parse(out)
        self.assertEqual(len(res.entities), 2)
        self.assertEqual(res.entities[0]["status"], 301)
        self.assertIn("backup.zip", res.entities[1]["path"])

    def test_nikto_parser(self):
        out = "- Nikto v2.5\n+ Target Hostname: example.com\n+ /: Directory indexing found. OSVDB-3268\n"
        res = NiktoParser().parse(out)
        findings = [e for e in res.entities if e["type"] == "nikto_finding"]
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[1]["osvdb"], "3268")

    def test_adapter_command_building(self):
        req = CommandRequest(capability="tls_scan", target="example.com")
        self.assertEqual(SslScanAdapter().build_command(req)[:2], ["sslscan", "--no-colour"])
        req = CommandRequest(capability="dir_enum", target="example.com")
        cmd = GobusterAdapter().build_command(req)
        self.assertTrue(cmd[0].endswith("gobuster") and "dir" in cmd)
        self.assertIn("-w", cmd)
        req = CommandRequest(capability="web_vuln_scan", target="example.com")
        cmd = NiktoAdapter().build_command(req)
        self.assertTrue(cmd[0].endswith("nikto"))


if __name__ == "__main__":
    unittest.main()
