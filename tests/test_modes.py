from __future__ import annotations

import io
import os
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

from ksec.capabilities.explain import ExplanationService, explain_tool
from ksec.cli.assess import cmd_assess
from ksec.cli.data import cmd_finding_explain
from ksec.cli.tools import cmd_tools_explain
from ksec.config.loader import KsecConfig
from ksec.identity.users import UserRepository
from ksec.modes import Mode, normalize_mode, resolve_mode
from tests import KsecTestCase


class ModeResolutionTest(KsecTestCase):
    def test_default_config_mode(self):
        self.assertEqual(KsecConfig.load().mode, "professional")

    def test_config_file_override(self):
        cfg_path = Path(self.tmp_dir) / "config.toml"
        cfg_path.write_text('[core]\nmode = "beginner"\n', encoding="utf-8")
        os.environ["KSEC_CONFIG"] = str(cfg_path)
        self.assertEqual(KsecConfig.load().mode, "beginner")

    def test_normalize_mode(self):
        self.assertEqual(normalize_mode("BEGINNER"), "beginner")
        self.assertEqual(normalize_mode("garbage"), "professional")
        self.assertEqual(normalize_mode(None), "professional")

    def test_flag_wins_over_config(self):
        self.assertEqual(resolve_mode("expert", "beginner"), Mode.EXPERT)
        self.assertEqual(resolve_mode(None, "beginner"), Mode.BEGINNER)
        self.assertEqual(resolve_mode(None, None), Mode.PROFESSIONAL)


class ExplanationServiceTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.service = ExplanationService()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_explanations_exist_for_catalog_tools(self):
        for name in ("nmap", "dig", "curl", "john", "whois", "subfinder"):
            explanation = explain_tool(name)
            self.assertIsNotNone(explanation, name)
            self.assertTrue(explanation.beginner)
            self.assertTrue(explanation.technical)

    def test_nmap_beginner_description(self):
        explanation = explain_tool("nmap")
        self.assertIn("doors that are open", explanation.beginner)

    def test_capability_explanation_mode_aware(self):
        beginner = self.service.explain_capability("port_scan", Mode.BEGINNER)
        self.assertIn("beginner", beginner)
        self.assertNotIn("technical", beginner)
        expert = self.service.explain_capability("port_scan", Mode.EXPERT)
        self.assertIn("technical", expert)
        self.assertIn("privilege", expert)
        self.assertIn("outputs", expert)
        professional = self.service.explain_capability("port_scan", Mode.PROFESSIONAL)
        self.assertIn("technical", professional)
        self.assertNotIn("privilege", professional)

    def test_tools_explain_cli(self):
        args = SimpleNamespace(tool="nmap", mode=None, json=False, quiet=False)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_tools_explain(self.ctx, args)
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("nmap", output)
        self.assertIn("port", output)

    def test_tools_explain_unknown_tool(self):
        args = SimpleNamespace(tool="no-such-tool", mode=None, json=False, quiet=False)
        with redirect_stdout(io.StringIO()):
            code = cmd_tools_explain(self.ctx, args)
        self.assertEqual(code, 1)


class AssessExplainTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context(overrides={"scheduler": {"max_concurrent_jobs": 1}})
        self.users = UserRepository(self.ctx.db)
        self.admin = self.users.create("admin", "pw123")
        self.ctx.rbac.assign_role(self.admin.id, "admin")
        self.engagement = self.ctx.authz.create_engagement("scope")
        self.ctx.authz.add_authorization(self.engagement.id, "10.0.0.0/8")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _assess_args(self, **overrides):
        defaults = dict(
            workflow="recon",
            target="10.0.0.5",
            engagement=self.engagement.id,
            user="admin",
            password="pw123",
            workspace="RED_TEAM",
            role=None,
            dry_run=True,
            explain=False,
            mode=None,
            json=True,
            quiet=False,
        )
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def _run_and_parse(self, args):
        import json as json_lib

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_assess(self.ctx, args)
        try:
            data = json_lib.loads(buffer.getvalue())
        except json_lib.JSONDecodeError:
            data = None
        return code, data

    def test_dry_run_explain_beginner(self):
        code, data = self._run_and_parse(self._assess_args(explain=True, mode="beginner"))
        self.assertEqual(code, 0)
        self.assertIn("explanations", data)
        explanation = data["explanations"][0]
        self.assertIn("beginner", explanation)
        self.assertNotIn("technical", explanation)

    def test_dry_run_explain_expert_includes_command(self):
        code, data = self._run_and_parse(self._assess_args(explain=True, mode="expert"))
        self.assertEqual(code, 0)
        explanation = data["explanations"][0]
        self.assertIn("technical", explanation)
        self.assertIn("privilege", explanation)

    def test_beginner_mode_auto_explains(self):
        code, data = self._run_and_parse(self._assess_args(mode="beginner"))
        self.assertEqual(code, 0)
        self.assertIn("explanations", data)


class FindingExplainTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.finding = self.ctx.findings.create(
            title="Open SSH",
            description="Port 22 exposed",
            severity="high",
            recommendation="Restrict access",
            source="nmap",
        )
        self.ctx.intel.register_ioc("10.0.0.5", "IP")
        from ksec.risk.engine import calculate_risk

        self.finding = self.ctx.findings.set_risk(
            self.finding.id, calculate_risk(severity="high")
        )

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _explain(self, mode):
        args = SimpleNamespace(id=self.finding.id, mode=mode, json=False, quiet=False)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_finding_explain(self.ctx, args)
        return code, buffer.getvalue()

    def test_beginner_explanation(self):
        code, output = self._explain("beginner")
        self.assertEqual(code, 0)
        self.assertIn("what_happened", output)
        self.assertIn("why_it_matters", output)
        self.assertNotIn("evidence_support", output)

    def test_professional_explanation(self):
        code, output = self._explain("professional")
        self.assertEqual(code, 0)
        self.assertIn("evidence_support", output)
        self.assertIn("why_this_risk", output)

    def test_expert_explanation_includes_iocs(self):
        self.ctx.db.execute(
            "UPDATE findings SET description = ? WHERE id = ?",
            ("Traffic to 10.0.0.5", self.finding.id),
        )
        code, output = self._explain("expert")
        self.assertEqual(code, 0)
        self.assertIn("ioc_matches", output)

    def test_unknown_finding(self):
        args = SimpleNamespace(id=9999, mode=None, json=False, quiet=False)
        with redirect_stdout(io.StringIO()):
            code = cmd_finding_explain(self.ctx, args)
        self.assertEqual(code, 1)


if __name__ == "__main__":
    import unittest

    unittest.main()