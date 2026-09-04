from __future__ import annotations

from ksec.identity.users import UserRepository
from ksec.modes import Mode
from ksec.tui.app import KsecTui, VIEWS
from tests import KsecTestCase


class TuiModeTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context(overrides={"scheduler": {"max_concurrent_jobs": 1}})
        users = UserRepository(self.ctx.db)
        admin = users.create("admin", "pw123")
        self.ctx.rbac.assign_role(admin.id, "admin")
        self.ctx.sessions.open(user=admin, workspace_name="RED_TEAM", role_name="admin")
        self._admin_id = admin.id
        self.ctx.findings.create(
            title="Open SSH",
            description="Port 22 exposed to the internet",
            severity="high",
            recommendation="Restrict access",
            source="nmap",
        )

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _rows(self, mode: Mode, view: str) -> list[str]:
        tui = KsecTui(self.ctx, mode=mode)
        tui.view = VIEWS.index(view)
        return tui._rows_for_view()

    # -- status -----------------------------------------------------------

    def test_status_beginner_is_plain_language(self):
        rows = self._rows(Mode.BEGINNER, "status")
        joined = " ".join(rows).lower()
        self.assertTrue(rows, "status view must have rows")
        self.assertIn("user account", joined)
        self.assertIn("session", joined)
        self.assertIn("finding", joined)
        # No raw internals in beginner mode.
        self.assertNotIn("db_path", joined)

    def test_status_expert_has_raw_config(self):
        rows = self._rows(Mode.EXPERT, "status")
        joined = " ".join(rows)
        self.assertIn("db_path", joined)
        self.assertIn("max_concurrent_jobs", joined)
        self.assertIn("adapters", joined)

    # -- jobs -------------------------------------------------------------

    def test_jobs_beginner_explains_capability(self):
        job = self.ctx.scheduler.submit(
            capability="dns_lookup", target="example.com", user_id=self._admin_id
        )
        rows = self._rows(Mode.BEGINNER, "jobs")
        joined = " ".join(rows).lower()
        self.assertIn(job.id[:10], joined)
        # Beginner mode adds a plain-language tool explanation.
        self.assertIn("phone book", joined)

    def test_jobs_expert_shows_raw_command(self):
        self.ctx.scheduler.submit(
            capability="dns_lookup", target="example.com", user_id=self._admin_id
        )
        rows = self._rows(Mode.EXPERT, "jobs")
        joined = "\n".join(rows)
        self.assertIn("$", joined)
        self.assertIn("dig", joined)
        self.assertIn("example.com", joined)

    # -- findings ---------------------------------------------------------

    def test_findings_beginner_plain_severity(self):
        rows = self._rows(Mode.BEGINNER, "findings")
        joined = " ".join(rows).lower()
        self.assertIn("serious issue", joined)
        self.assertIn("open ssh", joined)

    def test_findings_expert_full_details(self):
        rows = self._rows(Mode.EXPERT, "findings")
        joined = " ".join(rows)
        self.assertIn("conf=", joined)
        self.assertIn("risk=", joined)
        self.assertIn("fix:", joined)

    # -- explain ----------------------------------------------------------

    def test_explain_beginner_plain_language(self):
        rows = self._rows(Mode.BEGINNER, "explain")
        joined = " ".join(rows).lower()
        self.assertIn("doors that are open", joined)

    def test_explain_expert_full_fields(self):
        rows = self._rows(Mode.EXPERT, "explain")
        joined = " ".join(rows)
        self.assertIn("why:", joined)
        self.assertIn("data:", joined)
        self.assertIn("risk:", joined)
        self.assertIn("outputs:", joined)

    # -- sessions ---------------------------------------------------------

    def test_sessions_beginner_explains_workspace(self):
        rows = self._rows(Mode.BEGINNER, "sessions")
        joined = " ".join(rows).lower()
        self.assertIn("red team", joined)

    def test_sessions_expert_raw(self):
        rows = self._rows(Mode.EXPERT, "sessions")
        joined = " ".join(rows)
        self.assertIn("user=", joined)


if __name__ == "__main__":
    import unittest

    unittest.main()