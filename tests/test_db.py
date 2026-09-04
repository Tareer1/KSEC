from __future__ import annotations

from pathlib import Path

from ksec.bootstrap import MIGRATIONS_DIR
from ksec.db.connection import Database
from ksec.db.migrations import MigrationRunner
from tests import KsecTestCase


class MigrationTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.db = Database(Path(self.tmp_dir) / "test.db").connect()
        self.runner = MigrationRunner(self.db, MIGRATIONS_DIR)

    def tearDown(self):
        self.db.close()
        super().tearDown()

    def test_apply_runs_all_migrations(self):
        applied = self.runner.apply()
        self.assertIn("001_initial.sql", applied)
        self.assertIn("002_security_data.sql", applied)
        self.assertIn("003_learning_ops.sql", applied)
        self.assertIn("004_custom_workflows.sql", applied)
        self.assertIn("005_dfir_threatintel.sql", applied)
        self.assertIn("009_schedules.sql", applied)
        self.assertIn("010_api_tokens.sql", applied)
        self.assertIn("011_window_rules.sql", applied)
        self.assertEqual(self.runner.current_version(), 11)
        self.assertEqual(self.runner.pending(), [])

    def test_apply_is_idempotent(self):
        self.runner.apply()
        self.runner.apply()
        self.assertEqual(self.runner.current_version(), 11)

    def test_schema_tables_exist(self):
        self.runner.apply()
        tables = {
            row["name"]
            for row in self.db.query_all(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        for expected in (
            "users",
            "roles",
            "permissions",
            "role_permissions",
            "user_roles",
            "workspaces",
            "sessions",
            "engagements",
            "authorizations",
            "audit_log",
            "tool_registry",
            "jobs",
            "assets",
            "findings",
            "evidence",
            "cases",
            "case_findings",
            "workflow_runs",
            "custom_workflows",
            "dfir_artifacts",
            "dfir_timeline",
            "threat_actors",
            "campaigns",
            "ttps",
            "campaign_ttps",
            "iocs",
            "schema_migrations",
        ):
            self.assertIn(expected, tables)

    def test_foreign_keys_enforced(self):
        self.runner.apply()
        with self.assertRaises(Exception):
            self.db.execute(
                "INSERT INTO sessions (id, user_id, workspace_id, role_id, state, created_at)"
                " VALUES ('x', 999, 999, 999, 'ACTIVE', 'now')"
            )


if __name__ == "__main__":
    import unittest

    unittest.main()