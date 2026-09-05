from __future__ import annotations

from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository
from tests import KsecTestCase


class WorkflowStoreTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context(overrides={"scheduler": {"max_concurrent_jobs": 1}})
        self.store = self.ctx.workflow_store

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_create_and_get(self):
        workflow = self.store.create(
            "my-recon",
            steps=[
                {"capability": "dns_lookup"},
                {"capability": "port_scan", "options": {"top_ports": 100}},
            ],
            description="my custom recon",
            created_by="alice",
        )
        self.assertEqual(workflow.name, "my-recon")
        fetched = self.store.get_by_name("my-recon")
        self.assertEqual(fetched.description, "my custom recon")
        self.assertEqual(len(fetched.steps), 2)
        self.assertEqual(fetched.steps[1]["options"]["top_ports"], 100)

    def test_duplicate_name_rejected(self):
        self.store.create("flow", steps=[{"capability": "test_scan"}])
        with self.assertRaises(KSECError):
            self.store.create("flow", steps=[{"capability": "test_scan"}])

    def test_reserved_name_rejected(self):
        with self.assertRaises(KSECError):
            self.store.create("recon", steps=[{"capability": "test_scan"}])

    def test_invalid_name_rejected(self):
        with self.assertRaises(KSECError):
            self.store.create("Bad Name!", steps=[{"capability": "test_scan"}])

    def test_empty_steps_rejected(self):
        with self.assertRaises(KSECError):
            self.store.create("flow", steps=[])

    def test_unknown_capability_rejected(self):
        with self.assertRaises(KSECError):
            self.store.create("flow", steps=[{"capability": "no_such_cap"}])

    def test_invalid_options_rejected(self):
        with self.assertRaises(KSECError):
            self.store.create(
                "flow", steps=[{"capability": "test_scan", "options": {"bad key": "x"}}]
            )

    def test_update_and_delete(self):
        self.store.create("flow", steps=[{"capability": "test_scan"}])
        updated = self.store.update(
            "flow",
            steps=[{"capability": "test_scan"}, {"capability": "dns_lookup"}],
            description="edited",
        )
        self.assertEqual(len(updated.steps), 2)
        self.assertEqual(updated.description, "edited")
        self.store.delete("flow")
        self.assertIsNone(self.store.get_by_name("flow"))

    def test_disable_blocks_resolve(self):
        self.store.create("flow", steps=[{"capability": "test_scan"}])
        self.store.update("flow", enabled=False)
        self.assertIsNone(self.store.resolve("flow"))

    def test_validate_reports_unknown_capability(self):
        errors = self.store.validate_steps([{"capability": "no_such_capability"}])
        self.assertTrue(errors)
        self.assertTrue(any("unknown capability" in e for e in errors))

    def test_newly_wired_capabilities_validate_clean(self):
        """whois_lookup/traceroute/password_crack now have real adapters."""
        for capability in ("whois_lookup", "traceroute", "password_crack",
                           "snmp_enum", "smtp_enum"):
            self.assertEqual(
                self.store.validate_steps([{"capability": capability}]), []
            )


class CustomWorkflowExecutionTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context(overrides={"scheduler": {"max_concurrent_jobs": 1}})
        self.users = UserRepository(self.ctx.db)
        self.operator = self.users.create("op", "pw")
        self.ctx.rbac.assign_role(self.operator.id, "operator")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_custom_workflow_runs_policy_gated(self):
        self.ctx.workflow_store.create(
            "my-flow", steps=[{"capability": "test_scan"}]
        )
        definition = self.ctx.workflow_store.resolve("my-flow")
        self.assertIsNotNone(definition)

        engagement = self.ctx.authz.create_engagement("scope")
        self.ctx.authz.add_authorization(engagement.id, "10.0.0.0/8")
        session = self.ctx.sessions.open(self.operator, "RED_TEAM")
        run = self.ctx.workflows.run(
            definition,
            user=self.operator,
            session=session,
            target="10.0.0.5",
            engagement_id=engagement.id,
        )
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.workflow, "my-flow")

    def test_out_of_scope_custom_workflow_blocked(self):
        self.ctx.workflow_store.create(
            "my-flow", steps=[{"capability": "test_scan"}]
        )
        definition = self.ctx.workflow_store.resolve("my-flow")
        engagement = self.ctx.authz.create_engagement("scope")
        self.ctx.authz.add_authorization(engagement.id, "10.0.0.0/8")
        session = self.ctx.sessions.open(self.operator, "RED_TEAM")
        run = self.ctx.workflows.run(
            definition,
            user=self.operator,
            session=session,
            target="172.16.0.5",
            engagement_id=engagement.id,
        )
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.steps[0].state, "blocked")

    def test_resolve_unknown_returns_none(self):
        self.assertIsNone(self.ctx.workflow_store.resolve("does-not-exist"))

    def test_resolve_capability_as_single_step_workflow(self):
        from ksec.adapters.base import CommandRequest, ToolAdapter

        class FakeAdapter(ToolAdapter):
            name = "fake"
            capability = "my_http_probe"

            def build_command(self, request: CommandRequest) -> list[str]:
                return ["echo", request.target]

        self.ctx.adapters.register(FakeAdapter())
        definition = self.ctx.workflow_store.resolve("my_http_probe")
        self.assertIsNotNone(definition)
        self.assertEqual(definition.name, "my_http_probe")
        self.assertEqual(len(definition.steps), 1)
        self.assertEqual(definition.steps[0].capability, "my_http_probe")

    def test_history_records_runs(self):
        self.ctx.workflow_store.create(
            "my-flow", steps=[{"capability": "test_scan"}]
        )
        definition = self.ctx.workflow_store.resolve("my-flow")
        engagement = self.ctx.authz.create_engagement("scope")
        self.ctx.authz.add_authorization(engagement.id, "10.0.0.0/8")
        session = self.ctx.sessions.open(self.operator, "RED_TEAM")
        self.ctx.workflows.run(
            definition,
            user=self.operator,
            session=session,
            target="10.0.0.5",
            engagement_id=engagement.id,
        )
        rows = self.ctx.workflows.runs(workflow="my-flow")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "completed")
        all_runs = self.ctx.workflows.runs()
        self.assertGreaterEqual(len(all_runs), 1)


if __name__ == "__main__":
    import unittest

    unittest.main()