from __future__ import annotations

from ksec.identity.users import UserRepository
from ksec.workflows.definitions import WorkflowDefinition, WorkflowStep, get_workflow
from tests import KsecTestCase


def _test_workflow() -> WorkflowDefinition:
    return WorkflowDefinition(
        name="test_flow",
        description="test",
        steps=(WorkflowStep("test_scan"),),
    )


class WorkflowEngineTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context(overrides={"scheduler": {"max_concurrent_jobs": 1}})
        self.users = UserRepository(self.ctx.db)
        self.operator = self.users.create("op", "pw")
        self.ctx.rbac.assign_role(self.operator.id, "operator")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_builtin_workflows_exist(self):
        for name in ("recon", "assess"):
            definition = get_workflow(name)
            self.assertIsNotNone(definition)
            self.assertTrue(definition.steps)

    def test_dry_run_plans_without_execution(self):
        definition = _test_workflow()
        engagement = self.ctx.authz.create_engagement("scope")
        self.ctx.authz.add_authorization(engagement.id, "10.0.0.0/8")
        session = self.ctx.sessions.open(self.operator, "RED_TEAM")
        outcomes = self.ctx.workflows.plan(
            definition, user=self.operator, session=session, target="10.0.0.5",
            engagement_id=engagement.id,
        )
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0].policy_decision, "ALLOW")
        self.assertEqual(self.ctx.jobs.list(), [])  # nothing executed

    def test_out_of_scope_target_blocked(self):
        definition = _test_workflow()
        engagement = self.ctx.authz.create_engagement("scope")
        self.ctx.authz.add_authorization(engagement.id, "10.0.0.0/8")
        session = self.ctx.sessions.open(self.operator, "RED_TEAM")
        run = self.ctx.workflows.run(
            definition, user=self.operator, session=session, target="172.16.0.5",
            engagement_id=engagement.id,
        )
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.steps[0].state, "blocked")
        self.assertIn("not authorized", run.error)

    def test_missing_engagement_requires_authorization(self):
        definition = _test_workflow()
        session = self.ctx.sessions.open(self.operator, "RED_TEAM")
        run = self.ctx.workflows.run(
            definition, user=self.operator, session=session, target="10.0.0.5",
            engagement_id=None,
        )
        self.assertEqual(run.status, "failed")
        self.assertEqual(run.steps[0].policy_decision, "REQUIRE_AUTHORIZATION")

    def test_authorized_workflow_completes(self):
        definition = _test_workflow()
        engagement = self.ctx.authz.create_engagement("scope")
        self.ctx.authz.add_authorization(engagement.id, "10.0.0.0/8")
        session = self.ctx.sessions.open(self.operator, "RED_TEAM")
        run = self.ctx.workflows.run(
            definition, user=self.operator, session=session, target="10.0.0.5",
            engagement_id=engagement.id,
        )
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.steps[0].state, "completed")
        self.assertIsNotNone(run.steps[0].job_id)


if __name__ == "__main__":
    import unittest

    unittest.main()