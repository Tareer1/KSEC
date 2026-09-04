from __future__ import annotations

from ksec.identity.users import UserRepository
from ksec.policies.engine import Decision
from tests import KsecTestCase


class PolicyEngineTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.users = UserRepository(self.ctx.db)
        self.admin = self.users.create("admin", "pw")
        self.ctx.rbac.assign_role(self.admin.id, "admin")
        self.operator = self.users.create("op", "pw")
        self.ctx.rbac.assign_role(self.operator.id, "operator")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def evaluate(self, user, action, session=None, target=None, engagement_id=None):
        return self.ctx.policy.evaluate(
            user=user, action=action, session=session, target=target, engagement_id=engagement_id
        )

    def test_admin_allowed(self):
        result = self.evaluate(self.admin, "assess.run")
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_missing_permission_denied(self):
        result = self.evaluate(self.operator, "users.manage")
        self.assertEqual(result.decision, Decision.DENY)
        self.assertIn("lacks permission", result.reason)

    def test_requires_authorization_for_target(self):
        result = self.evaluate(self.operator, "recon.run", target="10.0.0.5")
        self.assertEqual(result.decision, Decision.REQUIRE_AUTHORIZATION)

    def test_target_without_auth_record_requires_authorization(self):
        engagement = self.ctx.authz.create_engagement("scope")
        result = self.evaluate(
            self.operator, "recon.run", target="10.0.0.5", engagement_id=engagement.id
        )
        self.assertEqual(result.decision, Decision.REQUIRE_AUTHORIZATION)

    def test_target_authorized_allowed(self):
        engagement = self.ctx.authz.create_engagement("scope")
        self.ctx.authz.add_authorization(engagement.id, "10.0.0.0/8")
        result = self.evaluate(
            self.operator, "recon.run", target="10.0.0.5", engagement_id=engagement.id
        )
        self.assertEqual(result.decision, Decision.ALLOW)

    def test_read_only_blocks_mutation(self):
        ctx = self.make_context(overrides={"safety": {"read_only": True}})
        try:
            result = ctx.policy.evaluate(user=self.admin, action="tools.install")
            self.assertEqual(result.decision, Decision.DENY)
            self.assertIn("read-only", result.reason)
        finally:
            ctx.close()

    def test_safe_mode_requires_confirmation_for_install(self):
        ctx = self.make_context(overrides={"safety": {"safe_mode": True}})
        try:
            result = ctx.policy.evaluate(user=self.admin, action="tools.install")
            self.assertEqual(result.decision, Decision.REQUIRE_CONFIRMATION)
        finally:
            ctx.close()

    def test_inactive_session_denied(self):
        session = self.ctx.sessions.open(self.operator, "RED_TEAM")
        self.ctx.sessions.close(session.id)
        closed = self.ctx.sessions.get(session.id)
        result = self.evaluate(self.operator, "assess.run", session=closed)
        self.assertEqual(result.decision, Decision.DENY)
        self.assertIn("expected ACTIVE", result.reason)


if __name__ == "__main__":
    import unittest

    unittest.main()