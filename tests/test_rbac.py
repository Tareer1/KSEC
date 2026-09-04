from __future__ import annotations

from ksec.identity.users import UserRepository
from tests import KsecTestCase


class RbacTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.users = UserRepository(self.ctx.db)

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_workspaces_seeded(self):
        names = {w["name"] for w in self.ctx.rbac.list_workspaces()}
        self.assertEqual(
            names,
            {
                "RED_TEAM",
                "BLUE_TEAM",
                "RESEARCH_OSINT",
                "ADVERSARY_SIMULATION",
                "LEARN_WORK",
            },
        )

    def test_roles_seeded(self):
        roles = {r["name"] for r in self.ctx.rbac.list_roles()}
        self.assertEqual(roles, {"admin", "operator", "auditor", "learner"})

    def test_admin_has_all_permissions(self):
        admin = self.users.create("root", "pw")
        self.ctx.rbac.assign_role(admin.id, "admin")
        for perm in ("assess.run", "users.manage", "audit.read", "learning.use"):
            self.assertTrue(self.ctx.rbac.user_has_permission(admin.id, perm), perm)

    def test_learner_limited(self):
        learner = self.users.create("student", "pw")
        self.ctx.rbac.assign_role(learner.id, "learner")
        self.assertTrue(self.ctx.rbac.user_has_permission(learner.id, "learning.use"))
        self.assertFalse(self.ctx.rbac.user_has_permission(learner.id, "assess.run"))
        self.assertFalse(self.ctx.rbac.user_has_permission(learner.id, "users.manage"))

    def test_unknown_role_rejected(self):
        user = self.users.create("nobody", "pw")
        from ksec.core.errors import AuthorizationError

        with self.assertRaises(AuthorizationError):
            self.ctx.rbac.assign_role(user.id, "superuser")


if __name__ == "__main__":
    import unittest

    unittest.main()