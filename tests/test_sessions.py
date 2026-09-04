from __future__ import annotations

from ksec.core.errors import SessionError
from ksec.identity.users import UserRepository
from tests import KsecTestCase


class SessionTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.users = UserRepository(self.ctx.db)
        self.user = self.users.create("op", "pw")
        self.ctx.rbac.assign_role(self.user.id, "operator")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_open_session_is_active(self):
        session = self.ctx.sessions.open(self.user, "RED_TEAM")
        self.assertEqual(session.state, "ACTIVE")
        self.assertEqual(session.workspace, "RED_TEAM")
        self.assertEqual(session.role, "operator")
        self.assertEqual(session.username, "op")

    def test_open_unknown_workspace_fails(self):
        with self.assertRaises(SessionError):
            self.ctx.sessions.open(self.user, "NO_SUCH")

    def test_close_pause_resume(self):
        session = self.ctx.sessions.open(self.user, "BLUE_TEAM")
        paused = self.ctx.sessions.pause(session.id)
        self.assertEqual(paused.state, "PAUSED")
        resumed = self.ctx.sessions.resume(session.id)
        self.assertEqual(resumed.state, "ACTIVE")
        closed = self.ctx.sessions.close(session.id)
        self.assertEqual(closed.state, "CLOSED")
        self.assertIsNotNone(closed.closed_at)

    def test_invalid_transition_fails(self):
        session = self.ctx.sessions.open(self.user, "LEARN_WORK")
        self.ctx.sessions.close(session.id)
        with self.assertRaises(SessionError):
            self.ctx.sessions.resume(session.id)

    def test_require_active_ownership(self):
        session = self.ctx.sessions.open(self.user, "RED_TEAM")
        other = self.users.create("other", "pw")
        with self.assertRaises(SessionError):
            self.ctx.sessions.require_active(session.id, other.id)
        ok = self.ctx.sessions.require_active(session.id, self.user.id)
        self.assertEqual(ok.id, session.id)

    def test_five_workspaces_one_user(self):
        sessions = [
            self.ctx.sessions.open(self.user, name)
            for name in ("RED_TEAM", "BLUE_TEAM", "RESEARCH_OSINT", "ADVERSARY_SIMULATION", "LEARN_WORK")
        ]
        self.assertEqual(len({s.workspace for s in sessions}), 5)
        self.assertEqual(len(self.ctx.sessions.list(self.user.id)), 5)


if __name__ == "__main__":
    import unittest

    unittest.main()