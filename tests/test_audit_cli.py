"""Audit log CLI: permission-gated read (audit.read)."""
from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace

from ksec.cli import audit as audit_commands
from ksec.identity.users import UserRepository
from tests import KsecTestCase


class AuditCliTests(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.users = UserRepository(self.ctx.db)
        self.admin = self.users.create("admin", "pw123")
        self.ctx.rbac.assign_role(self.admin.id, "admin")
        self.operator = self.users.create("operator", "pw123")
        self.ctx.rbac.assign_role(self.operator.id, "operator")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _args(self, **overrides):
        base = dict(
            user="admin",
            password="pw123",
            limit=50,
            event_type=None,
            actor=None,
            json=False,
            quiet=False,
        )
        base.update(overrides)
        return SimpleNamespace(**base)

    def _call(self, args):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = audit_commands.cmd_audit_list(self.ctx, args)
        return code, buffer.getvalue()

    def test_admin_can_list(self):
        code, out = self._call(self._args())
        self.assertEqual(code, 0)
        self.assertIn("audit event(s)", out)

    def test_json_shape(self):
        code, out = self._call(self._args(json=True))
        self.assertEqual(code, 0)
        rows = json.loads(out)
        self.assertIsInstance(rows, list)
        if rows:
            self.assertIn("event_id", rows[0])
            self.assertIn("event_type", rows[0])

    def test_actor_filter(self):
        code, out = self._call(self._args(actor="operator", json=True))
        self.assertEqual(code, 0)
        rows = json.loads(out)
        self.assertTrue(all(r["actor"] == "operator" for r in rows))

    def test_operator_denied(self):
        code, out = self._call(self._args(user="operator", password="pw123", json=True))
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertIn("authorization denied", data["error"])

    def test_bad_password_denied(self):
        code, _ = self._call(self._args(password="wrong"))
        self.assertEqual(code, 1)

    def test_missing_credentials_denied(self):
        code, _ = self._call(self._args(user=None, password=None))
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
