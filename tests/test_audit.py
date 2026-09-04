from __future__ import annotations

from ksec.logging_setup import redact
from tests import KsecTestCase


class RedactTest(KsecTestCase):
    def test_redacts_key_value_secrets(self):
        self.assertEqual(
            redact("connecting with password=hunter2 now"),
            "connecting with password=<REDACTED> now",
        )
        self.assertEqual(
            redact("token: abc123def"),
            "token: <REDACTED>",
        )

    def test_redacts_bearer_tokens(self):
        self.assertEqual(
            redact("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"),
            "Authorization: <REDACTED>",
        )

    def test_plain_text_unchanged(self):
        self.assertEqual(redact("just a normal message"), "just a normal message")


class AuditServiceTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.service = self.ctx.audit

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_record_and_list(self):
        event_id = self.service.record(
            event_type="test.event",
            actor="alice",
            action="test.action",
            outcome="success",
            payload={"key": "value"},
        )
        rows = self.service.list()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_id"], event_id)
        self.assertEqual(rows[0]["actor"], "alice")

    def test_filter_by_type_and_actor(self):
        self.service.record(event_type="a", actor="u1")
        self.service.record(event_type="b", actor="u1")
        self.service.record(event_type="a", actor="u2")
        self.assertEqual(len(self.service.list(event_type="a")), 2)
        self.assertEqual(len(self.service.list(actor="u2")), 1)
        self.assertEqual(len(self.service.list(event_type="a", actor="u1")), 1)

    def test_disabled_audit_records_nothing(self):
        ctx = self.make_context(overrides={"audit": {"enabled": False}})
        try:
            ctx.audit.record(event_type="x", outcome="success")
            self.assertEqual(ctx.audit.count(), 0)
        finally:
            ctx.close()


if __name__ == "__main__":
    import unittest

    unittest.main()