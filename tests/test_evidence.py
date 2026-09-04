from __future__ import annotations

from ksec.evidence.service import EvidenceService, hash_content
from tests import KsecTestCase


class EvidenceTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.service = EvidenceService(self.ctx.db)

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_hash_is_sha256(self):
        digest = hash_content("hello")
        self.assertEqual(len(digest), 64)
        self.assertEqual(hash_content("hello"), hash_content("hello"))
        self.assertNotEqual(hash_content("hello"), hash_content("hello!"))

    def test_add_and_verify(self):
        evidence = self.service.add(
            "GET /admin HTTP/1.1 403",
            tool="curl",
            operator="alice",
            collection_method="manual",
        )
        self.assertEqual(evidence.sha256, hash_content(evidence.content))
        ok, reason = self.service.verify(evidence.id)
        self.assertTrue(ok)
        self.assertIn("verified", reason)

    def test_tamper_detected(self):
        evidence = self.service.add("original content", tool="test")
        self.ctx.db.execute(
            "UPDATE evidence SET content = ? WHERE id = ?", ("tampered!", evidence.id)
        )
        ok, reason = self.service.verify(evidence.id)
        self.assertFalse(ok)
        self.assertIn("mismatch", reason)

    def test_list_filters_by_engagement(self):
        engagement = self.ctx.authz.create_engagement("e1")
        self.service.add("a", engagement_id=engagement.id)
        self.service.add("b")
        self.assertEqual(len(self.service.list(engagement_id=engagement.id)), 1)
        self.assertEqual(len(self.service.list()), 2)


if __name__ == "__main__":
    import unittest

    unittest.main()