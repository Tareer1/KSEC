from __future__ import annotations

import os
from pathlib import Path

from tests import KsecTestCase


class BackupTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.users_service = self.ctx.db

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_create_and_list(self):
        backup = self.ctx.backups.create()
        self.assertTrue(os.path.exists(backup.path))
        self.assertEqual(len(backup.sha256), 64)
        backups = self.ctx.backups.list()
        self.assertEqual(len(backups), 1)

    def test_verify(self):
        backup = self.ctx.backups.create()
        ok, reason = self.ctx.backups.verify(backup.id)
        self.assertTrue(ok)

    def test_verify_detects_tampering(self):
        backup = self.ctx.backups.create()
        with open(backup.path, "ab") as fh:
            fh.write(b"tamper")
        ok, reason = self.ctx.backups.verify(backup.id)
        self.assertFalse(ok)
        self.assertIn("mismatch", reason)

    def test_restore_requires_approval(self):
        backup = self.ctx.backups.create()
        with self.assertRaises(ValueError):
            self.ctx.backups.restore(backup.id, approve=False)

    def test_restore_to_target_path(self):
        # Make a change, then restore the pre-change backup.
        self.ctx.findings.create(title="before")
        backup = self.ctx.backups.create()
        self.ctx.findings.create(title="after")
        target = str(Path(self.tmp_dir) / "restored.db")
        destination = self.ctx.backups.restore(backup.id, approve=True, target_path=target)
        self.assertTrue(os.path.exists(destination))
        # The restored DB must contain the "before" finding.
        import sqlite3

        conn = sqlite3.connect(destination)
        rows = conn.execute("SELECT title FROM findings").fetchall()
        conn.close()
        titles = [r[0] for r in rows]
        self.assertIn("before", titles)
        self.assertNotIn("after", titles)


if __name__ == "__main__":
    import unittest

    unittest.main()