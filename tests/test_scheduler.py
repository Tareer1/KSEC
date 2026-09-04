from __future__ import annotations

import time

from ksec.core.errors import KSECError
from tests import KsecTestCase


class SchedulerTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context(overrides={"scheduler": {"max_concurrent_jobs": 1}})

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_job_runs_to_completion(self):
        job = self.ctx.scheduler.submit(capability="test_scan", target="10.0.0.1")
        completed = self.ctx.scheduler.wait_for(job.id, timeout=15)
        self.assertEqual(completed.state, "COMPLETED")
        self.assertEqual(completed.exit_code, 0)

    def test_missing_adapter_fails_job(self):
        job = self.ctx.scheduler.submit(capability="no_such_capability")
        completed = self.ctx.scheduler.wait_for(job.id, timeout=15)
        self.assertEqual(completed.state, "FAILED")
        self.assertIn("No adapter", completed.error)

    def test_job_submit_recorded_in_audit(self):
        # Regression: tool execution (the most security-relevant action) used
        # to leave no audit trail — only session.open appeared.
        from ksec.identity.users import UserRepository

        users = UserRepository(self.ctx.db)
        user = users.create("redops", "pw123")
        self.ctx.rbac.assign_role(user.id, "operator")
        job = self.ctx.scheduler.submit(
            capability="test_scan", target="10.0.0.1", user_id=user.id,
            workspace="RED_TEAM",
        )
        self.ctx.scheduler.wait_for(job.id, timeout=15)
        events = self.ctx.audit.list(limit=10)
        submits = [e for e in events if e["event_type"] == "job.submit"]
        self.assertEqual(len(submits), 1)
        self.assertEqual(submits[0]["actor"], "redops")
        self.assertIn("test_scan", submits[0]["action"])
        self.assertEqual(submits[0]["target"], "10.0.0.1")

    def test_cancel_queued_job(self):
        job = self.ctx.jobs.create(capability="test_scan")
        cancelled = self.ctx.scheduler.cancel(job.id)
        self.assertEqual(cancelled.state, "CANCELLED")

    def test_recover_marks_interrupted_jobs_failed(self):
        job = self.ctx.jobs.create(capability="test_scan")
        self.ctx.jobs.set_state(job.id, "RUNNING", started_at="now")
        ids = self.ctx.scheduler.recover()
        self.assertIn(job.id, ids)
        recovered = self.ctx.jobs.get(job.id)
        self.assertEqual(recovered.state, "FAILED")
        self.assertIn("Interrupted", recovered.error)

    def test_pause_resume(self):
        job = self.ctx.jobs.create(capability="test_scan")
        paused = self.ctx.scheduler.pause(job.id)
        self.assertEqual(paused.state, "PAUSED")
        resumed = self.ctx.scheduler.resume(job.id)
        self.assertEqual(resumed.state, "QUEUED")

    def test_cancel_running_slow_job(self):
        job = self.ctx.scheduler.submit(capability="test_scan", options={"sleep": 30})
        # Give the worker a moment to pick it up.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.ctx.jobs.get(job.id).state == "RUNNING":
                break
            time.sleep(0.05)
        cancelled = self.ctx.scheduler.cancel(job.id)
        self.assertIn(cancelled.state, ("CANCELLING", "CANCELLED"))
        terminal = self.ctx.scheduler.wait_for(job.id, timeout=10)
        self.assertEqual(terminal.state, "CANCELLED")


if __name__ == "__main__":
    import unittest

    unittest.main()