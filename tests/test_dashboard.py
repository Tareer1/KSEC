from __future__ import annotations

import json
import urllib.request

from tests import KsecTestCase


class DashboardTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.ctx.findings.create(title="test finding", severity="high")
        from ksec.dashboard.server import DashboardServer

        self.server = DashboardServer(self.ctx, host="127.0.0.1", port=0)
        self.server.start()
        self.base = f"http://127.0.0.1:{self.server.bound_port()}"

    def tearDown(self):
        self.server.stop()
        self.ctx.close()
        super().tearDown()

    def _get(self, path: str):
        with urllib.request.urlopen(self.base + path, timeout=5) as response:
            return response.status, response.read().decode("utf-8")

    def test_status_endpoint(self):
        status, body = self._get("/api/v1/status")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("db_path", data)
        self.assertEqual(data["findings"], 1)

    def test_jobs_endpoint(self):
        status, body = self._get("/api/v1/jobs")
        self.assertEqual(status, 200)
        self.assertIn("jobs", json.loads(body))

    def test_findings_endpoint(self):
        status, body = self._get("/api/v1/findings")
        self.assertEqual(status, 200)
        findings = json.loads(body)["findings"]
        self.assertEqual(len(findings), 1)

    def test_root_page(self):
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("KSEC Dashboard", body)

    def test_unknown_endpoint_404(self):
        import urllib.error

        with self.assertRaises(urllib.error.HTTPError):
            self._get("/api/v1/nope")


if __name__ == "__main__":
    import unittest

    unittest.main()