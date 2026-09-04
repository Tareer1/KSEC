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

    def _post(self, path: str) -> dict:
        request = urllib.request.Request(
            self.base + path, data=b"{}", method="POST"
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))

    def _produce_alert_and_case(self):
        report = self.ctx.soc.ingest(
            {"event_id": "dash-1", "source": "ids", "event_type": "beacon",
             "severity": "high", "ip": "10.1.1.5",
             "details": {"message": "outbound beacon to 198.51.100.9"}}
        )
        return report["alert"]["id"], report["case"]["id"]

    def test_alerts_and_cases_endpoints(self):
        alert_id, case_id = self._produce_alert_and_case()
        _, body = self._get("/api/v1/alerts")
        alerts = json.loads(body)["alerts"]
        self.assertEqual([a["id"] for a in alerts], [alert_id])
        _, body = self._get("/api/v1/cases")
        cases = json.loads(body)["cases"]
        self.assertEqual([c["id"] for c in cases], [case_id])

    def test_alert_ack_resolve_close_actions(self):
        alert_id, case_id = self._produce_alert_and_case()
        acked = self._post(f"/api/v1/alerts/{alert_id}/action/ack")
        self.assertEqual(acked["status"], "acknowledged")
        resolved = self._post(f"/api/v1/alerts/{alert_id}/action/resolve")
        self.assertEqual(resolved["status"], "resolved")
        # Actions are recorded in the audit log with actor=dashboard.
        rows = self.ctx.audit.list(limit=20)
        actors = {r["actor"] for r in rows if r["event_type"].startswith("alert.")}
        self.assertIn("dashboard", actors)

    def test_case_close_action(self):
        alert_id, case_id = self._produce_alert_and_case()
        result = self._post(f"/api/v1/cases/{case_id}/close")
        self.assertEqual(result["status"], "closed")
        self.assertEqual(self.ctx.cases.get(case_id).status, "closed")

    def test_bad_action_returns_400(self):
        import urllib.error

        alert_id, _ = self._produce_alert_and_case()
        with self.assertRaises(urllib.error.HTTPError) as exc:
            self._post(f"/api/v1/alerts/{alert_id}/action/nuke")
        self.assertEqual(exc.exception.code, 400)

    def test_unknown_alert_action_404(self):
        import urllib.error

        with self.assertRaises(urllib.error.HTTPError) as exc:
            self._post("/api/v1/alerts/999/action/ack")
        self.assertEqual(exc.exception.code, 404)


if __name__ == "__main__":
    import unittest

    unittest.main()