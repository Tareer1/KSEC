"""REST API tests: token lifecycle, auth, read/write endpoints."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from ksec.api.server import ApiServer
from tests import KsecTestCase


def _request(method: str, url: str, token: str | None = None, body: dict | None = None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8") or "{}")


class ApiTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        from ksec.identity.users import UserRepository

        self.user = UserRepository(self.ctx.db).create("admin", "pw123")
        self.ctx.rbac.assign_role(self.user.id, "admin")
        self.server = ApiServer(self.ctx, host="127.0.0.1", port=0)
        self.server.start()
        self.base = f"http://127.0.0.1:{self.server.bound_port()}"

    def tearDown(self):
        self.server.stop()
        self.ctx.close()
        super().tearDown()

    def _token(self, name="ci"):
        token, _ = self.ctx.api_tokens.create(user_id=self.user.id, name=name)
        return token

    def test_token_requires_bearer(self):
        status, body = _request("GET", f"{self.base}/api/v1/status")
        self.assertEqual(status, 401)
        self.assertIn("missing bearer token", body["error"])
        status, _ = _request("GET", f"{self.base}/api/v1/status", token="ksec_bogus")
        self.assertEqual(status, 401)

    def test_revoked_token_rejected(self):
        token, record = self.ctx.api_tokens.create(user_id=self.user.id, name="tmp")
        self.ctx.api_tokens.revoke(record.id)
        status, _ = _request("GET", f"{self.base}/api/v1/status", token=token)
        self.assertEqual(status, 401)

    def test_status_endpoint(self):
        from pathlib import Path

        from ksec.bootstrap import MIGRATIONS_DIR

        status, body = _request("GET", f"{self.base}/api/v1/status", token=self._token())
        self.assertEqual(status, 200)
        latest = max(int(f.name.split("_")[0]) for f in MIGRATIONS_DIR.glob("[0-9][0-9][0-9]_*.sql"))
        self.assertEqual(body["db_version"], latest)

    def test_list_endpoints(self):
        token = self._token()
        for path in ("assets", "findings", "alerts", "cases", "engagements", "jobs", "tools"):
            status, body = _request("GET", f"{self.base}/api/v1/{path}", token=token)
            self.assertEqual(status, 200, path)
        status, _ = _request("GET", f"{self.base}/api/v1/audit", token=token)
        self.assertEqual(status, 200)

    def test_unknown_route(self):
        status, _ = _request("GET", f"{self.base}/api/v1/nope", token=self._token())
        self.assertEqual(status, 404)

    def test_soc_ingest_endpoint(self):
        token = self._token()
        status, body = _request(
            "POST", f"{self.base}/api/v1/soc/ingest", token=token,
            body={"event_id": "api-1", "event_type": "beacon", "severity": "high",
                  "ip": "203.0.113.66"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["event"]["event_id"], "api-1")

    def test_alert_action_records_actor(self):
        self.ctx.soc.ingest(
            {"event_id": "api-2", "event_type": "beacon", "severity": "high",
             "ip": "203.0.113.66"}
        )
        alert = self.ctx.soc_alerts.list()[0]
        token = self._token()
        status, body = _request(
            "POST", f"{self.base}/api/v1/alerts/action", token=token,
            body={"id": alert.id, "action": "ack"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["alert"]["status"], "acknowledged")
        events = self.ctx.audit.list(event_type="alert.acknowledged")
        self.assertEqual(events[0]["actor"], "admin")

    def test_run_dry_run_blocked_out_of_scope(self):
        token = self._token()
        status, body = _request(
            "POST", f"{self.base}/api/v1/run", token=token,
            body={"capability": "dns_lookup", "target": "203.0.113.99", "dry_run": True},
        )
        self.assertEqual(status, 403)
        self.assertTrue(body["blocked"])

    def test_run_unknown_capability(self):
        token = self._token()
        status, body = _request(
            "POST", f"{self.base}/api/v1/run", token=token,
            body={"capability": "no_such", "target": "example.com", "dry_run": True},
        )
        self.assertEqual(status, 400)
        self.assertIn("unknown capability", body["error"])


if __name__ == "__main__":
    import unittest

    unittest.main()
