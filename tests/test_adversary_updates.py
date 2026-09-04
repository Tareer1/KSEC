from __future__ import annotations

import io
import json
import threading
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository
from tests import KsecTestCase


# ---------------------------------------------------------------------------
# Adversary simulation
# ---------------------------------------------------------------------------


class AdversaryTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context(overrides={"scheduler": {"max_concurrent_jobs": 1}})
        self.users = UserRepository(self.ctx.db)
        self.admin = self.users.create("admin", "pw123")
        self.ctx.rbac.assign_role(self.admin.id, "admin")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _profile(self, **overrides):
        steps = overrides.pop(
            "steps",
            [
                {"technique_id": "T1590", "capability": "dns_lookup", "tactic": "reconnaissance"},
                {"technique_id": "T1046", "capability": "port_scan", "tactic": "discovery"},
            ],
        )
        params = dict(
            name="apt-demo", description="demo", threat_actor="APT-X",
            source="research", created_by="admin", steps=steps,
        )
        params.update(overrides)
        return self.ctx.adversary.create_profile(**params)

    def test_create_profile_with_technique_auto_ttp(self):
        profile = self._profile()
        self.assertEqual(profile.name, "apt-demo")
        self.assertEqual(len(profile.steps), 2)
        # Technique ids recorded as framework TTPs for coverage.
        ttps = {t.technique_id for t in self.ctx.intel.list_ttps()}
        self.assertIn("T1590", ttps)
        self.assertIn("T1046", ttps)

    def test_profile_requires_steps(self):
        with self.assertRaises(ValueError):
            self.ctx.adversary.create_profile("empty", steps=[])

    def test_coverage(self):
        self._profile()
        coverage = self.ctx.adversary.coverage()
        self.assertEqual(coverage["total_techniques"], 2)
        self.assertIn("reconnaissance", coverage["by_tactic"])

    def test_exercise_dry_run_policy_gated(self):
        profile = self._profile()
        engagement = self.ctx.authz.create_engagement("adv")
        self.ctx.authz.add_authorization(engagement.id, "10.0.0.0/8")
        exercise_id = self.ctx.adversary.create_exercise(
            "ex1", profile_id=profile.id, engagement_id=engagement.id, operator_id=self.admin.id
        )
        # Out-of-scope target is blocked at policy level even in dry run.
        result = self.ctx.adversary.plan_exercise(
            exercise_id, user=self.admin, target="203.0.113.99",
            engagement_id=engagement.id, policy=self.ctx.policy, dry_run=True,
        )
        self.assertEqual(result["mode"], "dry-run")
        self.assertEqual(result["status"], "planned")
        # Every step is refused at policy level (out of scope).
        for step in result["steps"]:
            self.assertEqual(step["policy_decision"], "REQUIRE_AUTHORIZATION")
        # A live run of the same exercise would block these steps.
        live = self.ctx.adversary.plan_exercise(
            exercise_id, user=self.admin, target="203.0.113.99",
            engagement_id=engagement.id, policy=self.ctx.policy, dry_run=False,
        )
        self.assertEqual(live["status"], "failed")
        self.assertTrue(all(s["state"] == "blocked" for s in live["steps"]))

    def test_exercise_dry_run_allowed_in_scope(self):
        profile = self._profile(steps=[{"technique_id": "T1590", "capability": "dns_lookup"}])
        engagement = self.ctx.authz.create_engagement("adv")
        self.ctx.authz.add_authorization(engagement.id, "example.com")
        exercise_id = self.ctx.adversary.create_exercise(
            "ex2", profile_id=profile.id, engagement_id=engagement.id, operator_id=self.admin.id
        )
        result = self.ctx.adversary.plan_exercise(
            exercise_id, user=self.admin, target="example.com",
            engagement_id=engagement.id, policy=self.ctx.policy, dry_run=True,
        )
        self.assertEqual(result["status"], "planned")
        step = result["steps"][0]
        self.assertEqual(step["policy_decision"], "ALLOW")
        self.assertEqual(step["state"], "planned")

    def test_exercise_report(self):
        profile = self._profile()
        engagement = self.ctx.authz.create_engagement("adv")
        self.ctx.authz.add_authorization(engagement.id, "example.com")
        exercise_id = self.ctx.adversary.create_exercise(
            "ex3", profile_id=profile.id, engagement_id=engagement.id, operator_id=self.admin.id
        )
        report = self.ctx.adversary.report(exercise_id)
        self.assertEqual(report["profile"], "apt-demo")
        self.assertEqual(report["coverage_count"], 2)


class AdversaryCliTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _common(self, **overrides):
        defaults = dict(json=True, quiet=False)
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_profile_add_list_cli(self):
        from ksec.cli.adversary import cmd_adv_profile_add, cmd_adv_profile_list

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_adv_profile_add(
                self.ctx,
                self._common(
                    name="cli-profile", description="d", threat_actor="APT-CLI",
                    source="", user="admin", technique=["T1046", "T1590"], steps_json=None,
                ),
            )
        self.assertEqual(code, 0)
        created = json.loads(buffer.getvalue())
        self.assertEqual(created["techniques"], ["T1046", "T1590"])
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_adv_profile_list(self.ctx, self._common())
        self.assertEqual(code, 0)
        data = json.loads(buffer.getvalue())
        self.assertEqual(len(data), 1)


# ---------------------------------------------------------------------------
# Update system
# ---------------------------------------------------------------------------


class UpdateTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_check_ok_on_fresh_install(self):
        # Ensure a verified backup exists so the rollback check passes.
        self.ctx.backups.create()
        report = self.ctx.updates.check()
        self.assertTrue(report["offline"])
        self.assertTrue(report["ok"], report)
        names = {c["name"] for c in report["checks"]}
        self.assertEqual(names, {"schema", "rollback", "plugins", "registry"})
        schema = next(c for c in report["checks"] if c["name"] == "schema")
        self.assertEqual(schema["pending_migrations"], [])

    def test_missing_backup_flagged(self):
        report = self.ctx.updates.check()
        rollback = next(c for c in report["checks"] if c["name"] == "rollback")
        self.assertFalse(rollback["ok"])
        self.assertIn("backup", rollback["detail"])

    def test_update_check_cli(self):
        from ksec.cli.update import cmd_update_check

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_update_check(
                self.ctx, SimpleNamespace(json=True, quiet=False)
            )
        self.assertEqual(code, 1)  # no backup yet -> not update-ready
        data = json.loads(buffer.getvalue())
        self.assertIn("checks", data)


# ---------------------------------------------------------------------------
# Notification providers
# ---------------------------------------------------------------------------


class _WebhookServer:
    """Minimal HTTP server that records POST payloads."""

    def __init__(self):
        self.received: list[dict] = []
        self._httpd = HTTPServer(("127.0.0.1", 0), self._handler_factory())
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def _handler_factory(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                server.received.append(payload)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        return Handler

    def start(self):
        self._thread.start()

    def stop(self):
        self._httpd.shutdown()
        self._thread.join(timeout=5)


class NotificationProviderTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.server = _WebhookServer()
        self.server.start()
        self.ctx = self.make_context()
        self.ctx.notifications.providers = {
            "hook": {"type": "webhook", "url": f"http://127.0.0.1:{self.server.port}/hook"},
        }

    def tearDown(self):
        self.ctx.close()
        self.server.stop()
        super().tearDown()

    def test_record_delivers_to_webhook(self):
        self.ctx.notifications.record(
            event_type="soc.alert", title="Critical alert", body="beacon detected"
        )
        self.assertEqual(len(self.server.received), 1)
        payload = self.server.received[0]
        self.assertEqual(payload["event_type"], "soc.alert")
        self.assertEqual(payload["title"], "Critical alert")
        self.assertIn("beacon detected", payload["body"])

    def test_deliver_failure_does_not_raise(self):
        self.ctx.notifications.providers["bad"] = {
            "type": "webhook", "url": "http://127.0.0.1:1/nope"
        }
        results = self.ctx.notifications.deliver(
            event_type="test", title="x", body="y"
        )
        self.assertTrue(results["hook"]["ok"])
        self.assertFalse(results["bad"]["ok"])

    def test_unknown_provider_reported(self):
        self.ctx.notifications.providers["nope"] = {"type": "carrier-pigeon"}
        results = self.ctx.notifications.deliver(event_type="test", title="x")
        self.assertFalse(results["nope"]["ok"])

    def test_config_loads_providers(self):
        import os
        from pathlib import Path

        cfg = Path(self.tmp_dir) / "notify.toml"
        cfg.write_text(
            '[notifications.providers.hook]\n'
            'type = "webhook"\n'
            f'url = "http://127.0.0.1:{self.server.port}/cfg"\n',
            encoding="utf-8",
        )
        os.environ["KSEC_CONFIG"] = str(cfg)
        from ksec.config.loader import KsecConfig

        config = KsecConfig.load()
        self.assertIn("hook", config.notification_providers)
        self.assertEqual(
            config.notification_providers["hook"]["type"], "webhook"
        )


class NotifyCliTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_notify_list_empty(self):
        from ksec.cli.notify import cmd_notify_list

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_notify_list(
                self.ctx, SimpleNamespace(limit=50, json=True, quiet=False)
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buffer.getvalue()), [])

    def test_notify_test_no_providers(self):
        from ksec.cli.notify import cmd_notify_test

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_notify_test(
                self.ctx,
                SimpleNamespace(title=None, body=None, json=True, quiet=False),
            )
        self.assertEqual(code, 1)
        data = json.loads(buffer.getvalue())
        self.assertFalse(data["sent"])


if __name__ == "__main__":
    import unittest

    unittest.main()