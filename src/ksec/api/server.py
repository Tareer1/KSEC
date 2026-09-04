"""KSEC REST API server (stdlib-only, token-authenticated).

All endpoints require ``Authorization: Bearer <token>``. Reads expose the
same data as the CLI list commands; writes go through the same services,
policy checks and audit trail (SOC ingest, alert/case actions, live
capability runs) — never around them.
"""
from __future__ import annotations

import dataclasses
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Type

from ksec.core.errors import KSECError
from ksec.identity.users import UserRepository
from ksec.workflows.definitions import list_workflows

if TYPE_CHECKING:
    from ksec.bootstrap import KsecContext


def _ser(value):
    """Serialize dataclass / sqlite Row / scalar to JSON-safe values."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    if hasattr(value, "keys"):  # sqlite3.Row
        return dict(value)
    return value

_ERROR_PERMISSION = "audit.read"


def make_handler(context: KsecContext) -> Type[BaseHTTPRequestHandler]:
    class ApiHandler(BaseHTTPRequestHandler):
        server_version = "KSEC-API/0.1"

        # -- plumbing ------------------------------------------------------

        def _json(self, data, status: int = 200) -> None:
            body = json.dumps(data, indent=2, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0:
                return {}
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {}
            return data if isinstance(data, dict) else {}

        def _authorize(self) -> tuple[bool, object]:
            """Return (ok, user_or_error_dict)."""
            header = self.headers.get("Authorization", "")
            scheme, _, token = header.partition(" ")
            if scheme.lower() != "bearer" or not token.strip():
                return False, {"error": "missing bearer token (Authorization: Bearer <token>)"}
            record = context.api_tokens.validate(token.strip())
            if record is None:
                return False, {"error": "invalid or revoked token"}
            user = UserRepository(context.db).get(record.user_id)
            if user is None:
                return False, {"error": "token owner no longer exists"}
            return True, user

        def _route_get(self, path: str) -> tuple[int, dict]:
            if path == "/api/v1/status":
                return 200, self._status()
            if path == "/api/v1/jobs":
                return 200, {"jobs": [_job(j) for j in context.jobs.list(limit=100)]}
            if path == "/api/v1/assets":
                return 200, {"assets": [_ser(a) for a in context.assets.list()]}
            if path == "/api/v1/findings":
                return 200, {"findings": [_ser(f) for f in context.findings.list()]}
            if path == "/api/v1/alerts":
                return 200, {"alerts": [_ser(a) for a in context.soc_alerts.list()]}
            if path == "/api/v1/cases":
                return 200, {"cases": [_ser(c) for c in context.cases.list()]}
            if path == "/api/v1/engagements":
                return 200, {"engagements": [_ser(e) for e in context.authz.list_engagements()]}
            if path == "/api/v1/sessions":
                return 200, {"sessions": [_ser(s) for s in context.sessions.list()]}
            if path == "/api/v1/iocs":
                return 200, {"iocs": [_ser(i) for i in context.intel.list_iocs()]}
            if path == "/api/v1/tools":
                return 200, {"tools": [_ser(t) for t in context.capabilities.discover(persist=False)]}
            if path == "/api/v1/audit":
                return 200, {"audit": [dict(r) for r in context.audit.list(limit=100)]}
            return 404, {"error": f"not found: {path}"}

        # -- HTTP verbs ----------------------------------------------------

        def do_GET(self):  # noqa: N802
            ok, who = self._authorize()
            if not ok:
                self._json(who, 401)
                return
            user = who
            path = self.path.split("?", 1)[0]
            if path == "/api/v1/audit":
                if not context.rbac.user_has_permission(user.id, _ERROR_PERMISSION):
                    self._json({"error": f"user lacks permission {_ERROR_PERMISSION}"}, 403)
                    return
            status, data = self._route_get(path)
            self._json(data, status)

        def do_POST(self):  # noqa: N802
            ok, who = self._authorize()
            if not ok:
                self._json(who, 401)
                return
            user = who
            body = self._read_body()
            path = self.path.split("?", 1)[0]
            try:
                if path == "/api/v1/soc/ingest":
                    data, status = self._soc_ingest(body)
                elif path == "/api/v1/alerts/action":
                    data, status = self._alert_action(body, user)
                elif path == "/api/v1/cases/close":
                    data, status = self._case_close(body, user)
                elif path == "/api/v1/run":
                    data, status = self._run(body, user)
                else:
                    data, status = {"error": f"not found: {path}"}, 404
            except KSECError as exc:
                data, status = {"error": exc.message}, 400
            except ValueError as exc:
                data, status = {"error": str(exc)}, 400
            self._json(data, status)

        # -- endpoint handlers ----------------------------------------------

        def _soc_ingest(self, body: dict) -> tuple[dict, int]:
            report = context.soc.ingest(body)
            return {"event": report}, 201 if report.get("created") else 200

        def _alert_action(self, body: dict, user) -> tuple[dict, int]:
            alert_id = int(body.get("id") or 0)
            action = str(body.get("action") or "")
            if context.soc_alerts.get(alert_id) is None:
                return {"error": f"unknown alert: {alert_id}"}, 404
            if action == "ack":
                updated = context.soc_alerts.acknowledge(alert_id, actor=user.username)
            elif action == "resolve":
                updated = context.soc_alerts.resolve(
                    alert_id, case_id=body.get("case_id"), actor=user.username
                )
            elif action == "close":
                updated = context.soc_alerts.set_status(alert_id, "closed", actor=user.username)
            else:
                return {"error": "action must be ack|resolve|close"}, 400
            return {"alert": updated.to_dict()}, 200

        def _case_close(self, body: dict, user) -> tuple[dict, int]:
            case_id = int(body.get("id") or 0)
            if context.cases.get(case_id) is None:
                return {"error": f"unknown case: {case_id}"}, 404
            case = context.cases.close(case_id, actor=user.username)
            return {"closed": True, "id": case.id, "status": case.status}, 200

        def _run(self, body: dict, user) -> tuple[dict, int]:
            capability = str(body.get("capability") or "")
            target = str(body.get("target") or "")
            engagement_id = body.get("engagement_id")
            workspace = str(body.get("workspace") or "RED_TEAM")
            if not capability or not target:
                return {"error": "capability and target are required"}, 400
            definition = context.workflow_store.resolve(capability)
            if definition is None:
                available = [w.name for w in list_workflows()] + [w.name for w in context.workflow_store.list()]
                return {"error": f"unknown capability {capability!r}; available: {', '.join(available)}"}, 400
            session = context.sessions.open(user, workspace, role_name=body.get("role"))
            if body.get("dry_run"):
                outcomes = context.workflows.plan(
                    definition, user=user, session=session,
                    target=target, engagement_id=engagement_id,
                )
                blocked = [o for o in outcomes if o.policy_decision != "ALLOW"]
                return {
                    "mode": "dry-run",
                    "blocked": bool(blocked),
                    "steps": [
                        {"capability": o.capability, "policy": o.policy_decision, "reason": o.policy_reason}
                        for o in outcomes
                    ],
                }, 200 if not blocked else 403
            run = context.workflows.run(
                definition, user=user, session=session,
                target=target, engagement_id=engagement_id,
            )
            return {
                "run_id": run.run_id,
                "workflow": run.workflow,
                "target": run.target,
                "status": run.status,
                "error": run.error,
            }, 200 if run.status == "completed" else 400

        def _status(self) -> dict:
            return {
                "version": "0.2.0",
                "db_version": context.db.query_one("SELECT COUNT(*) AS c FROM schema_migrations")["c"],
                "users": context.db.query_one("SELECT COUNT(*) AS c FROM users")["c"],
                "jobs": len(context.jobs.list(limit=1000)),
                "findings": len(context.findings.list()),
                "alerts_open": context.soc_alerts.count(status="open"),
                "assets": len(context.assets.list()),
            }

        def log_message(self, fmt: str, *args) -> None:  # quiet access log
            return

    return ApiHandler


def _job(job) -> dict:
    return {
        "id": job.id,
        "capability": job.capability,
        "target": job.target,
        "state": job.state,
        "exit_code": job.exit_code,
        "entity_count": (job.result or {}).get("entity_count", 0),
        "created_at": job.created_at,
        "completed_at": job.completed_at,
    }


class ApiServer:
    def __init__(self, context: KsecContext, host: str = "127.0.0.1", port: int = 9090):
        self.context = context
        self.host = host
        self.port = port
        self.httpd = ThreadingHTTPServer((host, port), make_handler(context))

    def serve_forever(self) -> None:
        self.httpd.serve_forever()

    def start(self) -> None:
        import threading

        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def bound_port(self) -> int:
        return int(self.httpd.server_address[1])
