"""Local web dashboard (optional interface, spec: Optional Local Web Dashboard).

Serves JSON API endpoints plus a minimal HTML triage page using only the
standard library. Reads (status/jobs/findings/engagements/assets/alerts/cases)
and SOC triage writes (ack/resolve/close alerts, close cases) all go through
the same core services as the CLI — the dashboard can never bypass
authorization or scope.

Safety notes:

* bind to ``127.0.0.1`` (default) — the page offers write buttons, so do not
  expose the dashboard on a routable interface; use ``ksec api`` (bearer
  tokens) for remote/scripted access
* write actions are status transitions only, recorded in the audit log with
  actor ``dashboard``
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Type

from ksec.bootstrap import KsecContext

ACTOR = "dashboard"


def _auth_snippet(require_auth: bool) -> str:
    """JS injected into the page: token prompt + bearer header when auth is on."""
    if not require_auth:
        return ""
    return """
const TOKEN_KEY = 'ksec_dash_token';
function getToken(){ return localStorage.getItem(TOKEN_KEY) || ''; }
function askToken(){
  const t = prompt('KSEC dashboard token (create one with: ksec api token create --user NAME --password ...)');
  if (t){ localStorage.setItem(TOKEN_KEY, t); }
}
if(!getToken()){ askToken(); }
function authHeaders(extra){
  const h = Object.assign({}, extra || {});
  if(getToken()){ h['Authorization'] = 'Bearer ' + getToken(); }
  return h;
}
"""


PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>KSEC Dashboard</title>
<style>
body{font-family:monospace;margin:2rem;background:#111;color:#eee}
h1{color:#4ade80} a{color:#60a5fa} h2{border-bottom:1px solid #333;padding-bottom:.3rem}
table{border-collapse:collapse;width:100%;margin:.6rem 0 1.4rem}
th,td{text-align:left;padding:.35rem .6rem;border-bottom:1px solid #2a2a2a;font-size:13px}
th{color:#9ca3af}
button{background:#1e3a8a;color:#eee;border:1px solid #3b82f6;border-radius:4px;padding:.2rem .6rem;cursor:pointer;font-family:monospace}
button:hover{background:#2563eb}
.sev-critical{color:#f87171}.sev-high{color:#fb923c}.sev-medium{color:#facc15}.sev-low{color:#93c5fd}.sev-info{color:#9ca3af}
.note{color:#9ca3af;font-size:12px}
</style></head><body>
<h1>KSEC Dashboard</h1>
<p class="note">Local SOC triage — bind to 127.0.0.1 only. Every write is recorded in the audit log (actor=dashboard).
Actions: <a href="/">overview</a> &middot; <a href="/soc">SOC alerts</a> &middot; <a href="/cases">cases</a></p>

<section id="page"></section>

<script>
const HOST = '';
__AUTH_JS__
function esc(v){ const d=document.createElement('div'); d.textContent=v==null?'':String(v); return d.innerHTML; }
function sevClass(s){ return 'sev-'+(s||'info'); }
async function api(path, method){
  const opts = method ? {method, headers:authHeaders({'Content-Type':'application/json'}), body:'{}'} : {method, headers:authHeaders({})};
  const r = await fetch(HOST + path, opts);
  if (r.status === 401){ askToken(); location.reload(); throw new Error('unauthorized'); }
  return r.json();
}
function page(html){ document.getElementById('page').innerHTML = html; }

async function overview(){
  const d = await api('/api/v1/status');
  page(`<h2>Overview</h2>
  <table>
    <tr><td>version</td><td>${esc(d.version)}</td></tr>
    <tr><td>jobs</td><td>${esc(d.jobs)}</td></tr>
    <tr><td>sessions</td><td>${esc(d.sessions)}</td></tr>
    <tr><td>findings</td><td>${esc(d.findings)}</td></tr>
    <tr><td>assets</td><td>${esc(d.assets)}</td></tr>
    <tr><td>alerts</td><td>${esc(d.alerts)}</td></tr>
    <tr><td>cases</td><td>${esc(d.cases)}</td></tr>
    <tr><td>audit events</td><td>${esc(d.audit_events)}</td></tr>
  </table>`);
}

async function socAlerts(){
  const d = await api('/api/v1/alerts?limit=100');
  const rows = d.alerts.map(a => `<tr>
    <td>#${a.id}</td>
    <td class="${sevClass(a.severity)}">${esc(a.severity)}</td>
    <td>${esc(a.type)}</td>
    <td>${esc(a.summary)}</td>
    <td>${esc(a.status)}</td>
    <td>
      ${a.status==='open'?`<button onclick="actAlert(${a.id},'ack')">ack</button>`:''}
      ${a.status!=='resolved'&&a.status!=='closed'?`<button onclick="actAlert(${a.id},'resolve')">resolve</button>`:''}
      ${a.status!=='closed'?`<button onclick="actAlert(${a.id},'close')">close</button>`:''}
    </td></tr>`).join('');
  page(`<h2>SOC alerts</h2><table><tr><th>id</th><th>severity</th><th>type</th><th>summary</th><th>status</th><th>action</th></tr>${rows||'<tr><td colspan="6">no alerts</td></tr>'}</table>`);
}
async function actAlert(id, action){
  await api('/api/v1/alerts/'+id+'/action/'+action, 'POST');
  socAlerts();
}

async function cases(){
  const d = await api('/api/v1/cases');
  const rows = d.cases.map(c => `<tr>
    <td>#${c.id}</td>
    <td class="${sevClass(c.severity)}">${esc(c.severity)}</td>
    <td>${esc(c.title)}</td>
    <td>${esc(c.status)}</td>
    <td>${c.status!=='closed'?`<button onclick="actCase(${c.id})">close</button>`:''}</td></tr>`).join('');
  page(`<h2>Cases</h2><table><tr><th>id</th><th>severity</th><th>title</th><th>status</th><th>action</th></tr>${rows||'<tr><td colspan="5">no cases</td></tr>'}</table>`);
}
async function actCase(id){
  await api('/api/v1/cases/'+id+'/close', 'POST');
  cases();
}

window.addEventListener('hashchange', route);
function route(){
  const h = location.hash || '#overview';
  if (h.startsWith('#soc')) socAlerts();
  else if (h.startsWith('#cases')) cases();
  else overview();
}
route();
</script>
</body></html>
"""


def make_handler(
    context: KsecContext, require_auth: bool = False
) -> Type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "KSEC/0.2"
        _require_auth = require_auth

        def _json(self, data: dict | list, status: int = 200) -> None:
            body = json.dumps(data, indent=2, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, body: bytes, status: int = 200) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body_json(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0:
                return {}
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
                return data if isinstance(data, dict) else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {}

        def _check_auth(self) -> bool:
            """Bearer-token auth (spec 06#75): dashboard enforces the same
            backend authorization as the CLI/API when ``--require-auth``."""
            if not self._require_auth:
                return True
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return False
            token = header[len("Bearer "):].strip()
            record = context.api_tokens.validate(token)
            if record is None:
                return False
            self._actor = f"dashboard:{record.user_id}"
            return True

        def _page(self) -> bytes:
            html = PAGE.replace("__AUTH_JS__", _auth_snippet(self._require_auth))
            return html.encode("utf-8")

        def _dispatch(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/":
                return self._html(self._page())
            if path.startswith("/soc") or path.startswith("/cases"):
                return self._html(self._page())
            if not self._check_auth():
                return self._json({"error": "unauthorized — provide a valid Bearer API token"}, 401)

            if self.command == "GET":
                # /api/v1/alerts?limit=50&status=open
                if path == "/api/v1/alerts":
                    import urllib.parse

                    query = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
                    limit = int((query.get("limit") or ["50"])[0])
                    status = (query.get("status") or [None])[0]
                    return self._json(self._alerts(limit=limit, status=status))
                if path == "/api/v1/cases":
                    return self._json(self._cases())
                routes = {
                    "/api/v1/status": self._status,
                    "/api/v1/jobs": self._jobs,
                    "/api/v1/findings": self._findings,
                    "/api/v1/engagements": self._engagements,
                    "/api/v1/assets": self._assets,
                }
                handler = routes.get(path)
                if handler is None:
                    return self._json({"error": "not found"}, 404)
                return self._json(handler())

            if self.command == "POST":
                # /api/v1/alerts/<id>/action/<ack|resolve|close>
                parts = path.strip("/").split("/")
                if len(parts) == 6 and parts[0] == "api" and parts[1] == "v1" \
                        and parts[2] == "alerts" and parts[4] == "action":
                    try:
                        alert_id = int(parts[3])
                    except ValueError:
                        return self._json({"error": "bad alert id"}, 400)
                    return self._alert_action(alert_id, parts[5])
                # /api/v1/cases/<id>/close
                if len(parts) == 5 and parts[0] == "api" and parts[1] == "v1" \
                        and parts[2] == "cases" and parts[4] == "close":
                    try:
                        case_id = int(parts[3])
                    except ValueError:
                        return self._json({"error": "bad case id"}, 400)
                    return self._case_close(case_id)
                return self._json({"error": "not found"}, 404)
            return self._json({"error": "method not allowed"}, 405)

        def do_GET(self):  # noqa: N802
            self._dispatch()

        def do_POST(self):  # noqa: N802
            self._dispatch()

        def log_message(self, fmt: str, *args) -> None:  # quiet
            pass

        # -- actions ---------------------------------------------------------

        def _alert_action(self, alert_id: int, action: str) -> None:
            alert = context.soc_alerts.get(alert_id)
            if alert is None:
                return self._json({"error": f"unknown alert: {alert_id}"}, 404)
            try:
                if action == "ack":
                    updated = context.soc_alerts.acknowledge(alert_id, actor=ACTOR)
                elif action == "resolve":
                    updated = context.soc_alerts.resolve(alert_id, actor=ACTOR)
                elif action == "close":
                    updated = context.soc_alerts.set_status(alert_id, "closed", actor=ACTOR)
                else:
                    return self._json({"error": f"unknown action: {action}"}, 400)
            except Exception as exc:  # noqa: BLE001 - surface as HTTP error
                return self._json({"error": str(exc)}, 409)
            return self._json({"updated": True, "id": alert_id, "status": updated.status})

        def _case_close(self, case_id: int) -> None:
            case = context.cases.get(case_id)
            if case is None:
                return self._json({"error": f"unknown case: {case_id}"}, 404)
            try:
                updated = context.cases.close(case_id, actor=ACTOR)
            except Exception as exc:  # noqa: BLE001
                return self._json({"error": str(exc)}, 409)
            return self._json({"updated": True, "id": case_id, "status": updated.status})

        # -- data helpers --------------------------------------------------

        def _status(self) -> dict:
            return {
                "version": __import__("ksec", fromlist=["__version__"]).__version__,
                "db_path": str(context.config.db_path),
                "config_source": str(context.config.source) if context.config.source else "defaults",
                "jobs": len(context.jobs.list()),
                "sessions": len(context.sessions.list()),
                "findings": len(context.findings.list()),
                "assets": len(context.assets.list()),
                "alerts": context.soc_alerts.count(),
                "cases": len(context.cases.list()),
                "audit_events": context.audit.count(),
            }

        def _alerts(self, limit: int = 50, status: str | None = None) -> dict:
            alerts = context.soc_alerts.list(limit=limit, status=status)
            return {
                "alerts": [
                    {
                        "id": a.id,
                        "alert_id": a.alert_id,
                        "severity": a.severity,
                        "risk_score": a.risk_score,
                        "type": a.type,
                        "summary": a.summary,
                        "status": a.status,
                        "source": a.source,
                        "created_at": a.created_at,
                    }
                    for a in alerts
                ]
            }

        def _cases(self) -> dict:
            return {
                "cases": [
                    {
                        "id": c.id,
                        "title": c.title,
                        "severity": c.severity,
                        "status": c.status,
                        "owner": c.owner,
                        "created_at": c.created_at,
                    }
                    for c in context.cases.list()
                ]
            }

        def _jobs(self) -> dict:
            return {
                "jobs": [
                    {
                        "id": j.id[:12],
                        "capability": j.capability,
                        "target": j.target,
                        "state": j.state,
                        "exit_code": j.exit_code,
                        "created_at": j.created_at,
                    }
                    for j in context.jobs.list(limit=50)
                ]
            }

        def _findings(self) -> dict:
            return {
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "severity": f.severity,
                        "status": f.status,
                        "risk_level": f.risk_level,
                    }
                    for f in context.findings.list()[:50]
                ]
            }

        def _engagements(self) -> dict:
            return {
                "engagements": [
                    {
                        "id": e.id,
                        "name": e.name,
                        "status": e.status,
                        "created_at": e.created_at,
                    }
                    for e in context.authz.list_engagements()
                ]
            }

        def _assets(self) -> dict:
            return {
                "assets": [
                    {
                        "id": a.id,
                        "target": a.target,
                        "type": a.asset_type,
                        "criticality": a.criticality,
                    }
                    for a in context.assets.list()
                ]
            }

    return DashboardHandler


class DashboardServer:
    def __init__(
        self,
        context: KsecContext,
        host: str = "127.0.0.1",
        port: int = 8080,
        require_auth: bool = False,
    ):
        self.host = host
        self.port = port
        self.require_auth = require_auth
        handler = make_handler(context, require_auth=require_auth)
        self.httpd = ThreadingHTTPServer((host, port), handler)

    def serve_forever(self) -> None:
        try:
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.httpd.server_close()

    def start(self):
        """Serve in a background thread (used by tests and scripts)."""
        import threading

        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def bound_port(self) -> int:
        return self.httpd.server_address[1]
