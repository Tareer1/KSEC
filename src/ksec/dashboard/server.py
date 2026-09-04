"""Local web dashboard (optional interface, spec: Optional Local Web Dashboard).

Serves read-only JSON API endpoints plus a minimal HTML page using only the
standard library. The dashboard uses the same core services as the CLI — it
can never bypass authorization or scope.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Type

from ksec.bootstrap import KsecContext

PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>KSEC Dashboard</title>
<style>
body{font-family:monospace;margin:2rem;background:#111;color:#eee}
h1{color:#4ade80} a{color:#60a5fa}
pre{background:#1e1e1e;padding:1rem;border-radius:6px;overflow-x:auto}
</style></head><body>
<h1>KSEC Dashboard</h1>
<p>Endpoints: <a href="/api/v1/status">status</a> &middot;
<a href="/api/v1/jobs">jobs</a> &middot;
<a href="/api/v1/findings">findings</a> &middot;
<a href="/api/v1/engagements">engagements</a> &middot;
<a href="/api/v1/assets">assets</a></p>
<h2>/api/v1/status</h2><pre id="status">loading&hellip;</pre>
<script>
fetch('/api/v1/status').then(r=>r.json()).then(d=>{
  document.getElementById('status').textContent=JSON.stringify(d,null,2);
});
</script>
</body></html>
"""


def make_handler(context: KsecContext) -> Type[BaseHTTPRequestHandler]:
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "KSEC/0.1"

        def _json(self, data: dict, status: int = 200) -> None:
            body = json.dumps(data, indent=2, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _routes(self) -> tuple[str, dict]:
            # Lazy handlers: only the requested endpoint is evaluated.
            path = self.path.split("?", 1)[0]
            routes = {
                "/": (200, lambda: {"html": PAGE}),
                "/api/v1/status": (200, self._status),
                "/api/v1/jobs": (200, self._jobs),
                "/api/v1/findings": (200, self._findings),
                "/api/v1/engagements": (200, self._engagements),
                "/api/v1/assets": (200, self._assets),
            }
            entry = routes.get(path)
            if entry is None:
                return 404, {"error": "not found"}
            status, handler = entry
            return status, handler()

        def do_GET(self):  # noqa: N802
            status, data = self._routes()
            if self.path.split("?", 1)[0] == "/":
                body = PAGE.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._json(data, status)

        def log_message(self, fmt: str, *args) -> None:  # quiet
            pass

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
                "audit_events": context.audit.count(),
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
    def __init__(self, context: KsecContext, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        handler = make_handler(context)
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