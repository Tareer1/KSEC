"""Internal event bus and notification service (spec: EVENT BUS / NOTIFICATION ENGINE).

Components communicate loosely through the event bus. Notifications are
recorded to a log-style store and delivered through pluggable providers
(email, telegram, slack, webhook) configured under ``[notifications]``
(spec 02#30 NOTIFICATION ENGINE). Providers are best-effort: delivery
failures never break the calling operation.
"""
from __future__ import annotations

import json
import smtplib
import sqlite3
import urllib.request
from typing import Any, Callable

from ksec.db.connection import Database
from ksec.identity.users import now_utc


class EventBus:
    """Minimal in-process pub/sub."""

    def __init__(self):
        self._subscribers: dict[str, list[Callable[[dict], None]]] = {}

    def subscribe(self, event_type: str, handler: Callable[[dict], None]) -> None:
        self._subscribers.setdefault(event_type, []).append(handler)

    def publish(self, event_type: str, **payload: Any) -> None:
        event = {"type": event_type, "payload": payload}
        for handler in self._subscribers.get(event_type, []):
            handler(event)


class NotificationService:
    def __init__(self, db: Database, providers: dict | None = None):
        self.db = db
        # provider_name -> config dict, e.g. {"type": "telegram", ...}
        self.providers: dict[str, dict] = providers or {}

    def record(
        self,
        *,
        channel: str = "log",
        event_type: str,
        title: str,
        body: str = "",
        deliver: bool = True,
    ) -> int:
        with self.db.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO notifications (channel, event_type, title, body, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (channel, event_type, title, body, now_utc()),
            )
        if deliver:
            self.deliver(event_type=event_type, title=title, body=body)
        return cursor.lastrowid

    # -- providers --------------------------------------------------------

    def deliver(self, *, event_type: str, title: str, body: str = "") -> dict:
        """Send through every configured provider. Never raises.

        Returns {provider_name: {"ok": bool, "error": str|None}}.
        """
        results: dict = {}
        for name, config in self.providers.items():
            results[name] = self._deliver_one(name, config, event_type, title, body)
        return results

    def _deliver_one(self, name, config, event_type, title, body) -> dict:
        provider_type = str(config.get("type", "log")).lower()
        try:
            if provider_type == "log":
                return {"ok": True, "error": None, "channel": "log"}
            if provider_type in ("telegram", "slack", "discord", "webhook"):
                return _send_webhook(config, title, body, event_type, provider_type)
            if provider_type == "email":
                return _send_email(config, title, body)
            return {"ok": False, "error": f"unknown provider type {provider_type!r}"}
        except Exception as exc:  # providers are best-effort
            return {"ok": False, "error": str(exc)}

    def list(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.db.query_all(
            "SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (limit,)
        )

    def count(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) AS c FROM notifications")
        return int(row["c"]) if row else 0


def _send_webhook(config: dict, title: str, body: str, event_type: str, kind: str) -> dict:
    """Telegram/Slack/Discord/generic webhook via HTTP POST (stdlib)."""
    url = config.get("url", "")
    if not url:
        return {"ok": False, "error": "provider requires 'url'"}
    payload = _payload_for(kind, config, title, body, event_type)
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=config.get("timeout", 10)) as response:
        response.read()
    return {"ok": True, "error": None, "channel": kind}


def _payload_for(kind: str, config: dict, title: str, body: str, event_type: str) -> dict:
    if kind == "telegram":
        text = f"*{title}*\n{body}" if body else f"*{title}*"
        return {"chat_id": config.get("chat_id", ""), "text": text}
    if kind == "slack":
        return {"text": f"*{title}*\n{body}" if body else title}
    if kind == "discord":
        return {"content": f"**{title}**\n{body}" if body else title}
    return {"event_type": event_type, "title": title, "body": body}


def _send_email(config: dict, title: str, body: str) -> dict:
    """SMTP delivery (stdlib smtplib)."""
    host = config.get("host", "")
    sender = config.get("from", "")
    recipients = config.get("to", "")
    if not host or not sender or not recipients:
        return {"ok": False, "error": "email provider requires host, from, to"}
    to_list = recipients.split(",") if isinstance(recipients, str) else list(recipients)
    message = f"Subject: {title}\n\n{body}"
    port = int(config.get("port", 587))
    use_tls = bool(config.get("tls", True))
    with smtplib.SMTP(host, port, timeout=config.get("timeout", 15)) as smtp:
        if use_tls:
            smtp.starttls()
        username = config.get("username")
        password = config.get("password")
        if username:
            smtp.login(username, password or "")
        smtp.sendmail(sender, to_list, message.encode("utf-8"))
    return {"ok": True, "error": None, "channel": "email"}