"""KSEC REST API (stdlib-only, token-authenticated).

A small JSON API over the same core services the CLI uses — it can never
bypass authorization or scope. Bearer tokens identify a platform user;
write endpoints (SOC ingest, alert/case actions, live runs) go through
the same policy checks and audit trail as their CLI equivalents.

Note: ``ksec.api.server`` is intentionally NOT imported here — bootstrap
must stay import-light to avoid a cycle (server imports bootstrap for the
context type). Import it lazily: ``from ksec.api.server import ApiServer``.
"""
from ksec.api.tokens import TokenStore

__all__ = ["TokenStore"]
