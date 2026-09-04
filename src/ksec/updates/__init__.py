"""Update system (spec 01#36 UPDATE SYSTEM, 01#37 OFFLINE OPERATION).

Checks local state — KSEC version, pending migrations, plugin/registry
consistency and rollback readiness (backups) — and reports what an update
would touch. Fully offline-first: no network calls are made; a future
remote/package source plugs in behind the same interface.
"""