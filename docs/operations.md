# KSEC — Operations Guide

Mirrors `specs/10-docs-operations-dod.md` §40–64. KSEC is a single-operator
(or small-team) platform; this guide covers keeping it healthy, backed up,
and auditable.

## 1. Health

- `ksec status` — schema version, data dir, counts. Schema `vN` should match
  the code's migration count.
- `ksec doctor` — health checks: database, migrations, tools, plugins,
  backup. Any `FAIL` has a fix hint (see Troubleshooting).
- `ksec env` — environment fingerprint (Kali distro, kernel, tools found).

## 2. Daily operations check

1. `ksec status` — normal.
2. `ksec job list` — no jobs stuck in RUNNING/QUEUED from yesterday
   (scheduler recovers on start, but confirm).
3. `ksec soc alert list --status open` — triage open alerts: `ack`, then
   `resolve`.
4. `ksec intel ioc list` — review newly auto-registered IOCs
   (high-confidence from parser fields, low-confidence from raw text).
5. `ksec notify list` — confirm alert notifications are flowing.

## 3. Weekly operations check

1. `ksec backup create` — weekly backup (also keeps `update check`
   rollback-ready); verify with `ksec backup verify`.
2. `ksec report create --engagement N --title "Weekly"` — capture state.
3. `ksec learning` review (`ksec learn progress --user ...`) if a curriculum
   is in use.
4. `ksec audit` review — confirm expected operations only
   (audit read requires the `auditor` role).

## 4. Monthly operations check

1. Restore drill: restore the oldest backup into a scratch `KSEC_HOME`
   (`KSEC_HOME=/tmp/drill KSEC_CONFIG=/tmp/drill/config.toml`), verify data,
   discard.
2. `ksec update check` — decide on upgrades; follow the
   [QA & Release](qa-release.md) procedure.
3. Review engagements: close finished ones, prune stale scope rules.
4. Review plugins (`ksec plugin list` / `check`): disable anything unused.

## 5. Backup & restore

- `ksec backup create` — full snapshot with integrity hash.
- `ksec backup list` / `ksec backup verify <id>` — list / verify.
- `ksec backup restore <id> --yes` — restore (refuses on hash mismatch or
  missing approval).
- **Disaster recovery**: restore onto a fresh `KSEC_HOME`; `ksec doctor`
  confirms the schema; evidence/report digests validate chain of custody.

## 6. Updating

1. `ksec backup create`
2. `ksec update check` — confirm rollback-ready
3. Pull new code (see [QA & Release](qa-release.md))
4. `ksec doctor` — migrations apply automatically on first run
5. `ksec plugin check` — bundled plugins re-validated
6. `ksec status` — schema matches the new version

`ksec update check` is offline-first: it compares against the code you run,
never phones home.

## 7. Security incident runbook (KSEC itself)

1. **Detect**: unusual audit entries, unexpected jobs/sessions, alerts.
2. **Contain**: revoke user sessions (`ksec session close`), disable
   plugins (`ksec plugin disable/block`), `read_only = true` in `[safety]`.
3. **Preserve**: `ksec backup create` and export the audit log + logs
   (`$KSEC_HOME/ksec.log`) — read-only copies for investigation.
4. **Analyze**: correlation_id in error output maps to audit entries;
   SOC events + alerts (`ksec soc event list --entity <x>`) give timeline.
5. **Recover**: restore the last clean backup to a fresh `KSEC_HOME`; rotate
   passwords (users store only scrypt hashes).
6. **Learn**: open a case (`ksec case create`), record findings/evidence,
   and file the report.

## 8. Data retention & privacy

- Audit log retention is configured in `[audit]` (`retention_days`).
- Logs are secret-redacted by the logging setup.
- Evidence/backups hold whatever scan data you collected — scope them to the
  engagement and purge with the engagement at the end of the contract.

## 9. Monitoring & capacity

- KSEC is local/single-process: watch disk for `ksec.db`, evidence blobs and
  backups (`$KSEC_HOME`).
- Scheduler concurrency is bounded by config; long jobs are visible in
  `ksec job list` and controllable (`pause`, `resume`, `cancel`).

## 10. FAQ

See `docs/troubleshooting.md` for the symptom→fix table, and the
[User Guide](user-guide.md) for per-feature examples.
