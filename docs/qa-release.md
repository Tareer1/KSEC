# KSEC — QA & Release Process

Mirrors `specs/09-testing-qa-release.md` (testing/QA) and §55 of
`specs/10-docs-operations-dod.md` (release operations). This is the
*process* document; the mechanics are in `Makefile`, `.github/workflows/`,
`scripts/smoke.sh`, and `tests/`.

## 1. Quality gates (what runs)

| Gate | Command | Where | Scope |
|---|---|---|---|
| Unit suite | `make test` (`python3 -m unittest discover -s tests`) | local + CI | 387 tests across every module |
| CLI smoke | `make smoke` (`bash scripts/smoke.sh`) | local + CI (needs network + a few kali tools) | 201 end-to-end CLI checks incl. real dig/nmap/curl against example.com |
| Boot check | `ksec init && ksec status && ksec doctor` | CI | CLI boots and schema applies on a fresh env |
| Health | `ksec doctor` | local | db/migrations/tools/plugins/backup |
| Update readiness | `ksec update check` | local | version/migrations/plugins/rollback |

CI (`.github/workflows/ci.yml`) runs on push to `main` and on pull
requests:

* **test** job — unit suite on Python 3.11/3.12/3.13, compile/AST sanity
  sweep, no `TODO`/`FIXME`/`XXX` markers in `src/`, and a CLI boot check
  (`init && status && doctor && ask`) on a fresh env.
* **smoke** job — the full 201-check CLI smoke suite on Python 3.12 after
  installing the minimal scan tools (`dnsutils`, `nmap`) for live checks.

## 2. Pre-release checklist

1. `make test` — green.
2. `make smoke` — green (run on a Kali machine with network).
3. `ksec doctor` — all `ok`.
4. `ksec backup create` + `ksec update check` — rollback-ready.
5. Docs in sync: `README.md` status list, `docs/user-guide.md`,
   `CHANGELOG.md` (Keep a Changelog), CLI reference if commands changed.
6. Version bump in `pyproject.toml` and `src/ksec/__init__.py`; schema
   migration count matches `tests/test_db.py`.
7. No `TODO`/`FIXME` markers in `src/` (checked at release time).

## 3. Versioning

Semantic versioning (`major.minor.patch`). Changelog follows
[Keep a Changelog](https://keepachangelog.com/): Added / Changed / Fixed.

- **Breaking** (schema, CLI, security model) → bump minor (pre-1.0) and note
  migration numbers.
- **New compatible features** → bump minor (pre-1.0) or patch.

Schema is versioned independently by migrations (`001`–`011`); the
database reports its own `schema vN`, and `doctor`/`update check` verify it
matches the code.

## 4. Release procedure

```bash
git checkout main && git pull
make test && make smoke        # gates
# bump version, update CHANGELOG, commit
git tag -a v0.2.0 -m "KSEC v0.2.0"
git push origin main --tags
```

After deploy (per environment): `ksec doctor` (applies any new migrations
automatically on first run), `ksec plugin check`, `ksec backup create`.

## 5. Bug classification

- **Release-blocking**: data loss/corruption, privilege escalation, silent
  policy bypass, crash with traceback on a documented command, backup
  restore failure.
- **Normal**: wrong-but-clean behavior, error message quality, docs drift.
- **Cosmetic**: formatting, help text.

Handled KSEC errors (code + correlation_id, no traceback) are the expected
contract; an unhandled traceback is always a bug.

## 6. Testing approach by layer

- **Unit** (`tests/`): services with a temp database via the same bootstrap
  used by the CLI; scheduler/execution exercised with the `null` adapter
  and mocked tools where network is unavailable.
- **Arsenal**: adapter command building + parser unit tests for every
  integrated Kali tool (incl. whatweb/theHarvester), with live
  verification against RFC-2606 targets where tools exist on the box.
- **CLI**: `tests/test_*_cli.py` run real handler functions; `scripts/smoke.sh`
  runs the real `python3 -m ksec` process end to end.
- **Security**: RBAC permission checks, policy denial paths, plugin trust
  gating, command-builder argv safety, audit append-only, evidence/backup
  hash verification all have dedicated tests.
- **Failure injection**: dry-runs never execute; out-of-scope/denied targets
  are asserted to fail cleanly (smoke checks verify no traceback on invalid
  input across command groups).

## 7. Test data policy

Smoke/live tests use only RFC-2606 reserved targets (`example.com`,
`.test`, `.local`) and documentation IP ranges (`203.0.113.0/24`,
`198.51.100.0/24`, `192.0.2.0/24`). Extraction deliberately filters
reserved domains so test noise never becomes production IOCs.
