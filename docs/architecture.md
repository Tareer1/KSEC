# KSEC — Architecture

Mirrors `specs/02-architecture-repo-structure.md`. KSEC is a single-process,
stdlib-only Python application over a SQLite database, designed to run on a
Kali workstation (or one operator laptop) — not a distributed service.

```
┌────────────────────────────── CLI / TUI / Dashboard ─────────────────────────────┐
│  ksec <command>   (argparse)      ksec tui (curses)     ksec dashboard (HTTP)     │
└──────────────┬────────────────────────────────────────────────────────────────────┘
               │ bootstrap.py — dependency wiring (single composition root)
┌──────────────▼────────────────────────────────────────────────────────────────────┐
│  Policy layer          RBAC (roles→permissions) · authorization · scope · audit   │
│  Orchestration         scheduler (jobs) · workflow engine · execution engine      │
│  Security modules      dfir · threat_intel · soc · adversary · plugins · updates  │
│  Domain services       assets · findings · evidence · cases · correlation ·       │
│                        normalization · risk · reporting · learning · backups      │
│  Infrastructure        adapters → Kali tools · parsers · capabilities registry ·  │
│                        notifications (providers) · config · logging               │
│  Storage               SQLite + sequential migrations (001–008)                   │
└────────────────────────────────────────────────────────────────────────────────────┘
```

## Layout

| Path | Contents |
|---|---|
| `src/ksec/` | Application package |
| `src/ksec/cli/` | One module per CLI group, `main.py` = parser/wiring |
| `src/ksec/bootstrap.py` | Composition root — builds and wires every service |
| `migrations/` | Ordered SQL migrations (`001`–`008`) |
| `plugins/` | Plugin tree (`plugins/web/http_headers/` bundled example) |
| `specs/` | Master specifications the product is built against |
| `tests/` | Stdlib unittest suite |
| `scripts/smoke.sh` | End-to-end CLI smoke suite |
| `docs/` | Guides (user, walkthrough, this architecture, …) |

## Core design decisions

1. **Zero runtime dependencies.** Everything (CLI, TUI, dashboard HTTP,
   SQLite access, scrypt, curses) uses the Python standard library, so the
   tool runs on any Python 3.11+ without a package install step.
2. **Composition root.** `bootstrap.py` constructs services in dependency
   order and exposes a `KsecContext`; CLI handlers are thin. Tests build the
   same context in-memory with a temp database.
3. **Capabilities, not tools.** Workflows reference *capabilities*
   (`dns_lookup`, `port_scan`, `http_probe`, …). The `capabilities` +
   `adapters` registries map a capability to an installed Kali tool and its
   parser. A capability with no adapter/tool is reported, never crashed on.
4. **Policy is a gate, not a suggestion.** Every execution path
   (assess, workflow, scheduler, adversary exercise) resolves the target
   against the engagement scope through the policy engine before a command
   is built — and command construction is list-based argv (no shell).
5. **Extensible by plugin.** New adapters/parsers live in `plugins/` with a
   manifest (permissions, trust); see `plugins/README.md`.

## Module map

| Module | Responsibility | Spec |
|---|---|---|
| `rbac`, `authorization`, `policies` | Roles → permissions, scope matching, ALLOW/DENY/REQUIRE_* decisions | 06 |
| `identity`, `sessions` | Users (scrypt), 5-workspace sessions | 06 |
| `kali`, `installer`, `capabilities`, `adapters`, `parsers`, `execution` | Tool discovery/install, safe execution, output parsing | 04 |
| `jobs`, `scheduler`, `workflows` | Job lifecycle, concurrency, recovery, workflow engine | 07 |
| `assets`, `findings`, `evidence`, `cases`, `risk`, `correlation`, `normalization` | Security data + deterministic risk | 05 |
| `dfir` | Artifacts + incident timeline | 08 |
| `threat_intel` | IOCs (incl. auto-extraction), actors, campaigns, TTPs | 08 |
| `soc` | Normalize → enrich → correlate → rule → risk → alert → case | 08 |
| `adversary` | Profiles, ATT&CK coverage, gated exercises | 08 |
| `plugins` | Manifest validation, trust levels, permission-controlled loading | 02/08 |
| `notifications` | Event bus + email/telegram/slack/discord/webhook providers | 02 |
| `updates` | Offline update-readiness check | 01 |
| `reporting`, `learning`, `backups` | Reports, curriculum, integrity-verified backups | 05/03 |
| `tui`, `dashboard`, `modes` | Interfaces + beginner/professional/expert explanations | 03 |

## Data flow examples

**Scan → knowledge.** `assess example.com` → policy check → scheduler job →
adapter (`dig`/`nmap`) → parser entities → auto asset registration, auto
IOC extraction, evidence stored with SHA-256.

**Event → action.** `soc ingest` → normalizer (canonical event) → enricher
(asset/IOC/findings lookup) → correlator (recent same-entity volume) → rule
engine → risk score → alert → (case auto-open) → notification.

## Database

SQLite at `$KSEC_HOME/ksec.db`, schema versioned by migrations
(`001`–`008`); `ksec doctor` verifies schema currency. Tables:

`users roles permissions role_permissions user_roles workspaces sessions
engagements authorizations audit_log tool_registry jobs assets findings
evidence cases case_findings workflow_runs learning_progress backups
notifications reports custom_workflows dfir_artifacts dfir_timeline
threat_actors campaigns ttps campaign_ttps iocs plugin_registry soc_events
detection_rules alerts advsim_profiles advsim_profile_steps
advsim_exercises advsim_exercise_steps`

## Interfaces

- **CLI** — every feature; `--json` for scripting (see
  [CLI Reference](cli-reference.md)).
- **TUI** — curses; mode-aware (beginner explains, expert shows raw
  commands). Needs a TTY.
- **Dashboard** — stdlib HTTP on `127.0.0.1`; endpoints under
  `/api/v1/` (`status`, `jobs`, `findings`, `engagements`, `assets`) plus a
  status page at `/`.
