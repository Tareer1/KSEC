# KSEC — All-in-One Kali Linux Security Operations Platform

> **Don't reinvent Kali. Orchestrate Kali.**
> **Made by REBEL.**

KSEC is a modular, local-first, AI-free security operations platform for
Kali Linux. It provides one unified interface through which authorized
security professionals, researchers, defenders, learners and testers run
their workflows — while KSEC orchestrates the underlying Kali tools behind
the scenes.

This repository is being built directly against the master specification
documents in [`specs/`](specs/). User documentation lives in
[`docs/`](docs/README.md) — start with the
[User Guide](docs/user-guide.md), which covers every implemented command, or the
[End-to-End Walkthrough](docs/walkthrough.md), a real run through every module
with captured output.

| File | Topic |
|------|-------|
| `01-master-product-spec.md` | Product vision, workspaces, learning, requirements |
| `02-architecture-repo-structure.md` | Architecture & repository structure |
| `03-cli-tui-ux.md` | CLI, TUI & 5-terminal UX |
| `04-kali-integration-tools.md` | Kali integration & tool/capability system |
| `05-database-evidence-cases.md` | Database, shared state, evidence, cases |
| `06-security-rbac-safety.md` | Security, RBAC, authorization & safety |
| `07-workflow-scheduler.md` | Workflow, automation, scheduler engine |
| `08-security-modules.md` | All security modules & operational capabilities |
| `09-testing-qa-release.md` | Testing, QA, deployment & release |
| `10-docs-operations-dod.md` | Documentation, operations & Definition of Done |

## Status

Implemented so far (spec Stages 1–9 core, interfaces included):

- [x] Repository skeleton + GitHub-ready files (SECURITY, CONTRIBUTING, CI, templates)
- [x] Configuration loading (TOML, precedence, `KSEC_HOME` / `KSEC_CONFIG`)
- [x] Structured, secret-redacting logging
- [x] SQLite database with sequential migrations (`001`–`008`)
- [x] Identity: users + scrypt password hashing
- [x] RBAC: workspaces, roles, permissions (seeded)
- [x] Sessions (5-workspace model)
- [x] Authorization / engagement scope records (CIDR/domain matching)
- [x] Policy engine (ALLOW / DENY / REQUIRE_CONFIRMATION / REQUIRE_AUTHORIZATION)
- [x] Append-only audit log (read via `ksec audit list`, `audit.read` permission)
- [x] Kali environment fingerprinting (`ksec env`)
- [x] Capability registry + dynamic tool discovery (`ksec tools`)
- [x] Safe command builder + execution engine
- [x] Output parsers (nmap XML, dig, HTTP probe)
- [x] Tool adapters (nmap, dig, curl, null) + adapter registry
- [x] Jobs + central scheduler (concurrency, pause/resume/cancel, recovery)
- [x] Workflow engine + built-in workflows (`recon`, `assess`) + auto asset registration
- [x] User-defined workflows: `ksec workflow create/edit/validate/run/history` + `ksec run` alias
- [x] Assets, Findings, Evidence (SHA-256 + verify), Cases
- [x] Deterministic, versioned risk engine
- [x] Controlled tool installation manager (`ksec tools install`)
- [x] Reporting engine (Markdown/HTML, `ksec report`)
- [x] Normalization + correlation engines
- [x] DFIR module: forensic artifacts + incident timeline (`ksec dfir`)
- [x] Threat intelligence: IOCs (normalized + correlated + **auto-extracted from job evidence**), actors, campaigns, TTPs, enrichment (`ksec intel`)
- [x] SOC alert pipeline: normalize -> enrich (asset/IOC) -> correlate -> rules -> risk -> alert -> case (`ksec soc ingest|alert|rule|event`)
- [x] Learning curriculum (12 phases, 5 levels) + progress (`ksec learn`)
- [x] Backup/restore with integrity verification (`ksec backup`)
- [x] Notifications + event bus
- [x] TUI (`ksec tui`) and local web dashboard (`ksec dashboard`)
- [x] Beginner/Professional/Expert operation modes (`--mode`, config `core.mode`)
- [x] Tool + result explanation system (`ksec tools explain`, `ksec assess --explain`, `ksec finding explain`)
- [x] Mode-aware TUI: beginner = plain-language explanations, expert = raw commands & detail (`ksec tui --mode beginner|expert`)
- [x] Plugin architecture: `plugins/` tree, manifest (permissions/trust/capabilities), permission-controlled loading, bundled example plugin (`ksec plugin list|install|enable|disable|uninstall|check`)
- [x] IOC extraction from scan results: auto-register IOCs from job evidence (`ksec intel ioc extract`)
- [x] Adversary simulation: profiles, ATT&CK technique coverage, policy-gated dry/live exercises + reports (`ksec adversary`)
- [x] Notification providers: email / telegram / slack / discord / webhook (`ksec notify`, config `[notifications.providers]`)
- [x] SOC alerts notify event-driven through configured providers
- [x] Offline update-readiness check: version, migrations, plugins, rollback gating (`ksec update check`)
- [x] Authorized vuln checks: deterministic TLS/header/banner probes → auto findings (`ksec vuln check`)
- [x] Atomic red tests for detection validation (`ksec atomic list|info|run`)
- [x] Adversary kill-chain execution (ATT&CK tactic order) + per-phase coverage reports (`ksec adversary exercise chain`)
- [x] Kali tool integrations: nmap, dig, curl + **sslscan, gobuster, nikto** (adapters+parsers+install mapping)
- [x] CLI: `init status doctor version config env tools session engagement
      assess job asset finding evidence case report learn backup tui dashboard
      admin user audit plugin intel dfir soc workflow adversary vuln atomic update notify run`
- [x] 294 unit tests (stdlib unittest, no dependencies) + 165-step CLI smoke suite
  (`python3 -m unittest discover -s tests` / `bash scripts/smoke.sh`)
- [x] v0.2.0 — changelog in `CHANGELOG.md`; docs in [`docs/`](docs/README.md)

## Quick start (no installation required)

```bash
# Run from the repository root
export PYTHONPATH=src

# Initialize: creates config, database, roles and the admin user
python3 -m ksec init --username admin --password 'change-me'

# Check platform status and health
python3 -m ksec status
python3 -m ksec doctor

# User management
python3 -m ksec admin user list
python3 -m ksec admin user create --username analyst --password 's3cret' --role operator

# Or install the `ksec` command into your environment
pip install -e .
ksec version
```

## Architecture

```text
KALI LINUX
    │
    ▼
KSEC CORE  (CLI / TUI / Dashboard)
    │
    ├── SESSION MANAGER ── WORKSPACE MANAGER (5 workspaces)
    ├── POLICY ENGINE ── AUTHORIZATION ── RBAC
    ├── WORKFLOW ENGINE ── JOB SCHEDULER
    ├── CAPABILITY REGISTRY ── ADAPTERS ── PARSERS
    └── ASSETS ── FINDINGS ── EVIDENCE ── RISK ── CASES ── REPORTS
```

## Principles

- **AI-free** — no LLM/cloud API dependency; works offline.
- **Kali-aware** — dynamically discovers installed tools and capabilities.
- **Safe** — authorization, scope and RBAC are enforced by the core.
- **Explainable** — every decision carries a deterministic reason.
- **Recoverable** — jobs and state survive failures where possible.

## Development

```bash
make test      # run the unit test suite (stdlib unittest, no deps)
make run       # run the CLI
```

## End-to-end example

```bash
export PYTHONPATH=src
python3 -m ksec init --username admin --password 'change-me'

# Scope: engagement 1 is authorized for the 10.0.0.0/8 range
python3 -m ksec engagement create --name "Authorized test"
python3 -m ksec engagement scope add --engagement 1 --target 10.0.0.0/8

# Out-of-scope targets are blocked by the policy engine
python3 -m ksec assess 172.16.0.5 --engagement 1 --user admin --password 'change-me' --dry-run

# Real run: executes dig + nmap through the scheduler
python3 -m ksec assess 10.0.0.5 --engagement 1 --user admin --password 'change-me' --workflow recon

# Security data
python3 -m ksec evidence add --content "port 22/tcp open" --tool nmap --operator admin
python3 -m ksec evidence verify 1
python3 -m ksec finding create --title "SSH exposed" --severity high --risk
python3 -m ksec case create --title "Assessment findings" --severity high
python3 -m ksec case add-finding --case 1 --finding 1
```