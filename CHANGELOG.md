# Changelog

All notable changes are tracked here. Format follows
[Keep a Changelog](https://keepachangelog.com/) and semantic versioning.

## [0.2.0] - 2026-09-04

### Added — Expanded modules (spec Stages 6–8)

- Plugin architecture: `plugins/` + manifest schema + permission-controlled
  loading; bundled `web/http_headers` example plugin (migration `006`)
- RBAC `plugin.manage` permission + plugin approval workflow
- Mode-aware TUI (`--mode beginner|professional|expert`) with per-view
  explanations for beginners and raw commands/output for experts
- IOC extraction from scan results: structured entities (high confidence)
  + raw evidence text (low confidence), idempotent auto-registration on
  every completed job (`ksec intel ioc extract`)
- SOC alert pipeline: normalize → enrich → correlate → rules → risk →
  alert → case (migration `007`; `ksec soc` ingest/rule/alert/event)
- SOC alert event-driven notifications via configured providers
- Adversary simulation: profiles, TTPs, ATT&CK coverage, gated live
  exercises (migration `008`; `ksec adversary`)
- Pluggable notification providers: email / telegram / slack / discord /
  webhook (`ksec notify`)
- Update system: version / migration / plugin / rollback checks with
  backup gating (`ksec update check`)
- CLI: `plugin adversary update notify` + audit-log read (`ksec audit list`)
- End-to-end walkthrough at `docs/walkthrough.md`
- Guides: installation, CLI reference, architecture, security model,
  operations, troubleshooting, QA & release (`docs/`)
- Repeatable CLI smoke suite (`scripts/smoke.sh`, `make smoke`) — 156 checks
- Capability-as-workflow: any registered capability (incl. plugins) runs as a
  single-step workflow, e.g. `ksec run http_headers example.com`
- URL / host:port targets normalize to their host for scope matching
  (`https://example.com` matches a scope rule for `example.com`)
- Fix: parser registry resolved tool aliases but not parser names, so nmap
  jobs silently produced 0 entities; registry now resolves both
- Authorized vulnerability checks (`ksec vuln check`): deterministic
  read-only TLS/HTTP-header/banner probes -> auto findings with risk scores
- Atomic red tests (`ksec atomic`): one-technique detection-validation
  library (T1590/T1046/T1071.001/T1190/T1082), policy-gated + audited
- Adversary kill-chain (`adversary exercise chain`): executes profile steps
  in ATT&CK tactic order; reports gain per-phase technique coverage
- New tool integrations: sslscan (`tls_scan`), nikto (`web_vuln_scan`),
  gobuster (`directory_brute`) adapters + parsers + install mapping
- 286 unit tests + 164-step CLI smoke suite

## [0.1.0] - 2026-09-04

### Added — Foundation (spec Stages 1–5)

- Repository skeleton: `pyproject.toml`, README, LICENSE, Makefile
- Configuration loader (TOML, precedence, `KSEC_HOME` / `KSEC_CONFIG`)
- Structured, secret-redacting logging
- SQLite database with sequential migrations (`001`–`003`)
- Identity: users + scrypt password hashing
- RBAC: 5 workspaces, 4 roles, 16 permissions (seeded)
- Sessions with lifecycle states (5-workspace model)
- Engagements, authorizations and scope matching (IP/CIDR/domain)
- Policy engine: ALLOW / DENY / REQUIRE_CONFIRMATION / REQUIRE_AUTHORIZATION
- Append-only audit log
- Kali environment fingerprinting (`ksec env`)
- Capability registry + dynamic tool discovery (`ksec tools`)
- Safe command builder (list-based argv, no shell injection)
- Execution engine with timeouts
- Output parsers: nmap XML, dig, HTTP probe
- Tool adapters: nmap, dig, curl, null
- Jobs + central scheduler (concurrency, pause/resume/cancel, recovery)
- Workflow engine + built-in `recon` / `assess` workflows
- Asset, Finding, Evidence (SHA-256 + verify) and Case services
- Deterministic, versioned risk engine
- Controlled tool installation manager (approval + verification)
- Reporting engine (Markdown / HTML)
- Normalization + correlation engines (auto-register assets from scans)
- Learning curriculum (12 phases, 18 lessons, 5 levels) + progress
- Backup / restore with integrity verification
- Notifications + internal event bus
- TUI (curses) and local web dashboard (stdlib HTTP)
- CLI: `init status doctor version config env tools session engagement
  assess job asset finding evidence case report learn backup tui dashboard
  admin user`
- 128 unit tests