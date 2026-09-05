# Changelog

All notable changes are tracked here. Format follows
[Keep a Changelog](https://keepachangelog.com/) and semantic versioning.

## [Unreleased] — spec completion round (safety, time-bound auth, lab mode, workflow DAG/versioning, CLI)

### Added — time-bound authorization + lab mode (spec 06)

- **Time-bound authorization** (migration `014`): engagements carry an
  optional validity window (`valid_from` / `valid_until`). Engagements that
  are not yet valid or already expired are refused at the policy gate
  (`ksec engagement create --valid-from --valid-until`; `ksec engagement
  list` flags `[not-yet-valid]` / `[expired]`).
- **Lab/CTF mode enforcement**: with `[safety] lab_mode = true`, every
  target action is restricted to lab-range networks and lab-labelled
  hostnames (private/loopback CIDRs, `.test/.local/.lab/.ctf/.lan` and
  lab/ctf/target hostname markers). Public targets are denied with a clear
  reason.
- **`ksec mode` command**: `ksec mode status` shows operation + safety
  modes; `ksec mode set lab|safe|read-only on|off` persists to the config
  file without duplicating TOML tables.

### Added — workflow DAG, retry and versioning (spec 07)

- **Dependency graph (DAG)**: workflow steps accept `name` and `depends_on`
  so a step only runs after its dependencies; the engine executes steps in
  dependency order. Validation rejects unknown dependencies and cycles.
- **Retry with exponential backoff**: per-step `retry` (0-10) and
  `retry_delay` fields retry failed jobs with backoff.
- **Immutable executed versions** (migration `014`): custom workflows carry
  a `version` (bumped on every edit) and each run snapshots the exact
  definition + version that executed (`ksec workflow history` shows the
  version + snapshot).

### Added — CLI completion (spec 03/07)

- **Session switch/reconnect**: `ksec session switch <id>` pauses the
  user's other active sessions and activates the target;
  `ksec session reconnect <id>` resumes a paused session (spec 07 §31-32).
- **Tool management**: `ksec tools search`, `tools capabilities`,
  `tools docs`, `tools update`, `tools remove` and `tools list
  --category/--installed/--missing/--broken` filters.
- **Dashboard auth** (spec 06 §75): `ksec dashboard start --require-auth`
  validates a `Bearer` API token (same `ksec api` token store) on every
  request; the page prompts for a token.
- **Global flags** (spec 03): `--debug`, `--no-color`, `--profile NAME`
  (`[profiles.<name>]` config sections, deep-merged) and `--config PATH`.
  Also fixed a pre-existing argparse bug where root-level flags given
  before the subcommand (e.g. `ksec --json status`) were silently dropped.
- **Breaking rename**: `ksec adversary coverage/exercise new --profile` is
  now `--profile-id` so it cannot collide with the global `--profile` flag.

### Added — safety controls (spec 06)

- **Emergency stop** (`ksec stop --all`): cancels every non-terminal job,
  blocks new submissions, preserves evidence/state, and records an audit
  event. The flag is persisted in the database so it survives process
  restarts; `ksec stop --status` / `ksec stop --reset` manage it
  (migration `013`).
- **Rate limiting**: `[safety] rate_limit_per_minute` (global) and
  `rate_limit_per_user` sliding-window caps enforced at job submission;
  denials are audited (`policy.rate_limited`).
- **Lab mode** config flag (`[safety] lab_mode`) alongside safe/read-only.

### Added — data model completion (spec 05)

- **Evidence chain of custody** (migration `012`): every capture/verify/state
  change is appended to `evidence_custody`; `ksec evidence custody <id>`
  shows the full chain and integrity failures are recorded.
- **Case notes, timeline and reopen** (migration `012`): `ksec case note
  add|list`, `ksec case timeline`, `ksec case reopen --reason` — notes are
  append-only and every state change lands in the case timeline.
- **Finding lifecycle**: `ksec finding update <id> --status` (incl.
  `accepted_risk`), `ksec finding remediate` (owner/priority/due), and
  `ksec finding verify` — a separate verification record is required before
  a finding is marked `verified` (spec 05 #38).
- **Database introspection**: `ksec db version|health|repair` (integrity
  check, foreign keys, migrations, storage, WAL checkpoint + reindex).
- **Auditable exports**: `ksec export case|findings|evidence|assets` — JSON
  with schema/export versioning, provenance and chain-of-custody included.

### Added — new modules (spec 08)

- **GRC/Compliance** (`ksec grc`): NIST 800-53, CIS, OWASP, ISO/IEC 27001,
  SOC 2 and PCI DSS control mappings (versioned) over deterministic checks
  (audit, scope, authorization, evidence integrity, backups, TLS, headers,
  banners). `ksec grc check` stores every run as evidence + audit.
- **Malware analysis** (`ksec malware analyze`): static-only pipeline
  (hash, format detection PE/ELF/Mach-O/ZIP/PDF/script, strings, entropy),
  hashes auto-registered as IOCs, analysis stored as evidence — the sample
  is never executed.
- **Endpoint security** (`ksec endpoint`): read-only local inventory
  (host, processes, users, listening sockets) parsed from `/proc`;
  passive `check` flags root-equivalent accounts and exposed listeners and
  can create findings.
- Knowledge base grew to 52 topics (grc, malware, endpoint, stop-emergency,
  role-blackhat). `ksec role blackhat` is the black-hat mindset playbook —
  full kill-chain emulation that stays inside engagement scope (controlled
  adversary simulation, spec 06 #28).
- 414 unit tests + QA gate (compile/AST/marker/knowledge sweeps).

## [0.3.0] - 2026-09-04 — real-use power round

### Added — SOC intake & forensics round

- **SIEM auto-ingestion** (`ksec siem`, spec: real SOC intake): UDP
  syslog-style listener (`listen`) and file/directory watcher (`watch`) that
  parse RFC3164 syslog, JSONL and auditd key=value records into the SOC
  pipeline. Parsed events carry deterministic ids so re-sent bursts dedupe;
  IPs/domains inside message text are extracted by the normalizer so
  syslog lines enrich/correlate like any other event (`siem demo` shows all
  formats).
- **Windowed detection rules** (migration `011`): `soc rule add ...
  --within <minutes> --count <N>` — count-based rules fire exactly once when
  the incoming event crosses the threshold inside the window (e.g. 5
  auth_failures from one IP in 5 minutes = brute-force alert). Windowed
  evaluation is SQL over stored events; supported operators eq/contains/
  min_severity; `window_count`/`window_minutes` columns.
- **Interactive dashboard**: SOC triage views (alerts/cases) with
  ack/resolve/close buttons (`/api/v1/alerts`, `/api/v1/cases` +
  POST actions); every write is audited with actor `dashboard`. Read-only
  overview now reports alert/case counts.
- **Plugin scaffold** (`ksec plugin new`): generates a ready-to-fill plugin
  (manifest.json + adapter.py + parser.py + README) with normalized
  underscore capabilities; scaffolded plugins pass `plugin check`.
- **DFIR forensics extras**: `dfir artifact hash` records SHA-256/SHA-1 +
  size of a collected file on the artifact (audited); `dfir export` writes
  the merged artifact+event chronology as CSV or JSONL.
- Knowledge base grew to 47 topics (siem, windowed-rules, api, schedules,
  dashboard, whatweb, theHarvester, nuclei, whois + refreshed
  dfir/plugins/learner cards).
- CI upgraded to a full QA gate: unit matrix on Python 3.11/3.12/3.13 +
  compile/AST sweep + `TODO`/`FIXME`/`XXX` marker check + CLI boot check
  (test job) and the full 201-check CLI smoke suite with minimal Kali
  tools (smoke job). QA/release numbers synced (387 unit / 201 smoke /
  migrations 001-011).
- Arsenal +2: **whatweb** (web_fingerprint — server/framework/title/IP
  fingerprints as host + web_tech entities) and **theHarvester**
  (osint_harvest — passive emails/hosts/IPs from public sources; default
  crtsh source). Both live-verified: whatweb against example.com (assets
  registered from host entities), theHarvester against iana.org (10
  entities, subdomains auto-registered as domain assets).

### Added

- Real offensive arsenal: five production Kali integrations wired through
  the authorized pipeline (capability → scope policy → adapter → parser →
  assets/IOCs): wpscan (WordPress/CVE findings), hydra (authorized online
  auth testing → confirmed-login findings), enum4linux (SMB shares /
  null-session), smbmap (share access map), dnsrecon (deep DNS
  enumeration; scheduler now parses a configurable output stream because
  dnsrecon ≥ 1.6 logs to stderr)
- **In-tool mentor**: `ksec ask "<question>"` answers anything in plain
  language — security concepts from absolute zero (IP, ports, DNS, TLS,
  IOCs, risk, engagement/scope), every integrated tool card, four role
  playbooks (`ksec role red|blue|purple|learner`) and module guides — and
  always suggests the exact command to run next. Fully offline,
  deterministic keyword routing (Roman-Urdu questions like "nmap kya hai"
  route correctly), mode-aware, `--json`, `--list`
### Added — automation & reporting polish

- **Recurring job schedules** (migration `009`): `ksec job schedule
  add <capability> <target> --cron '0 6 * * *'` with deterministic
  5-field cron matcher (`*`, `*/step`, ranges, lists). Creation runs a
  policy/scope check so automation can never target an unauthorized
  host; due schedules fire through the normal scheduler + audit trail;
  `list | remove | run <id>` (run-now waits for completion)
- Report **executive summary**: every Markdown/HTML report now opens with
  severity counts, the highest-risk findings and a recommended next
  step — written for non-technical readers
- SOC triage **actor attribution**: `ksec soc alert action
  ack|resolve|close` and `ksec case close` accept optional `--user`
  and record the acting analyst in the audit log

### Added — REST API (scripts / SIEM integration)

- `ksec api token create|list|revoke` (migration `010`): SHA-256-hashed,
  revocable bearer tokens owned by a platform user; plaintext shown once
- `ksec api serve`: stdlib JSON API on localhost — reads
  (status/jobs/assets/findings/alerts/cases/engagements/sessions/iocs/
  tools/audit-gated) and writes (SOC ingest, alert ack/resolve/close,
  case close, capability runs with dry-run and live scope checks) — all
  through the same services, policy and audit trail as the CLI
- Confirmed AI-free: `dependencies = []`, offline mentor is a
  deterministic keyword router — no LLM/cloud anywhere
- 387 unit tests + 201-step CLI smoke suite (updated with this round)
- **Release 0.3.0**: all real-use rounds above (arsenal + mentor +
  automation + SOC intake + API + dashboard + forensics + QA gate)
  consolidated into one versioned, push-ready product.

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
- Case lifecycle closure exposed on the CLI (`ksec case close <id>`)
- 286 unit tests + 165-step CLI smoke suite

### Fixed — review round (spec 06 audit + error-path hardening)

- DFIR: `dfir artifact add` / `dfir event add` against an unknown case
  (or unknown evidence / artifact id) now fail with a clean
  "Unknown case/evidence/artifact" error instead of a raw
  `sqlite3.IntegrityError` traceback
- SOC intake: `--event-json` no longer silently drops CLI flags
  (`--event-id`, `--ip`, ...) — flags now fill keys missing from the JSON
- Audit coverage (spec 06): alert create/ack/resolve, case create/add-finding/
  status, and DFIR artifact/event actions now emit audit events, so SOC
  triage → case closure is fully traceable in `ksec audit list`
- Audit coverage for the core operational trail: engagement creation and
  scope allow/deny changes (`authz.engagement.create`, `authz.scope.add`)
  and every tool/job submission (`job.submit:<capability>`, actor + target +
  session + workspace) now land in the audit log — previously only
  `session.open` appeared while real tool execution ran unaudited
- 294 unit tests + 165-step CLI smoke suite

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