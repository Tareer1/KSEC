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
- [x] SQLite database with sequential migrations (`001`–`011`)
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
- [x] Kali tool integrations: nmap, dig, curl + **sslscan, gobuster, nikto, wpscan, hydra, enum4linux, smbmap, dnsrecon, whatweb, theHarvester** (adapters+parsers+install mapping) — 19 integrated tools, live-verified
- [x] **In-tool mentor** — `ksec ask` answers anything in plain language inside the tool (security concepts from zero, every tool card, module guides) and `ksec role red|blue|purple|blackhat|learner` shows the exact step-by-step playbook for each team; fully offline, no AI dependency — `blackhat` is controlled authorized emulation of the real intruder mindset (spec 06 §28), never unrestricted activity
- [x] **Recurring jobs** (cron automation): `ksec job schedule add <capability> <target> --cron '0 6 * * *'` — policy-checked at creation, fires through the same scheduler + audit trail (`ksec job schedule list|remove|run`)
- [x] Report **executive summary**: auto severity counts + top-risk findings + recommended next step at the top of every Markdown/HTML report
- [x] SOC triage actor audit: `soc alert action ack/resolve/close` and `case close` accept `--user`, recording who acted in the audit log
- [x] **REST API** (`ksec api`): SHA-256-hashed revocable bearer tokens + stdlib JSON server — reads (status/jobs/assets/findings/alerts/cases/engagements/sessions/iocs/tools/audit) and writes (SOC ingest, alert/case actions, scope-checked capability runs) all behind the same policy + audit as the CLI
- [x] **SIEM auto-ingestion** (`ksec siem`): UDP syslog-style listener + file/directory watcher — parses RFC3164 syslog, JSONL and auditd key=value records and pushes every line through the normal SOC pipeline with deterministic dedup (`ksec siem listen|watch|demo`)
- [x] **Windowed detection rules**: `ksec soc rule add ... --within <minutes> --count <N>` fires once when N matching events occur inside the window (brute-force detection) — migration `011`
- [x] **Emergency stop** (`ksec stop --all`): cancels every non-terminal job, blocks new submissions persistently (survives restarts), preserves evidence, audited — `stop --status` / `stop --reset`
- [x] **Rate limiting**: `[safety] rate_limit_per_minute` (global) + `rate_limit_per_user` sliding-window caps on job submission, audited denials
- [x] **Finding lifecycle**: `ksec finding update <id> --status`, `ksec finding remediate`, `ksec finding verify` (separate verification records), `ksec finding remediations` — spec remediation engine
- [x] **Case notes + timeline + reopen**: `ksec case note add|list`, `ksec case timeline`, `ksec case reopen --reason` — migration `012`
- [x] **Evidence chain of custody**: every capture/verify/action recorded (`ksec evidence custody <id>`), integrity failures tracked — migration `012`
- [x] **Database introspection**: `ksec db version|health|repair` (integrity, foreign keys, migrations, WAL checkpoint/reindex)
- [x] **Auditable exports**: `ksec export case|findings|evidence|assets` — JSON with provenance + chain of custody
- [x] **GRC/Compliance** (`ksec grc`): NIST 800-53 / CIS / OWASP / ISO 27001 / SOC 2 / PCI DSS controls mapped to deterministic checks; snapshots stored as evidence — migration `012`
- [x] **Malware analysis** (`ksec malware analyze`): static-only hash/format/strings/entropy, hashes auto-registered as IOCs, evidence stored — never executes the sample
- [x] **Endpoint security** (`ksec endpoint`): read-only host/process/user/listening-socket inventory from /proc; passive checks + optional findings
- [x] **Interactive SOC dashboard**: alert ack/resolve/close + case close from the browser (`ksec dashboard start`), audited as actor `dashboard`; optional bearer-token auth (`--require-auth`, spec 06 §75) — page prompts for a `ksec api` token and every request is validated
- [x] **Time-bound authorization**: `ksec engagement create --valid-from --valid-until` — engagements outside their validity window are refused at the policy gate (spec 06 §54), migration `014`
- [x] **Lab/CTF mode**: `ksec mode set lab on` restricts every target action to lab ranges/hostnames; `ksec mode status|set lab|safe|read-only on|off` persists to the config file (spec 06 §56)
- [x] **Workflow DAG + retry**: custom workflow steps support `name`, `depends_on` (dependency ordering, cycle/unknown-dep validation) and `retry`/`retry_delay` (exponential backoff) — spec 07, migration `014`
- [x] **Workflow versioning**: custom workflows carry a `version` bumped on every edit; each run snapshots the exact definition + version it executed (`ksec workflow history` shows immutable snapshots) — spec 07
- [x] **Session switch/reconnect**: `ksec session switch <id> --user ...` pauses the user's other active sessions while activating the target; `ksec session reconnect <id>` resumes a paused session (spec 07 §31-32)
- [x] **Tool management** (`ksec tools`): `search`, `capabilities`, `docs`, `update`, `remove`, plus `list --category/--installed/--missing/--broken` filters (spec 03)
- [x] **Global CLI flags**: `--debug`, `--no-color`, `--profile NAME` (config `[profiles.<name>]` sections) and `--config PATH` (spec 03); root-level flags now survive subcommand parsing
- [x] **Plugin scaffold** (`ksec plugin new`): generates a valid manifest + adapter + parser skeleton with normalized capabilities
- [x] **DFIR forensics extras**: `dfir artifact hash` (SHA-256/SHA-1 of a collected file) + `dfir export` (chronology as CSV/JSONL)
- [x] **100% AI-free**: zero dependencies (`dependencies = []`), fully offline — the `ksec ask` mentor is a deterministic keyword router over curated topics, no LLM/cloud of any kind
- [x] **5 domain modules** (`ksec module`): API Security, Wireless, Cloud, Container and Kubernetes — each declares its Kali tools, reports which are installed and runs deterministic offline posture checks (spec 08 #23-27), migration `015`
- [x] **Purple team exercises** (`ksec purple exercise`): coordinated red+blue lifecycle — new/start/complete tallies findings (red), open alerts (blue) and fired detections, then reports detection coverage (spec 08 #28), migration `015`
- [x] **Change detection** (`ksec change`): baselines over assets/findings/jobs/config + deterministic drift scans that flag added/removed/changed state and raise notifications (spec 08 #59), migration `015`
- [x] **Job operations**: `ksec job logs <id>` (captured stdout/stderr), `job retry <id>` (fresh resubmit, never re-runs the record), `job trace <id>` (session/schedule/audit lineage) and `job health` (live scheduler state)
- [x] **Report preview + PDF export**: `ksec report preview` renders a report without storing it; `report create --format pdf` and `report export <id>` write a printable PDF — pure stdlib, zero dependencies
- [x] **Activity views**: `ksec history` (chronological timeline across runs/audit/jobs) and `ksec graph` (engagements → assets → findings → cases/evidence relationships)
- [x] **Learn practice drills** (`ksec learn practice`): hands-on authorized drills with per-user attempts + pass status (`practice list|start|pass`), migration `015`
- [x] **Event-driven workflow triggers** (`ksec workflow trigger`): event_type + target-glob → workflow bindings fired through the normal policy gate (`trigger add|list|remove|enable|disable|fire`), beyond cron schedules, migration `015`
- [x] **Real-world red team — exploit intelligence** (`ksec exploit`): local Exploit-DB lookup maps discovered software versions to known public exploits (`exploit search` / `exploit map` — auto-findings for verified exploits with CVE + EDB-ID). New scope-gated offensive capabilities: `cve_scan` (nuclei — 7000+ CVE templates), `sqli_test` (sqlmap), `web_fuzz` (ffuf), `smb_cred_test` (nxc) and the `exploit_lookup` workflow
- [x] **Alternate-tool dispatch** (`--options '{"tool": "..."}'`): the same capability can use a different provider — `port_scan` via `masscan` (high-speed), `web_fuzz` via `wfuzz`, `dns_enum` via `dnsenum`, `subdomain_enum` via `amass` (deep OSINT). New workflows: `fast_scan` (masscan range scan), `subdomain` (deep subdomain discovery), `wifi` (AP discovery)
- [x] **Wireless capabilities**: `wifi_scan` (iwlist — AP discovery: BSSID/ESSID/channel/encryption) and `wifi_crack` (aircrack-ng — WPA/WEP key recovery from captured handshakes), both scope-gated like every capability
- [x] **DOCX report export**: `report create --format docx` and `report export <id> --format docx` write a real editable Word document — pure stdlib (zipfile/XML), zero dependencies
- [x] **Extended ATT&CK coverage**: adversary/atomic exercises now map 21 techniques across all 14 kill-chain phases (adds T1505.003, T1078, T1003, T1213, T1041, T1485)
- [x] **Full catalog runnable**: whois_lookup, traceroute and password_crack (john — offline hash cracking) gained real adapters, closing the last "listed but not runnable" gap; every catalog tool now runs through the policy gate
- [x] **Service enumeration**: `snmp_enum` (snmpwalk + onesixtyone community discovery) and `smtp_enum` (smtp-user-enum VRFY/RCPT/EXPN) capabilities + the `enumerate` workflow
- [x] CLI: `init status doctor version config env tools session engagement
      assess job asset finding evidence case report learn workflow dfir intel
      plugin adversary vuln atomic soc siem run backup tui dashboard ask role api
      stop db export grc malware endpoint mode module purple change history graph`
- [x] 514 unit tests (stdlib unittest, no dependencies) + 383-check CLI smoke suite
  (`python3 -m unittest discover -s tests` / `bash scripts/smoke.sh`)
- [x] Migrations `001`–`015`
- [x] **v0.6.0** — changelog in `CHANGELOG.md`; docs in [`docs/`](docs/README.md)

## Requirements

- **Kali Linux** (recommended — KSEC discovers the tools already installed)
  or any Debian-based Linux with Python **3.11+**
- Python 3 only — **zero third-party dependencies** (`dependencies = []`),
  100% offline, **no AI / no cloud**

## Install on Kali Linux

### Fastest — one command (recommended)

Works on Kali's externally managed Python (PEP 668) — no sudo, no manual
venv, no rc-file editing. The installer clones KSEC into `~/KSEC`, creates
a `.venv`, pip-installs it (zero dependencies) and symlinks the `ksec`
command into `~/.local/bin` so it works in any new terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/Tareer1/KSEC/main/install.sh | bash
```

…or, from a clone:

```bash
cd KSEC && bash install.sh
```

Customize the install location with `KSEC_DIR=/opt/KSEC bash install.sh`.

### Manual — quick clone & run (no install, ~10 seconds)

```bash
git clone https://github.com/Tareer1/KSEC.git ~/KSEC
cd ~/KSEC
export PYTHONPATH=src            # point Python at the source
python3 -m ksec --version
```

### Manual — install the `ksec` command (venv, PEP 668-safe)

```bash
cd ~/KSEC
python3 -m venv .venv
source .venv/bin/activate       # every new terminal needs this line
pip install -e .
ksec version
```

> **Tip:** if you don't want to activate the venv every time, add
> `alias ksec='/home/<user>/KSEC/.venv/bin/ksec'` to your shell rc —
> `~/.zshrc` on Kali (the default shell is zsh, not bash).

After any option, run the one-time initialization:

```bash
ksec init --username admin --password 'change-me'   # creates config, DB, roles, admin
ksec status                                          # is everything healthy?
ksec doctor                                           # full health checks
ksec tools list                                       # which Kali tools KSEC found
```

> KSEC stores its state in `~/.config/ksec/` (override with `KSEC_HOME`).
> Nothing ever leaves your machine.

## First run — the 5-command loop

KSEC only runs against **authorized targets** (written scope) — this is the
core safety model. The daily pattern is always:

```bash
# 1. Authorization first (without this nothing runs)
ksec engagement create --name pentest-1
ksec engagement scope add --engagement 1 --target example.com --effect allow

# 2. Open a role + workspace session
ksec session open --user admin --password 'change-me' --workspace RED_TEAM --role admin

# 3. Run a workflow — KSEC picks the right Kali tool itself
ksec assess example.com --engagement 1 --user admin --password 'change-me' --workflow recon

# 4. Document what you found
ksec finding create --title "Open port 443" --severity medium --risk --engagement 1
ksec evidence add --content "..." --tool nmap --engagement 1
ksec case create --title "Issue #1" --engagement 1

# 5. Produce the report
ksec report create --engagement 1 --title "Pentest Report"
ksec report export 1 --out report.pdf
```

Try it with `--dry-run` first to see the policy plan without executing:

```bash
ksec assess example.com --engagement 1 --user admin --password 'change-me' --dry-run --explain
```

## Every command group

```bash
ksec init status doctor version config env          # core
ksec admin                                          # users, roles, RBAC
ksec session                                        # 5-workspace sessions
ksec engagement                                     # authorized scope
ksec recon network web research osint                 # top-level workflow shortcuts
ksec assess / ksec run / ksec workflow              # run workflows (DAG, retry)
ksec job                                            # jobs, schedules, retry, logs
ksec module                                         # api/wireless/cloud/container/k8s
ksec tools                                          # Kali tool discovery
ksec asset finding evidence case report             # security data
ksec exploit                                        # version -> known public exploits (local Exploit-DB)
ksec purple                                         # coordinated red+blue exercises
ksec change                                         # baseline + drift detection
ksec soc siem                                       # alert pipeline + ingestion
ksec dfir intel malware endpoint grc                # DFIR, intel, malware, GRC
ksec adversary atomic                               # adversary simulation
ksec learn                                          # curriculum + practice drills
ksec role / ksec suggest / ksec ask                 # in-tool mentor (offline)
```

Run any group with `--help` for its full subcommands:

```bash
ksec module --help
ksec purple --help
ksec report --help
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