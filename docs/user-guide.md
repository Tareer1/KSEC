# KSEC User Guide

KSEC is an all-in-one security operations platform for Kali Linux. It
orchestrates Kali security tools behind one unified interface: you interact
with `ksec`, not with dozens of separate tools. Everything runs locally,
works offline, and never depends on AI/cloud services.

This guide covers **every implemented command**. Run
`python3 -m ksec COMMAND --help` for the exact flags of any command.

---

## Table of contents

1. [Getting started](#1-getting-started)
2. [Global options](#2-global-options)
3. [Configuration and environment](#3-configuration-and-environment)
4. [Core commands](#4-core-commands)
5. [User administration](#5-user-administration)
6. [Environment and tools](#6-environment-and-tools)
7. [Sessions](#7-sessions)
8. [Engagements and scope](#8-engagements-and-scope)
9. [Assessment and workflows](#9-assessment-and-workflows)
10. [Jobs](#10-jobs)
11. [Security data: assets, findings, evidence, cases](#11-security-data)
12. [Reporting](#12-reporting)
13. [Learning](#13-learning)
14. [Backup and recovery](#14-backup-and-recovery)
15. [DFIR: digital forensics](#15-dfir)
16. [Threat intelligence](#16-threat-intelligence)
17. [SOC alert pipeline](#17-soc-alert-pipeline)
18. [Operation modes and explanations](#18-operation-modes-and-explanations)
19. [Interfaces: TUI and dashboard](#19-interfaces)
20. [End-to-end example](#20-end-to-end-example)
21. [Plugins](#21-plugins)
22. [Adversary simulation](#22-adversary-simulation)
23. [Notifications](#23-notifications)
24. [Updates](#24-updates)
25. [Vulnerability checks](#25-vulnerability-checks)
26. [Atomic red tests](#26-atomic-red-tests)
27. [In-tool mentor](#27-in-tool-mentor)
28. [Tips and troubleshooting](#28-tips-and-troubleshooting)

---

## 1. Getting started

```bash
export PYTHONPATH=src            # run from the repository root

# One-time initialization: writes config, creates the database,
# seeds roles/workspaces, and creates the admin user.
python3 -m ksec init --username admin --password 'change-me'

# Check that everything is healthy.
python3 -m ksec doctor
python3 -m ksec status
```

> **Authorized use only.** KSEC is for testing systems you own or have
> written permission to test. Scope is enforced by the policy engine.

---

## 2. Global options

Every command accepts these flags, either before or after the subcommand:

| Flag | Meaning |
|------|---------|
| `--json` | Machine-readable JSON output |
| `-q`, `--quiet` | Reduce output (IDs/names only) |
| `--verbose` | Extra diagnostics (e.g. risk reasoning) |
| `--version` | Show version and exit |

Examples:

```bash
python3 -m ksec status --json
python3 -m ksec admin user list -q
```

---

## 3. Configuration and environment

KSEC state lives in a data directory; all paths are overridable via
environment variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `KSEC_HOME` | Data directory (database + logs) | `~/.local/share/ksec` |
| `KSEC_CONFIG` | Config file path | `~/.config/ksec/config.toml` (or `./ksec.toml`) |

Configuration is TOML with precedence: *defaults < config file < CLI*.
`ksec init` writes a documented config file. View the effective
configuration with:

```bash
python3 -m ksec config show
```

Key settings (edit the config file to change):

```toml
[core]
data_dir = "/home/user/.local/share/ksec"
log_level = "INFO"

[scheduler]
max_concurrent_jobs = 2
default_timeout_seconds = 300

[safety]
require_authorization = true
safe_mode = false
read_only = false

[audit]
enabled = true
```

---

## 4. Core commands

```bash
python3 -m ksec init                     # initialize (idempotent)
python3 -m ksec status                   # platform status
python3 -m ksec doctor                   # health checks
python3 -m ksec version                  # version + Python
python3 -m ksec config show              # effective configuration
python3 -m ksec env                      # environment fingerprint
```

`ksec env` reports OS/Kali release, kernel, architecture, runtime (bare
metal / VM / WSL / container), privilege level and network state — all
without making network calls.

---

## 5. User administration

```bash
python3 -m ksec admin user create --username analyst \
    --password 's3cret' --role operator --display-name "Analyst"
python3 -m ksec admin user list
```

Roles (seeded at init):

| Role | Permissions |
|------|-------------|
| `admin` | Everything (including `users.manage`, `roles.manage`, `tools.install`) |
| `operator` | Run assessments/recon, manage findings/evidence/cases, generate reports |
| `auditor` | Read-only: audit log, reports, tool list |
| `learner` | Learning curriculum only |

Passwords are hashed with scrypt (never stored in plain text). If
`--password` is omitted, one is generated and printed to stderr once.

The append-only audit log is read via `ksec audit` (requires the
`audit.read` permission — `admin` or `auditor`):

```bash
python3 -m ksec audit list --user auditor --password 'change-me'
python3 -m ksec audit list --user auditor --password 'change-me' \
    --event-type admin.user.create --actor admin --json
```

---

## 6. Environment and tools

```bash
python3 -m ksec tools list                # discover installed Kali tools
python3 -m ksec tools info nmap           # details for one tool
python3 -m ksec tools health              # re-check + missing capabilities
```

`tools install` is the **controlled installation** path: it finds a provider
for a missing capability, requires approval, installs via `apt-get`, and
verifies the binary:

```bash
# Show the plan without installing
python3 -m ksec tools install --capability subdomain_enum \
    --user admin --password 'change-me' --dry-run

# Approve and install (admin-only; safe mode requires confirmation)
python3 -m ksec tools install --capability subdomain_enum \
    --user admin --password 'change-me' --yes
```

Installed tools are recorded in `tool_registry` with version and health.

---

## 7. Sessions

Sessions bind a user + workspace + role. One person can hold five sessions
(one per workspace); five people can each hold one.

```bash
python3 -m ksec session open --user admin --password 'change-me' \
    --workspace RED_TEAM
python3 -m ksec session list
python3 -m ksec session status <SESSION_ID>
python3 -m ksec session pause <SESSION_ID>
python3 -m ksec session resume <SESSION_ID>
python3 -m ksec session close <SESSION_ID>
```

Workspaces: `RED_TEAM`, `BLUE_TEAM`, `RESEARCH_OSINT`,
`ADVERSARY_SIMULATION`, `LEARN_WORK`.

---

## 8. Engagements and scope

An engagement carries its own **authorization and scope** — independent of
user identity. Out-of-scope targets are blocked by the policy engine.

```bash
# Create an engagement and allowlist a scope
python3 -m ksec engagement create --name "Authorized pentest"
python3 -m ksec engagement scope add --engagement 1 --target 10.0.0.0/8
python3 -m ksec engagement scope add --engagement 1 --target .example.com
python3 -m ksec engagement scope add --engagement 1 \
    --target 192.168.1.10 --effect deny

python3 -m ksec engagement list
python3 -m ksec engagement scope list --engagement 1
```

Scope patterns support: `*`, exact IP/domain, CIDR (`10.0.0.0/8`), and
domain suffixes (`.example.com` or `example.com` matches
`sub.example.com`). Deny rules win over allow rules.

---

## 9. Assessment and workflows

The headline flow: one command runs an entire authorized assessment,
orchestrating tools under the hood.

```bash
# Policy-check first without executing anything
python3 -m ksec assess 10.0.0.5 --engagement 1 \
    --user admin --password 'change-me' --dry-run

# Real run: executes dig + nmap + curl through the scheduler
python3 -m ksec assess 10.0.0.5 --engagement 1 \
    --user admin --password 'change-me' --workflow assess
```

Built-in workflows: `recon` (dns_lookup + port_scan) and `assess`
(dns_lookup + port_scan + http_probe).

### User-defined workflows

Create reusable workflows from capability steps:

```bash
# Simple form: repeated --step flags
python3 -m ksec workflow create --name my-recon \
    --description "custom recon" \
    --step dns_lookup --step port_scan

# With options: JSON form
python3 -m ksec workflow create --name my-assess \
    --steps-json '[{"capability":"dns_lookup"},
                   {"capability":"port_scan","options":{"service_version":true,"top_ports":1000}}]'

python3 -m ksec workflow list
python3 -m ksec workflow validate --name my-recon
python3 -m ksec workflow edit --name my-recon --step traceroute   # replace steps
python3 -m ksec workflow edit --name my-recon --disable            # disable
python3 -m ksec workflow history [--name my-recon]
```

Run a workflow — either command:

```bash
python3 -m ksec workflow run my-recon 10.0.0.5 \
    --engagement 1 --user admin --password 'change-me'
python3 -m ksec run my-recon 10.0.0.5 \
    --engagement 1 --user admin --password 'change-me'   # alias
```

Validation enforces: valid name (not clashing with built-ins), at least one
step, known capabilities, safe option keys/values.

---

## 10. Jobs

Every workflow step becomes a **job** executed by the central scheduler.

```bash
python3 -m ksec job list [--state RUNNING]
python3 -m ksec job status <JOB_ID>
python3 -m ksec job pause <JOB_ID>
python3 -m ksec job resume <JOB_ID>
python3 -m ksec job cancel <JOB_ID>
```

The scheduler respects `max_concurrent_jobs`, pauses running processes
(SIGSTOP), resumes them (SIGCONT), and cancels them cleanly. Jobs
interrupted by a crash are marked FAILED on the next start — never blindly
resumed.

### Recurring schedules (cron automation)

Schedule a capability to run on a cron expression — e.g. daily
reconnaissance at 06:00:

```bash
python3 -m ksec job schedule add dns_enum example.com \
    --cron "0 6 * * *" --engagement 1 --user admin
python3 -m ksec job schedule list
python3 -m ksec job schedule run 1          # run now (waits for completion)
python3 -m ksec job schedule remove 1
```

Cron fields: `minute hour day-of-month month day-of-week` with `*`,
`*/step`, ranges and comma lists. Schedules are **policy-checked when
you create them** — an out-of-scope target is refused — and fire through
the same scheduler and audit trail as normal jobs (`workflow` is recorded
as `schedule:<id>`).

---

## 11. Security data

### Assets

```bash
python3 -m ksec asset list [--engagement N]
```

Assets are registered automatically from scan results (hosts, addresses,
domains) and can be registered manually through the service layer.

### Findings

```bash
python3 -m ksec finding create --title "Open SSH on host" \
    --severity high --confidence high \
    --engagement 1 --asset 1 \
    --risk --criticality high --exploitability medium \
    --exposure internet --impact high --evidence verified

python3 -m ksec finding list [--engagement N] [--status open] [--severity high]
```

With `--risk`, the deterministic risk engine scores the finding
(severity × criticality × exploitability × exposure × impact, discounted by
confidence, boosted by evidence quality) and attaches reasoning. Add
`--verbose` to print the full reasoning. Findings are automatically checked
against known IOCs (`ioc_matches` appears in the output when they match).

### Evidence

Evidence is hashed (SHA-256) at collection time; integrity is verifiable —
evidence must never silently change.

```bash
python3 -m ksec evidence add --content "22/tcp open ssh" \
    --tool nmap --operator admin --engagement 1
python3 -m ksec evidence add --file ./capture.pcap --tool tcpdump \
    --method "packet capture"
python3 -m ksec evidence list [--engagement N]
python3 -m ksec evidence verify 1     # exit 0 if hash matches
```

### Cases

```bash
python3 -m ksec case create --title "Incident 42" --severity high --owner analyst
python3 -m ksec case list
python3 -m ksec case add-finding --case 1 --finding 3
```

---

## 12. Reporting

Reports are generated from structured KSEC data (engagement, scope, assets,
findings, risk, evidence, cases) — never from raw tool output.

```bash
python3 -m ksec report create --engagement 1 --title "Assessment Report"
python3 -m ksec report create --engagement 1 --format html --out report.html
python3 -m ksec report list
python3 -m ksec report show 1 --raw     # print full content
```

Formats: `markdown` (default) and `html`.

Every report opens with an **Executive Summary** — severity counts, the
highest-risk findings and a recommended next step — written for
non-technical readers, followed by the full scope/assets/findings/
evidence/cases sections.

---

## 13. Learning

The built-in curriculum has 12 phases (orientation → final assessment) and
18 lessons, teaching while you work — fully offline, no AI.

```bash
python3 -m ksec learn list
python3 -m ksec learn lesson --id orientation.what-is-ksec \
    --user admin --password 'change-me'
python3 -m ksec learn complete --id orientation.what-is-ksec \
    --user admin --password 'change-me'
python3 -m ksec learn progress --user admin --password 'change-me'
```

Progress tracks per-user completion and maps to the five learner levels
(Explorer → Security Practitioner).

---

## 14. Backup and recovery

```bash
python3 -m ksec backup create            # timestamped, hashed local backup
python3 -m ksec backup list
python3 -m ksec backup verify 1         # recompute + compare SHA-256
python3 -m ksec backup restore 1 --yes  # restore (requires --yes)
```

Backups use SQLite's online backup API (consistent even with WAL active).
Restore refuses unverified backups and validates the file before
overwriting.

---

## 15. DFIR

Forensic artifacts and incident timelines.

```bash
# Collect an artifact (optionally linked to verified evidence)
python3 -m ksec dfir artifact add --case 1 --type log \
    --name /var/log/auth.log --host web-01 --tool collector \
    --evidence 2 --collected-at 2026-09-04T08:00:00Z
python3 -m ksec dfir artifact list [--case 1] [--host web-01]

# Add timeline events
python3 -m ksec dfir event add --case 1 \
    --time 2026-09-04T08:00:00Z --type auth_failure \
    --actor attacker --details "brute force on ssh"
python3 -m ksec dfir event add --case 1 \
    --time 2026-09-04T09:30:00Z --type login --actor attacker

# Chronological incident timeline
python3 -m ksec dfir timeline --case 1 [--event-type login]

# Forensics extras: hash a collected file and export the chronology
python3 -m ksec dfir artifact hash 1 --path /evidence/auth.log.bin
python3 -m ksec dfir export --case 1 --format jsonl --out case-1.jsonl
python3 -m ksec dfir export --case 1 --format csv
```

Artifact types: `file`, `log`, `process`, `network`, `auth`, `browser`,
`malware`, `registry`, `memory`, `other`.
Event types: `created`, `modified`, `deleted`, `executed`, `network`,
`login`, `auth_failure`, `privilege`, `persistence`, `exfiltration`,
`other`.

---

## 16. Threat intelligence

IOCs (normalized at registration), threat actors, campaigns and ATT&CK TTPs.

```bash
# Actors, campaigns, TTPs
python3 -m ksec intel actor add --name "APT-X" --alias "Group Y"
python3 -m ksec intel actor list
python3 -m ksec intel campaign add --name "Operation Night" --actor "APT-X"
python3 -m ksec intel campaign list
python3 -m ksec intel ttp add --technique-id T1059 \
    --name "Command and Scripting Interpreter" --tactic execution
python3 -m ksec intel ttp list
python3 -m ksec intel link --campaign 1 --ttp 1

# IOCs
python3 -m ksec intel ioc add --value evil.example.com --type DOMAIN \
    --confidence high --source research --actor "APT-X" --campaign "Operation Night"
python3 -m ksec intel ioc list [--type IP] [--status active]

# Correlation and enrichment
python3 -m ksec intel ioc correlate --value EVIL.EXAMPLE.COM
python3 -m ksec intel ioc enrich --ioc 1

# IOC extraction from evidence
python3 -m ksec intel ioc extract --job JOB_ID        # stored job result
python3 -m ksec intel ioc extract --evidence EVIDENCE_ID
python3 -m ksec intel ioc extract --text "scan hit 203.0.113.7"
```

IOC types: `IP`, `DOMAIN`, `URL`, `HASH`, `EMAIL`, `USERNAME`, `FILE`,
`PROCESS`, `CERTIFICATE`, `OTHER`. Values are normalized (IPs canonical,
domains lowercased, hashes lowercased) so correlation is deterministic and
registration is idempotent. `finding create` auto-correlates new findings
against registered IOCs; `enrich` returns the linked actor, campaign,
campaign TTPs and related findings.

### Automatic IOC extraction from scan results

Every **completed job automatically registers IOCs** from its evidence
(spec: IOC extraction):

- **Structured entities** (parser output) become high-confidence IOCs — e.g.
  a `dns_lookup` A-record answer registers the queried domain and the IP it
  resolves to; nmap hosts register addresses and hostnames.
- **Raw tool output** is scanned for IPs (ports stripped), domains, URLs,
  emails and md5/sha1/sha256 hashes, registered at low/medium confidence.

Extraction is conservative: invalid IPs/domains are rejected, reserved names
(`example.com`, `.test`, `.local`, …) are skipped, and raw-text values that
overlap a URL are recorded once as the URL. Registration is idempotent —
re-running extraction reports `already_known` instead of duplicating.

Confidence tells you how to treat each IOC: `high` came from a structured
field, `low` from free text. Example: run `ksec run recon example.com …`,
then `ksec intel ioc list` shows `example.com` + its A-record IPs as `high`
and incidental text matches as `low`.

---

## 17. SOC alert pipeline

The SOC module turns raw security events into actionable alerts and cases
(spec 08#16-18). Every ingested event runs the full pipeline:

```text
Event -> Normalize -> Enrich -> Correlate -> Rule evaluation -> Risk score
      -> Alert -> Case
```

### Ingesting an event

```bash
# Flags for a simple event
python3 -m ksec soc ingest --event-id ev-1 --source firewall \
    --event-type port_scan --severity medium --ip 10.0.0.5

# Or a full raw event as JSON (details preserved)
python3 -m ksec soc ingest --event-json '{"event_id":"ev-2","source":"ids",
    "event_type":"beacon","severity":"high","ip":"203.0.113.66"}'
```

**Normalize** maps any event onto a canonical record: severity labels are
canonicalized (`7`→`high`, `warning`→`low`, …), IPs/domains are validated and
normalized (auto-extracted from details when not top-level), and re-ingesting
the same `event_id` is a no-op (idempotent intake).

**Enrich** resolves the event's entity (IP/domain/host) against KSEC: known
assets (with criticality), registered IOCs and open findings. **Correlate**
counts recent events sharing the same entity and their distinct sources.

**Rules and risk**: detection rules fire deterministically on normalized
fields; without a matching rule, only `high`/`critical` events alert. The
risk score (0–10) adds asset criticality, IOC confidence (+actor), related
event volume and distinct sources on top of the base severity.

```bash
python3 -m ksec soc rule add --name c2-beacon --event-type beacon \
    --field domain --operator contains --value .top --severity critical \
    --risk-boost 1
python3 -m ksec soc rule list
python3 -m ksec soc rule enable 1 | disable 1 | delete 1
```

Rules compare one normalized field (`ip`, `domain`, `host`, `username`,
`process`, `source`, `event_type`, `severity`, `details`) with an operator:
`eq`, `ne`, `contains`, `regex`, or `min_severity`.

**Windowed rules** detect bursts — e.g. 5 failed logins from one IP in 5
minutes. Add `--within <minutes> --count <N>`; the rule fires exactly once,
when the incoming event crosses the threshold inside the window (no alert
flood), and only for values matching the filter:

```bash
python3 -m ksec soc rule add --name ssh-brute --event-type auth_failure \
    --field ip --operator eq --value 203.0.113.66 --within 5 --count 5 \
    --severity high
```

### Auto-ingestion (`ksec siem`) — real log streams

Instead of typing events one by one, `ksec siem` connects live log streams
to the same pipeline:

```bash
# UDP syslog listener (point rsyslog at it: *.* @127.0.0.1:5514)
python3 -m ksec siem listen --port 5514 --source syslog

# Watch a growing log file (or a whole directory of logs)
python3 -m ksec siem watch /var/log/auth.log
python3 -m ksec siem watch /var/log --once        # bulk backfill, then exit

# See every supported format (JSONL / RFC3164 syslog / auditd key=value)
python3 -m ksec siem demo --ingest
```

Records are parsed, get deterministic ids (re-sending a burst after a
restart dedupes), and IPs/domains inside the message body are extracted — so
a raw `Failed password ... from 203.0.113.66` line enriches, correlates and
matches rules exactly like a manually typed event.

### Alerts and cases

When a rule fires (or the severity gate trips), KSEC creates an alert and
— for rule-driven or high-risk alerts — auto-opens a case linked to it:

```bash
python3 -m ksec soc alert list [--status open] [--severity high]
python3 -m ksec soc alert show 1          # full detail incl. enrichment
python3 -m ksec soc alert action ack 1    # open -> acknowledged
python3 -m ksec soc alert action resolve 1 [--case 3]
python3 -m ksec soc alert action close 1
python3 -m ksec soc event list [--entity 203.0.113.66]   # normalized events
```

Example output for a rule-matched beacon:

```text
event ev-3 (new)
  normalized: beacon [low] src=endpoint ip=203.0.113.66 domain=evil-c2.top
  enriched: asset=no ioc=yes          # IOC match: 203.0.113.66 (IP, conf=high)
  correlated: 1 related event(s) sources=ids
  rules: c2-beacon
  risk score: 5.8/10 (severity critical)
  ALERT #1 [CRITICAL] CRITICAL beacon 203.0.113.66 (rule c2-beacon)
  case #1 opened: CRITICAL alert: beacon 203.0.113.66
```

Alerts follow the spec lifecycle `open -> acknowledged -> resolved/closed`
and record acknowledgement/resolution timestamps; each alert links back to
its source event, rule, asset, IOC and case.

---

## 18. Operation modes and explanations

KSEC has three operation modes (spec: THREE OPERATION MODES). The principle:
**hide complexity, never hide useful information.**

| Mode | Who it's for | Behavior |
|------|--------------|----------|
| `beginner` | New users | Plain-language explanations, guided flow, no internals |
| `professional` | Practitioners | Technical descriptions, stages, findings (default) |
| `expert` | Power users | Everything: exact commands, adapters, privilege, raw detail |

Set the mode per command or in the config:

```bash
python3 -m ksec status --mode beginner
python3 -m ksec assess 10.0.0.5 --engagement 1 --user admin --password 'x' \
    --mode expert --explain
```

```toml
[core]
mode = "professional"   # beginner | professional | expert
```

### Explaining tools

```bash
python3 -m ksec tools explain nmap --mode beginner
python3 -m ksec tools explain nmap --mode professional
python3 -m ksec tools explain nmap --mode expert
```

Beginner example: *"This tool looks for doors that are open on a computer or
network, and what service is behind each door."* Every catalog tool has
beginner + technical descriptions, why it was selected, data collected,
risk, privilege requirements, inputs/outputs and a learn-more hint.

### Explaining assessments

`ksec assess --explain` (or `--mode beginner`, which auto-explains) adds a
per-step explanation. In expert mode the exact command is shown:

```bash
python3 -m ksec assess 10.0.0.5 --engagement 1 --user admin --password 'x' \
    --mode expert --explain
# step: dns_lookup   cmd: ['dig', '10.0.0.5']
# step: port_scan    cmd: ['nmap', '-oX', '-', '-sV', '--top-ports', '1000', '10.0.0.5']
```

### Explaining findings

```bash
python3 -m ksec finding explain 1 --mode beginner
python3 -m ksec finding explain 1 --mode expert
```

Every explanation answers: **What happened? Why does it matter? What
supports it? What should happen next?** — plus, for risk: **why did KSEC
mark it this way?** Expert mode adds confidence, recommendation, IOC
correlation matches and full risk reasoning.

---

## 19. Interfaces

### Terminal UI

```bash
python3 -m ksec tui                  # uses the configured mode (default: professional)
python3 -m ksec tui --mode beginner  # plain-language explanations everywhere
python3 -m ksec tui --mode expert    # raw commands, full findings, config detail
```

A curses-based TUI with the five workspace header, selectable views
(Status / Jobs / Sessions / Findings / Explain) and live refresh. Keys:
`1-5` switch views, `j/k` scroll, `r` refresh, `q` quit. Requires an
interactive terminal.

The TUI is **mode-aware** (spec: THREE OPERATION MODES):

- **Beginner** — every row is plain language: status explains what users,
  sessions and findings are; jobs show what each capability does ("this tool
  asks the internet's phone book…"); findings show severity in words ("serious
  issue that needs attention"); the Explain view lists each tool with a
  simple description.
- **Professional** — technical descriptions, capability names and
  severity/state labels.
- **Expert** — jobs show the exact validated command (`$ dig example.com …`)
  plus entity counts, duration and a sample of raw output; findings show
  confidence, risk score/level and the remediation; Status adds scheduler
  limits and the adapter list; the Explain view shows why/data/risk/inputs/
  outputs for every tool.

### Local web dashboard

```bash
python3 -m ksec dashboard start --host 127.0.0.1 --port 8080
# open http://127.0.0.1:8080/          (overview)
# open http://127.0.0.1:8080/soc       (SOC triage: alert buttons)
# open http://127.0.0.1:8080/cases     (cases)
```

The dashboard is **interactive SOC triage**: overview (status counts),
alerts (ack / resolve / close buttons per alert) and cases (close). Every
write is recorded in the audit log with actor `dashboard`. JSON endpoints
served over HTTP (stdlib):

- `/` `/soc` `/cases` — HTML pages
- `/api/v1/status` — platform status (+ alert/case counts)
- `/api/v1/alerts?limit=50&status=open` — alerts
- `/api/v1/cases` — cases
- `/api/v1/jobs`, `/api/v1/findings`, `/api/v1/engagements`, `/api/v1/assets`
- `POST /api/v1/alerts/<id>/action/<ack|resolve|close>`
- `POST /api/v1/cases/<id>/close`

The dashboard uses the same core services as the CLI — it cannot bypass
authorization or scope. Because it offers write buttons, keep it bound to
`127.0.0.1`; use `ksec api` (bearer tokens) for anything reachable by other
machines. Use `--background` to run it in a thread.

### REST API (`ksec api`) — for scripts / SIEM integration

A token-authenticated JSON API over the same core services (stdlib,
offline). Bearer tokens belong to a platform user and can be revoked;
write endpoints go through the same policy checks and audit trail as the
CLI — never around them.

```bash
# 1. Create a token (shown ONCE — store it safely)
python3 -m ksec api token create --name ci --user admin --password '...'

# 2. Start the API server
python3 -m ksec api serve --host 127.0.0.1 --port 9090

# 3. Use it (Authorization: Bearer <token>)
curl -H "Authorization: Bearer ksec_..." http://127.0.0.1:9090/api/v1/status
curl -X POST -H "Authorization: Bearer ksec_..." -H 'Content-Type: application/json' \
     -d '{"event_id":"e1","event_type":"auth_failure","severity":"high","ip":"203.0.113.66"}' \
     http://127.0.0.1:9090/api/v1/soc/ingest
```

Read endpoints: `status`, `jobs`, `assets`, `findings`, `alerts`, `cases`,
`engagements`, `sessions`, `iocs`, `tools`, `audit` (requires `audit.read`).
Write endpoints: `POST /api/v1/soc/ingest`, `POST /api/v1/alerts/action`
(ack|resolve|close, records the token user as actor),
`POST /api/v1/cases/close`, and `POST /api/v1/run` (capability + target +
engagement — dry-run and live runs are scope-checked; out-of-scope targets
return `403`).

```bash
python3 -m ksec api token list --user admin --password '...'
python3 -m ksec api token revoke 1 --user admin --password '...'
```

---

## 20. End-to-end example

A complete authorized workflow:

```bash
export PYTHONPATH=src

# 1. Initialize and create a user
python3 -m ksec init --username admin --password 'change-me'

# 2. Define the authorized scope
python3 -m ksec engagement create --name "Demo engagement"
python3 -m ksec engagement scope add --engagement 1 --target 10.0.0.0/8
python3 -m ksec engagement scope add --engagement 1 --target .example.com

# 3. Verify the policy gate (out-of-scope target is blocked)
python3 -m ksec assess 172.16.0.5 --engagement 1 \
    --user admin --password 'change-me' --dry-run    # exit 1, blocked

# 4. Run the assessment (executes dig + nmap + curl)
python3 -m ksec assess 10.0.0.5 --engagement 1 \
    --user admin --password 'change-me'

# 5. Review the jobs that ran
python3 -m ksec job list

# 6. Document a finding with risk + evidence + case
python3 -m ksec evidence add --content "22/tcp open ssh" \
    --tool nmap --operator admin --engagement 1
python3 -m ksec finding create --title "SSH exposed" --severity high \
    --engagement 1 --risk --criticality high
python3 -m ksec case create --title "Findings review" --severity high --engagement 1
python3 -m ksec case add-finding --case 1 --finding 1

# 7. Generate the report
python3 -m ksec report create --engagement 1 --format html --out report.html
```

---

## 21. Plugins

Plugins extend KSEC with new capabilities (adapters + parsers) without
changing core code. A plugin is a directory with a `manifest.json` plus
Python modules. The bundled example lives in
[`plugins/web/http_headers/`](../plugins/web/http_headers/README.md) and
demonstrates the full layout.

```bash
ksec plugin list                 # installed + bundled plugins
ksec plugin info http_headers    # manifest, trust, permissions, status
ksec plugin check                # validate every plugin (manifest/hash/health)

# Scaffold a new plugin: valid manifest + adapter + parser skeleton
ksec plugin new http-headers --tool curl --category web \
    --safety ACTIVE_SAFE --trust LOCAL --path ./plugins
#   -> edit ./plugins/http-headers/adapter.py + manifest.json, then install
```

**Installing a user plugin** (requires `plugin.manage` permission):

```bash
ksec plugin install /path/to/plugin-dir --trust VERIFIED \
    --user admin --password '...'
```

Trust levels gate what a plugin may do (`CORE_TRUSTED`, `VERIFIED`,
`LOCAL`, `THIRD_PARTY`, `UNTRUSTED`, `BLOCKED`); higher trust unlocks more
permissions. New plugins load **disabled** — approve them explicitly:

```bash
ksec plugin enable http_headers --user admin --password '...'
ksec plugin disable http_headers   # or: block / uninstall
```

Only enabled plugins register their capabilities with the scheduler, and
the execution gate re-checks plugin status at run time. Plugin capability
example (the bundled one):

```bash
ksec workflow run web/http_headers --target https://example.com \
    --engagement 1 --user admin --password '...'
```

Developer guide: [`plugins/README.md`](../plugins/README.md).

## 22. Adversary simulation

Emulation of known threat actors to test detections (blue team) or
validate coverage. Built around ATT&CK techniques.

**Profiles** — threat actors with mapped techniques and optional steps:

```bash
ksec adversary profile add --name apt-29 --threat-actor APT29 \
    --source mitre --technique T1071 --technique T1046 \
    --steps-json '[{"capability": "dns_lookup", "target": "{{target}}"}]'
ksec adversary profile list
ksec adversary profile show apt-29
```

**Coverage analysis** — which techniques the environment/workflow setup can
actually exercise:

```bash
ksec adversary coverage --profile apt-29
ksec adversary report <exercise-id>     # post-run technique coverage
```

**Exercises** — bind a profile to an engagement, then run dry or live:

```bash
ksec adversary exercise new --name c2-sim --profile apt-29 \
    --engagement 1 --user admin --password '...'
ksec adversary exercise list
ksec adversary exercise run <id> <target> --dry-run    # plan only
ksec adversary exercise run <id> <target> \
    --engagement 1 --user admin --password '...'       # live
```

Live runs go through the same policy engine as everything else:
out-of-scope targets are refused with `REQUIRE_AUTHORIZATION`, and every
step's outcome is recorded per technique for the coverage report.

## 23. Notifications

Recorded, event-driven alerts (e.g. SOC alerts automatically produce one)
optionally delivered to external channels via pluggable providers.

```bash
ksec notify list                 # recorded notifications
ksec notify test                 # send a test message via every provider
```

Providers are configured in `config.yaml` under
`[notifications.providers]` — `log` (default, no-op), `telegram`, `slack`,
`discord`, `webhook` (generic URL POST) or `email` (SMTP):

```toml
[notifications.providers]
soc_webhook = { type = "webhook", url = "https://hooks.example.com/ksec" }
# soc_email  = { type = "email", host = "smtp.example.com", port = 587, tls = true,
#                from = "ksec@example.com", to = "soc@example.com",
#                username = "ksec@example.com", password = "..." }
```

Delivery is best-effort and never breaks the pipeline that triggered it.
SOC alerts (section 17) automatically call `notify` with
`event_type = soc.alert` when an alert fires.

## 24. Updates

Offline-first health check before upgrading KSEC — what changed, whether
the database schema is current, and whether a safe rollback is possible.

```bash
ksec update check
```

Reports: current vs. latest known version, applied vs. pending migrations,
plugin status, and rollback readiness (a backup must exist and match before
an update is considered safe). Pairs with `ksec backup` (section 14): run a
backup first, then `ksec update check` shows rollback-ready.

## 25. Vulnerability checks

`ksec vuln` runs **deterministic, read-only checks** against an
in-scope target (TLS version, HTTP security headers, server-banner
disclosure, dev-server fingerprints) and records each positive result as a
finding with a risk score. It never exploits anything — it probes version
and configuration, then leaves analysis to the operator.

```bash
python3 -m ksec vuln checks                     # available checks
python3 -m ksec vuln check example.com \
    --engagement 1 --user admin --password '...'        # https/443 default
python3 -m ksec vuln check 127.0.0.1 --port 8000 \
    --engagement 1 --user admin --password '...'        # plain http
```

Out-of-scope targets are refused with `authorization denied`. Re-running a
check never duplicates findings (same title+engagement = skipped).

## 26. Atomic red tests

`ksec atomic` is a small Atomic-Red-Team-style library for **detection
validation**: one technique per test, executed with regular KSEC
capabilities so every run is policy-gated, scheduled and audited. After a
run, check whether your SOC/analytics noticed (each atomic prints its
`detection` hint).

```bash
python3 -m ksec atomic list
python3 -m ksec atomic info net-dns-lookup
python3 -m ksec atomic run net-port-scan example.com \
    --engagement 1 --user admin --password '...'
```

Techniques include DNS recon (T1590), port scan (T1046), HTTP C2-channel
probe (T1071.001), web recon (T1190) and service-banner grab (T1082).

The kill-chain companion: `ksec adversary exercise chain <id> <target>`
runs an exercise ordered by ATT&CK tactic phases
(reconnaissance → discovery → … → command-and-control) instead of stored
position, and `ksec adversary report <id>` shows per-phase coverage.

## 27. In-tool mentor

`ksec ask` is a built-in mentor: **ask anything in plain language and get
the answer inside the tool** — no internet, no AI dependency. Questions
can be as basic as you like ("what is an ip address") or as specific as
"hydra kya hai"; Roman-Urdu phrasing routes correctly. Every answer ends
with the exact command to run next.

```bash
python3 -m ksec ask "what is a port"            # concept, from zero
python3 -m ksec ask "nmap kya hai"              # tool card
python3 -m ksec ask "red team kaise shuru karun" # role playbook
python3 -m ksec ask "what is an ioc" --json     # structured answer
python3 -m ksec ask --list                       # every topic (38)
```

`ksec role` is a shortcut to the four team playbooks — the exact ordered
steps for that job, with copy-paste commands:

```bash
python3 -m ksec role red       # attacker: authorize -> recon -> probe -> vuln -> emulate -> document -> report
python3 -m ksec role blue      # defender: intel/rules -> ingest -> triage -> investigate -> resolve -> close
python3 -m ksec role purple    # researcher/OSINT: collect -> structure intel -> share -> validate detections
python3 -m ksec role learner   # student: curriculum -> lessons -> progress -> ask anything
```

The knowledge base covers: core concepts (IP, ports, DNS, HTTP/TLS,
vulnerabilities, IOCs, engagement/scope, risk, workspaces, OSINT,
ethics), every integrated tool (nmap, dig, dnsrecon, curl, sslscan,
nikto, gobuster, wpscan, hydra, enum4linux, smbmap, subfinder), module
guides (vuln, atomic, adversary, SOC pipeline, DFIR, plugins) and the
four role playbooks.

## 28. Tips and troubleshooting

**"Target not authorized for ..." / REQUIRE_AUTHORIZATION**
The target is outside every engagement scope rule. Add an allow rule
(`engagement scope add`) or check the engagement ID.

**"User ... lacks permission ..."**
The role assigned to the user does not include the permission. Use
`admin user create --role admin` (or assign a role with the permission).

**"No adapter for capability ..."**
The capability is known but has no adapter implementation. Built-in
capabilities with adapters: `port_scan` (nmap), `dns_lookup` (dig),
`http_probe` (curl), `tls_scan` (sslscan), `directory_brute`
(gobuster), `web_vuln_scan` (nikto), `wpscan`, `auth_test` (hydra),
`smb_enum` (enum4linux), `smb_map` (smbmap), `dns_enum` (dnsrecon),
`test_scan` (null).

**"Tool not found"**
The underlying Kali tool is not installed. Use
`ksec tools install --capability ... --user admin --password ... --yes`.

**Evidence verify fails (hash mismatch)**
Evidence content was altered after collection. Re-collect from source and
preserve the chain of custody.

**Backup restore refuses**
The backup hash does not match or approval (`--yes`) was not given.

**`ksec tui` says it needs an interactive terminal**
Run it in a real terminal (TTY), not a pipe or CI job.

**JSON everywhere**
Add `--json` to any command for structured output, e.g. for scripting:
`python3 -m ksec status --json | jq .db_version`.