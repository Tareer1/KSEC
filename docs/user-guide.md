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
28.5. [Safety controls: emergency stop + rate limiting](#285-safety-controls-emergency-stop--rate-limiting)
28.6. [GRC / compliance](#286-grc--compliance)
28.7. [Malware analysis](#287-malware-analysis-static-never-executes)
28.8. [Endpoint security](#288-endpoint-security-read-only-inventory)
28.9. [Database health + exports](#289-database-health--exports)
28.10. [Finding lifecycle + case collaboration](#2810-finding-lifecycle--case-collaboration)

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
ksec adversary coverage --profile-id 1    # (--profile renamed to --profile-id for global --profile)
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

## 28.5 Safety controls: emergency stop + rate limiting

```bash
# Cancel every running/queued job and block new submissions (persistent)
python3 -m ksec stop --all
python3 -m ksec stop --status      # is the stop active?
python3 -m ksec stop --reset       # clear it and accept jobs again
```

The emergency stop cancels all non-terminal jobs, preserves evidence and job
state, records an `emergency_stop` audit event, and persists across process
restarts. While active, every submission is refused.

Rate limiting caps job submissions in a sliding 60-second window
(config `[safety]`):

```toml
[safety]
rate_limit_per_minute = 0   # 0 = unlimited; global cap
rate_limit_per_user = 0     # 0 = unlimited; per-user cap
lab_mode = false            # lab/CTF mode: targets restricted to lab ranges
safe_mode = false
read_only = false
```

## 28.51 Time-bound authorization (spec 06 §54)

Engagements can carry an authorization window. Outside it, every target
action is refused at the policy gate — even if a scope rule matches:

```bash
# Valid for all of 2026
python3 -m ksec engagement create --name q1-2026 \
    --valid-from 2026-01-01 --valid-until 2026-12-31

# Expired / not-yet-valid engagements are flagged and refused
python3 -m ksec engagement list                 # shows [expired] / [not-yet-valid]
python3 -m ksec run dns_lookup example.com --engagement 2 --user admin \
    --password '...'      # -> refused: engagement expired on ...
```

## 28.52 Lab/CTF mode + `ksec mode`

Lab/CTF mode turns KSEC into a contained practice range: every target
action is limited to lab networks (127.0.0.0/8, 10/8, 172.16/12, 192.168/16,
::1, fc00::/7), lab hostnames (`.test .local .lab .ctf .lan .internal`
`.example`) and lab-labelled names. Public targets are denied with a clear
reason.

```bash
python3 -m ksec mode status                       # current operation + safety modes
python3 -m ksec mode set lab on                   # targets restricted to lab ranges
python3 -m ksec mode set lab off
python3 -m ksec mode set safe on                  # confirmation before tool install
python3 -m ksec mode set read-only on             # no mutating actions
```

Modes persist in the config file's `[safety]` table and take effect on the
next invocation.

## 28.53 Workflow DAG, retry + versioning (spec 07)

Workflow steps support dependencies (`depends_on` by step `name`), retries
with exponential backoff, and versioned immutable runs:

```bash
# A DAG: port_scan only runs after dns_lookup completes; retry twice on failure
python3 -m ksec workflow create --name staged \
  --steps-json '[
    {"capability": "dns_lookup", "name": "resolve"},
    {"capability": "port_scan", "name": "scan", "depends_on": ["resolve"],
     "retry": 2, "retry_delay": 5}
  ]'

python3 -m ksec workflow validate --name staged     # unknown deps / cycles rejected
python3 -m ksec workflow run staged example.com --engagement 1 --user admin --password '...'

# Every edit bumps the version; every run snapshots the exact executed definition
python3 -m ksec workflow list                      # shows v1, v2, ...
python3 -m ksec workflow history --json            # per-run version + immutable snapshot
```

## 28.54 Session switch/reconnect + tool management (spec 03/07)

```bash
# Switch the active context to another of the user's sessions (others pause)
python3 -m ksec session switch <session-id> --user admin --password '...'
# Reconnect to a paused session
python3 -m ksec session reconnect <session-id> --user admin --password '...'

# Tool management
python3 -m ksec tools search dns          # by name / capability / category
python3 -m ksec tools capabilities        # every capability, ready/missing
python3 -m ksec tools docs nmap           # full documentation
python3 -m ksec tools update              # re-discover + refresh registry
python3 -m ksec tools remove nmap         # drop a registry row (binary untouched)
python3 -m ksec tools list --installed --missing --broken --category recon
```

## 28.55 Dashboard auth + global flags

```bash
# Require a Bearer API token on every dashboard request (spec 06 §75)
python3 -m ksec dashboard start --require-auth --port 8080
python3 -m ksec api token create --user admin --password '...'   # token to paste

# Global flags (spec 03)
python3 -m ksec --debug status               # debug logging
python3 -m ksec --no-color status            # no ANSI color
python3 -m ksec --config ./team.toml status  # explicit config file
python3 -m ksec --profile soc status         # merge [profiles.soc] on top
```

Config profiles live in the same file under `[profiles.<name>]` tables and
deep-merge over the base configuration.

## 28.6 GRC / compliance

`ksec grc` maps KSEC's deterministic checks to framework controls
(NIST 800-53, CIS, OWASP, ISO 27001, SOC 2, PCI DSS) — it reports whether
the *technical check* passed, never legal certification:

```bash
python3 -m ksec grc frameworks
python3 -m ksec grc controls --framework "ISO 27001"
python3 -m ksec grc status
python3 -m ksec grc check --target example.com   # snapshot stored as evidence
```

## 28.7 Malware analysis (static, never executes)

```bash
python3 -m ksec malware analyze /evidence/sample.bin
python3 -m ksec malware analyze /evidence/sample.bin --finding
```

Pipeline: hash (SHA-256/SHA-1/MD5) → format detection (PE/ELF/Mach-O/ZIP/
PDF/script) → strings → entropy → hashes auto-registered as IOCs → analysis
stored as evidence. The sample is never executed.

## 28.8 Endpoint security (read-only inventory)

```bash
python3 -m ksec endpoint inventory
python3 -m ksec endpoint process --limit 50
python3 -m ksec endpoint user
python3 -m ksec endpoint port
python3 -m ksec endpoint check --create-findings
```

## 28.9 Database health + exports

```bash
python3 -m ksec db version     # schema version + pending migrations
python3 -m ksec db health      # integrity / foreign keys / migrations
python3 -m ksec db repair --yes # WAL checkpoint + reindex (backup first)

python3 -m ksec export case 1 --out case-1.json
python3 -m ksec export findings --engagement 1
python3 -m ksec export evidence            # includes chain of custody
python3 -m ksec export assets
```

## 28.10 Finding lifecycle + case collaboration

```bash
python3 -m ksec finding update 1 --status confirmed
python3 -m ksec finding remediate 1 --owner ops --priority high --description "upgrade TLS"
python3 -m ksec finding verify --remediation 1 --method retest --result verified
python3 -m ksec finding remediations 1

python3 -m ksec case note add --case 1 --content "analyst notes..." --author alice
python3 -m ksec case note list --case 1
python3 -m ksec case timeline 1
python3 -m ksec case reopen 1 --reason "new evidence"
python3 -m ksec evidence custody 1
```

## 28.10b Top-level shortcuts: recon / network / web / research / osint

```bash
python3 -m ksec recon example.com --engagement 1 --user admin --password ...
python3 -m ksec network example.com --engagement 1 --user admin --password ...
python3 -m ksec web example.com --engagement 1 --user admin --password ...
python3 -m ksec research example.com --engagement 1 --user admin --password ...
python3 -m ksec osint example.com --engagement 1 --user admin --password ...
```

Shortcuts for the built-in workflows of the same name (same flags as
`ksec run`/`ksec assess` — `--dry-run`, `--workspace`, `--role`):

- `recon` → dns_lookup + port_scan
- `network` → port_scan + smb_enum + smb_map
- `web` → web_fingerprint + http_probe + tls_scan + web_vuln_scan + directory_brute
- `research` → dns_lookup + dns_enum + osint_harvest
- `osint` → osint_harvest + dns_lookup

## 28.10c Real-world red team — exploit intelligence (searchsploit/sqlmap/ffuf/nxc)

```bash
# Version -> known public exploits (local Exploit-DB, read-only, legal)
python3 -m ksec exploit search "apache 2.4.49"
python3 -m ksec exploit search CVE-2021-41773
python3 -m ksec exploit map "apache 2.4.49" --engagement 1 --user red --password ...

# Or run through the same scheduler as any capability/workflow
python3 -m ksec run exploit_search "apache 2.4.49" --engagement 1 --user red
python3 -m ksec run exploit_lookup example.com --engagement 1 --user red

# Real offensive testing, always scope-gated
python3 -m ksec run cve_scan http://lab.local --engagement 1 --user red
python3 -m ksec run sqli_test http://lab.local --engagement 1 --user red
python3 -m ksec run web_fuzz http://lab.local --engagement 1 --user red
python3 -m ksec run smb_cred_test lab.local --engagement 1 --user red
```

- `exploit search` queries the local exploitdb database (Kali `exploitdb`
  package) — the same data professional red teams use, fully offline.
- `exploit map` auto-creates findings only for **verified** exploits,
  carrying the EDB-ID and CVE codes.
- New capabilities: `exploit_search` (searchsploit), `sqli_test`
  (sqlmap — batch, conservative level/risk), `web_fuzz` (ffuf),
  `smb_cred_test` (nxc) and `cve_scan` (nuclei — template-based CVE
  scanner, 7000+ templates, JSONL output, rate-limited). The `web`
  workflow now includes `cve_scan`. All run through the normal
  authorization gate.
- **Boundary (by design):** real exploitation of unknown/unpatched
  vulnerabilities (zero-day weaponization, payloads, meterpreter) is not
  part of KSEC — it stays an authorized testing platform.

## 28.11 Domain modules: api / wireless / cloud / container / kubernetes (spec 08 #23-27)

```bash
python3 -m ksec module list              # all 5 modules + audience
python3 -m ksec module info api          # capabilities + installed tools
python3 -m ksec module check cloud       # deterministic offline posture checks
python3 -m ksec module check api --user admin
```

Each module declares the Kali tools behind it and runs read-only, offline
posture checks (config presence, secret hygiene, config-directory
permissions, metadata guard) — nothing is executed against a target.

## 28.12 Purple team exercises (spec 08 #28)

```bash
python3 -m ksec purple exercise new --name "red-vs-blue" --engagement 1
python3 -m ksec purple exercise start 1
python3 -m ksec purple exercise complete 1   # tallies findings/alerts/detections
python3 -m ksec purple exercise show 1       # detection coverage % + verdict
python3 -m ksec purple exercise list
python3 -m ksec purple exercise delete 1
```

Completing an exercise deterministically counts the linked engagement's
findings (red output), open SOC alerts (blue detections) and fired
detection rules, then reports detection coverage.

## 28.13 Change detection: baselines + drift (spec 08 #59)

```bash
python3 -m ksec change baseline create --name prod-assets --scope assets
python3 -m ksec change baseline list
python3 -m ksec change scan 1              # clean or drift + diff items
python3 -m ksec change scans --baseline 1  # scan history
```

Scopes: `assets`, `findings`, `jobs`, `config`. A scan re-reads the state
and flags added/removed/changed records; drift raises a notification.

## 28.14 Job operations: logs / retry / trace / health

```bash
python3 -m ksec job logs <job-id>          # captured stdout/stderr
python3 -m ksec job retry <job-id>         # fresh resubmit (new job id)
python3 -m ksec job trace <job-id>         # session/schedule/audit lineage
python3 -m ksec job health                 # live scheduler state
```

Retry only accepts terminal jobs and always creates a brand-new job — the
original record is never re-executed.

## 28.15 Report preview + PDF export

```bash
python3 -m ksec report preview --engagement 1        # render, don't store
python3 -m ksec report create --engagement 1 --format pdf --out report.pdf
python3 -m ksec report export 1 --out report.pdf      # any stored report -> PDF
```

The PDF writer is pure stdlib — KSEC stays zero-dependency.

## 28.16 Activity views: history + graph

```bash
python3 -m ksec history --limit 30   # timeline: runs, audit events, jobs
python3 -m ksec graph                # engagements -> assets -> findings -> cases
python3 -m ksec graph --json
```

Both are read-only views over the shared database.

## 28.17 Learn practice drills

```bash
python3 -m ksec learn practice list
python3 -m ksec learn practice start --id practice.recon --user learner --password ...
python3 -m ksec learn practice pass  --id practice.recon --user learner --password ...
```

Six hands-on, authorized, offline drills with per-user attempts and pass
status (scope, recon, finding+risk, detection rule, DFIR artifact, report).

## 28.18 Event-driven workflow triggers (spec 07)

```bash
python3 -m ksec workflow trigger add --name on-fail --event-type job.failed \
    --workflow recon --event-glob "*.local"
python3 -m ksec workflow trigger list
python3 -m ksec workflow trigger fire --event-type job.failed \
    --payload '{"target": "x.local"}' --user admin --password ...
python3 -m ksec workflow trigger disable/enable/remove <id>
```

Triggers bind an event type + target glob to a workflow; firing runs every
match through the normal policy gate — authorization is never bypassed.

## 28.19 Alternate-tool dispatch (masscan / wfuzz / dnsenum / amass)

Every capability has a preferred tool, but the same capability can run with a
different provider through ``--options '{"tool": "..."}'``:

```bash
# High-speed port scan (masscan) instead of nmap
python3 -m ksec run port_scan 10.0.0.0/24 --engagement 1 --user red \
  --options '{"tool": "masscan", "ports": "1-1024", "rate": 1000}'

# Deep subdomain enumeration (amass, passive) — subdomain_enum
python3 -m ksec run subdomain_enum example.com --engagement 1 --user red \
  --options '{"tool": "amass"}'

# Web content fuzzing with wfuzz instead of ffuf
python3 -m ksec run web_fuzz http://example.com --engagement 1 --user red \
  --options '{"tool": "wfuzz"}'

# DNS enumeration with dnsenum instead of dnsrecon
python3 -m ksec run dns_enum example.com --engagement 1 --user red \
  --options '{"tool": "dnsenum"}'
```

New built-in workflows use this: `fast_scan` (masscan range scan),
`subdomain` (dns + amass + dnsenum) and `wifi` (AP discovery).

## 28.20 Wireless capabilities (wifi_scan / wifi_crack)

Wireless testing is scope-gated like every capability (target must be
covered by an engagement scope rule).

```bash
# Discover access points on an authorized interface
python3 -m ksec run wifi_scan wlan0 --engagement 1 --user red \
  --options '{"interface": "wlan0"}'
# => entities: BSSID / ESSID / channel / encryption

# Recover a WPA/WEP key from a captured handshake (own lab captures only)
python3 -m ksec run wifi_crack /labs/handshake.cap --engagement 1 --user red \
  --options '{"wordlist": "/usr/share/wordlists/rockyou.txt"}'
# => "KEY FOUND!" parsed into a wifi_key entity
```

## 28.21 DOCX report export

```bash
# Create a report directly as an editable Word document
python3 -m ksec report create --engagement 1 --format docx --out report.docx

# Export a stored report as DOCX
python3 -m ksec report export 1 --format docx --out report.docx
```

The DOCX writer is pure stdlib (zipfile + OOXML) — no dependencies, fully
offline, opens in Word / LibreOffice / Google Docs.

## 28.22 Extended ATT&CK coverage

Adversary and atomic exercises now cover **21 techniques** across all 14
kill-chain phases. Newly mapped techniques include T1505.003 (web shell),
T1078 (valid accounts), T1003 (credential dumping), T1213 (data from
information repositories), T1041 (exfiltration over C2) and T1485 (data
destruction).

```bash
python3 -m ksec adversary profile add --name apt-x --technique T1505.003 --technique T1041
python3 -m ksec adversary coverage
```

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