# KSEC — Full End-to-End Walkthrough

> **How this document was produced:** every command below was executed for
> real on a Kali Linux host against a fresh, isolated KSEC data directory
> (`KSEC_HOME=/tmp/ksec-wt`). Output shown is the **actual command output**,
> captured during the run — including real `dig`, `nmap` and `curl`
> executions against the public `example.com` host. No output was fabricated.

Environment used:

```text
Kali GNU/Linux 2026.3 | kernel 7.1.5+kali-amd64 | x86_64
KSEC 0.1.0 | Python 3.14.6 | SQLite schema v7
```

```bash
export KSEC_HOME=/tmp/ksec-wt KSEC_CONFIG=/tmp/ksec-wt/config.toml
rm -rf /tmp/ksec-wt && mkdir -p /tmp/ksec-wt
```

---

## Table of contents

1. [Initialization and platform checks](#1-initialization-and-platform-checks)
2. [Users, sessions and engagements](#2-users-sessions-and-engagements)
3. [Environment fingerprint and tool discovery](#3-environment-fingerprint-and-tool-discovery)
4. [Operation modes and tool explanations](#4-operation-modes-and-tool-explanations)
5. [Policy gate: dry runs and authorization](#5-policy-gate-dry-runs-and-authorization)
6. [Live assessment: recon workflow (real dig + nmap)](#6-live-assessment-recon-workflow)
7. [Automatic IOC extraction and asset registration](#7-automatic-ioc-extraction-and-asset-registration)
8. [Findings, risk and evidence](#8-findings-risk-and-evidence)
9. [Cases and DFIR timeline](#9-cases-and-dfir-timeline)
10. [Threat intelligence: actors, campaigns, TTPs](#10-threat-intelligence)
11. [SOC alert pipeline: event to case](#11-soc-alert-pipeline)
12. [Custom workflows](#12-custom-workflows)
13. [Scheduler: jobs and lifecycle control](#13-scheduler-jobs-and-lifecycle)
14. [Reporting](#14-reporting)
15. [Learning curriculum](#15-learning-curriculum)
16. [Backup and integrity](#16-backup-and-integrity)
17. [Dashboard API and TUI](#17-dashboard-api-and-tui)
18. [Audit trail](#18-audit-trail)
19. [Final state](#19-final-state)
20. [Live demo: SIEM ingestion + windowed brute-force detection](#20-live-demo-siem-ingestion-windowed-brute-force-detection)

---

## 1. Initialization and platform checks

```bash
python3 -m ksec version
python3 -m ksec init --username admin --password 'ChangeMe!123' --display-name "Walkthrough Admin"
```

```json
{
  "command": "version",
  "ksec": "0.1.0",
  "python": "3.14.6"
}
wrote config: /tmp/ksec-wt/config.toml
created admin user admin (id=1)
KSEC initialized.
```

`ksec init` writes a `config.toml`, creates the SQLite database (schema v7,
7 migrations), seeds roles/permissions/workspaces and creates the admin user.

```bash
python3 -m ksec status
python3 -m ksec doctor
```

```json
{
  "version": "0.1.0",
  "config_source": "/tmp/ksec-wt/config.toml",
  "data_dir": "/tmp/ksec-wt",
  "db_path": "/tmp/ksec-wt/ksec.db",
  "db_version": 7,
  "pending_migrations": [],
  "users": 1,
  "active_sessions": 0,
  "audit_events": 1,
  "safety": {"require_authorization": true, "safe_mode": false, "read_only": false}
}
```

```text
{'check': 'python', 'status': 'PASS', 'detail': '3.14.6'}
{'check': 'config', 'status': 'PASS', 'detail': '/tmp/ksec-wt/config.toml'}
{'check': 'data_dir', 'status': 'PASS', 'detail': '/tmp/ksec-wt'}
{'check': 'migrations', 'status': 'PASS', 'detail': 'version=7, pending=0'}
{'check': 'audit', 'status': 'PASS', 'detail': 'audit enabled'}
```

---

## 2. Users, sessions and engagements

```bash
python3 -m ksec admin user create --username operator --password 'Operator!123' --role operator -q
python3 -m ksec admin user list
```

```text
  1  admin                Walkthrough Admin        active    admin
  2  operator                                      active    operator
```

Open a RED_TEAM workspace session as admin, then create an engagement with
scoped authorization: `example.com` is allowed, `10.0.0.0/8` is denied.

```bash
python3 -m ksec session open --user admin --password 'ChangeMe!123' --workspace RED_TEAM
python3 -m ksec engagement create --name "Walkthrough Engagement" --description "E2E demo scope"
python3 -m ksec engagement scope add --engagement 1 --target example.com --action "*" --effect allow
python3 -m ksec engagement scope add --engagement 1 --target 10.0.0.0/8 --effect deny -q
python3 -m ksec engagement scope list --engagement 1
```

```text
session 7ae667b319 workspace: RED_TEAM role: admin state: ACTIVE
{"created": true, "id": 1}
  1  allow  *            example.com
  2  deny   *            10.0.0.0/8
```

---

## 3. Environment fingerprint and tool discovery

```bash
python3 -m ksec env
```

```json
{
  "hostname": "REBEL",
  "os_name": "Kali GNU/Linux",
  "os_release": "2026.3",
  "kernel": "7.1.5+kali-amd64",
  "architecture": "x86_64",
  "runtime": "bare_metal",
  "privilege": "user",
  "uid": 1000,
  "is_kali": true,
  "apt_available": true,
  "network_up": true
}
```

```bash
python3 -m ksec tools list
```

```text
ok  nmap         port_scan            Nmap version 7.99 ( https://nmap.org )
ok  masscan      port_scan            Masscan version 1.3.2 ( https://github.com/robertdavidgraham/masscan )
ok  dig          dns_lookup           Invalid option: --version
ok  whois        whois_lookup         Version 5.6.6.
--  subfinder    subdomain_enum       (not installed)
ok  nuclei       web_vuln_scan        [INF] Nuclei Engine Version: v3.11.1
ok  gobuster     directory_brute      gobuster version 3.8.2
ok  curl         http_probe           curl 8.21.0 ...
ok  traceroute   traceroute           Modern traceroute for Linux, version 2.1.6
ok  john         password_crack       Unknown option: "--version"

9/10 tools ready
```

`9/10` tools are installed on this Kali host; only `subfinder` is missing
(`ksec tools install` would install it with approval). Capability discovery
(`tools list`) maps each tool to the capability it provides.

---

## 4. Operation modes and tool explanations

```bash
python3 -m ksec tools explain nmap --mode beginner
```

```json
{
  "tool": "nmap",
  "explanation": "This tool looks for doors that are open on a computer or network, and what service is behind each door."
}
```

```bash
python3 -m ksec tools explain dig --mode expert
```

```json
{
  "tool": "dig",
  "beginner": "This tool asks the internet's phone book (DNS) where a name actually points.",
  "technical": "This capability performs DNS lookups (dig).",
  "why_selected": "Default provider for the dns_lookup capability.",
  "data_collected": "DNS records: A, AAAA, CNAME, MX, NS, TXT, SOA.",
  "risk": "PASSIVE \u2014 sends standard DNS queries.",
  "privilege": "None.",
  "inputs": "Domain name; optional record type.",
  "outputs": "DNS records for the queried name.",
  "learn_more": "man dig"
}
```

Beginner mode hides complexity; expert mode exposes everything (spec: *hide
complexity, never hide useful information*).

---

## 5. Policy gate: dry runs and authorization

Every action is policy-checked before execution. Scanning a target **without
an engagement authorization is refused**:

```bash
python3 -m ksec assess scanme.example.org --user operator --password 'Operator!123' \
    --workspace RED_TEAM --dry-run
```

```text
decision: REQUIRE_AUTHORIZATION | Action on a target requires an engagement authorization
```

With the engagement in scope, the same dry run plans `ALLOW` for every step —
**without touching the target**:

```bash
python3 -m ksec assess example.com --user operator --password 'Operator!123' \
    --workspace RED_TEAM --engagement 1 --dry-run --workflow recon
```

```json
{
  "workflow": "recon",
  "target": "example.com",
  "mode": "dry-run",
  "operation_mode": "professional",
  "steps": [
    {"capability": "dns_lookup", "policy": "ALLOW", "reason": "Permitted by policy"},
    {"capability": "port_scan", "policy": "ALLOW", "reason": "Permitted by policy"}
  ],
  "blocked": false
}
```

---

## 6. Live assessment: recon workflow

The `recon` workflow submits one job per step to the central scheduler, which
builds the validated command through the tool adapter, executes it, parses
the output and correlates the results. **This run executed real `dig` and
real `nmap` against `example.com`:**

```bash
python3 -m ksec run recon example.com --user operator --password 'Operator!123' \
    --workspace RED_TEAM --engagement 1
```

```text
run_id: 6d20de72dc | status: completed
 step: dns_lookup -> completed | entities: 2 | job: 8f6feed0b4
 step: port_scan  -> completed | entities: 0 | job: f7eee8ff29
```

The scheduler recorded both jobs as `COMPLETED` with `exit=0`:

```text
f7eee8ff29eb COMPLETED  port_scan        example.com          exit=0
8f6feed0b4ed COMPLETED  dns_lookup       example.com          exit=0
```

---

## 7. Automatic IOC extraction and asset registration

Every completed job's evidence is automatically processed:

* **structured entities** → assets (via the correlation engine) and
  **high-confidence IOCs** (via the IOC extractor)
* **raw tool output** → scanned for IPs/domains/URLs/hashes at low confidence

```bash
python3 -m ksec intel ioc list
python3 -m ksec asset list
```

```text
  5  DOMAIN   low      active  nmap.xsl            <- raw nmap output noise (low)
  4  IP       low      active  192.168.100.1       <- raw dig output (low)
  3  IP       high     active  172.66.147.243      <- A record (high)
  2  IP       high     active  104.20.23.154       <- A record (high)
  1  DOMAIN   high     active  example.com         <- queried name (high)

  1  example.com                  domain     crit=low
  2  104.20.23.154                ip         crit=low
  3  172.66.147.243               ip         crit=low
```

Confidence is provenance: `high` came from a structured parser field, `low`
from free text.

---

## 8. Findings, risk and evidence

```bash
python3 -m ksec finding create \
    --title "DNS answers resolve to shared CDN hosts" \
    --description "example.com resolves to CDN IPs 104.20.23.154 and 172.66.147.243" \
    --severity medium --confidence high \
    --recommendation "Verify origin IPs are not exposed" \
    --engagement 1 --risk --criticality medium --exploitability low \
    --exposure internet --impact medium --evidence partial
```

```json
{
  "created": true,
  "id": 1,
  "title": "DNS answers resolve to shared CDN hosts",
  "severity": "medium",
  "status": "open",
  "risk_score": 5.23,
  "risk_level": "Medium",
  "ioc_matches": [
    {"id": 3, "type": "IP", "value": "172.66.147.243", "confidence": "high"},
    {"id": 2, "type": "IP", "value": "104.20.23.154", "confidence": "high"}
  ]
}
```

`--risk` computes a deterministic risk score from the CVSS-style factors, and
the finding is automatically correlated against registered IOCs.

Findings explain themselves in plain language for beginners:

```bash
python3 -m ksec finding explain 1 --mode beginner
```

```json
{
  "id": 1,
  "title": "DNS answers resolve to shared CDN hosts",
  "what_happened": "example.com resolves to CDN IPs 104.20.23.154 and 172.66.147.243",
  "why_it_matters": "This is a moderate issue that should be addressed (severity=medium).",
  "what_should_happen_next": "Verify origin IPs are not exposed"
}
```

Evidence is hash-protected at collection and verified on demand:

```bash
python3 -m ksec evidence add --content "dig example.com -> 104.20.23.154, 172.66.147.243 (A records, TTL 300)" --tool dig --engagement 1
python3 -m ksec evidence verify 1
```

```json
{"created": true, "id": 1, "sha256": "f04ed6321232cfbb93d63f5a7d8e1a38df53d2ed5109d1c225e79f28824b6122", "tool": "dig"}
{"id": 1, "verified": true, "reason": "integrity verified"}
```

---

## 9. Cases and DFIR timeline

```bash
python3 -m ksec case create --title "Walkthrough: CDN exposure review" --severity medium --owner admin --engagement 1
python3 -m ksec case add-finding --case 1 --finding 1
python3 -m ksec case list
```

```text
{"created": true, "id": 1, "title": "Walkthrough: CDN exposure review", "status": "open"}
{"case_id": 1, "finding_id": 1, "linked": true}
  1  medium   open         findings=1   Walkthrough: CDN exposure review
```

DFIR records forensic artifacts and builds a chronological timeline:

```bash
python3 -m ksec dfir artifact add --case 1 --type log --name /var/log/auth.log --host web-01 --details "auth log from web-01" --tool dig
python3 -m ksec dfir event add --case 1 --time 2026-09-04T08:00:00Z --type auth_failure --actor attacker --details "5 failed ssh attempts" -q
python3 -m ksec dfir event add --case 1 --time 2026-09-04T09:30:00Z --type login --actor operator --details "successful login" -q
python3 -m ksec dfir timeline --case 1
```

```text
2026-09-04T08:00:00+00:00  auth_failure   actor=attacker         5 failed ssh attempts
2026-09-04T09:30:00+00:00  login          actor=operator         successful login
```

---

## 10. Threat intelligence

Actors, campaigns and ATT&CK TTPs, with IOCs normalized at registration:

```bash
python3 -m ksec intel actor add --name "APT-Walkthrough" --alias "WT-Group" --source research -q
python3 -m ksec intel campaign add --name "Operation Example" --actor "APT-Walkthrough" -q
python3 -m ksec intel ttp add --technique-id T1071 --name "Application Layer Protocol" --tactic "command-and-control" -q
python3 -m ksec intel link --campaign 1 --ttp 1 -q
python3 -m ksec intel ioc add --value evil-c2.example.org --type DOMAIN --confidence high \
    --source research --actor "APT-Walkthrough" --campaign "Operation Example" -q
python3 -m ksec intel ioc correlate --value EVIL-C2.EXAMPLE.ORG
```

```text
MATCH DOMAIN   evil-c2.example.org (confidence=high)
```

Correlation is case-insensitive and normalization-based. Enrichment pulls
together the actor, campaign, TTPs and related findings:

```bash
python3 -m ksec intel ioc enrich --ioc 6
```

```text
actor: APT-Walkthrough
campaign: Operation Example
ttps: ['T1071']
related_findings: 0
```

---

## 11. SOC alert pipeline

The SOC module runs every ingested event through
`normalize → enrich → correlate → rule eval → risk → alert → case`.
First, a deterministic detection rule for C2 beaconing:

```bash
python3 -m ksec soc rule add --name c2-beacon --event-type beacon \
    --field domain --operator contains --value .example.org \
    --severity critical --risk-boost 1 -q
python3 -m ksec soc rule list
```

```text
on  c2-beacon                    domain     contains     .example.org         -> critical
```

A benign event produces no alert:

```bash
python3 -m ksec soc ingest --event-id soc-1 --source firewall \
    --event-type dns --severity low --domain legit.example.net
```

```text
  risk score: 2.0/10 (severity low)
  no alert (no rule matched and severity below gate)
```

A beacon to the known-C2 domain fires the rule **and** matches the
registered IOC — enrichment adds IOC context, the rule boosts risk to
7.5/10, an alert is created and a **case is auto-opened**:

```bash
python3 -m ksec soc ingest --event-id soc-2 --source endpoint \
    --event-type beacon --severity medium \
    --domain evil-c2.example.org --ip 203.0.113.66
```

```text
event soc-2 (new)
  normalized: beacon [medium] src=endpoint ip=203.0.113.66 domain=evil-c2.example.org host=evil-c2.example.org
  enriched: asset=no ioc=yes findings=0
    ioc match: evil-c2.example.org (DOMAIN, conf=high)
  correlated: 0 related event(s) sources=-
  rules: c2-beacon
  risk score: 7.5/10 (severity critical)
  ALERT #1 [CRITICAL] CRITICAL beacon 203.0.113.66 (rule c2-beacon)
  case #2 opened: CRITICAL alert: beacon 203.0.113.66
```

```bash
python3 -m ksec soc alert list
python3 -m ksec soc alert action ack 1
```

```text
   1  [CRITICAL] risk=5.8  open         beacon           CRITICAL beacon 203.0.113.66 (rule c2-beacon)
ack -> status: acknowledged | acked_at: True
```

---

## 12. Custom workflows

Users define their own workflows from capability steps — validated against
the capability catalog and run by the same policy-gated engine:

```bash
python3 -m ksec workflow create --name my-recon --description "Custom recon" \
    --step dns_lookup --step http_probe --user operator -q
python3 -m ksec workflow validate --name my-recon
```

```json
{"name": "my-recon", "valid": true, "steps": ["dns_lookup", "http_probe"]}
```

Real execution (dig + curl) completes and is recorded in history:

```bash
python3 -m ksec run my-recon example.com --user operator --password 'Operator!123' \
    --workspace RED_TEAM --engagement 1
python3 -m ksec workflow history
```

```text
status: completed
 step: dns_lookup -> completed | entities: 2
 step: http_probe -> completed | entities: 1

f03ed02fef9f my-recon         example.com          completed  steps=2/2
6d20de72dca9 recon            example.com          completed  steps=2/2
```

---

## 13. Scheduler: jobs and lifecycle

Jobs run through the central scheduler worker pool. A long-running job can be
paused, resumed and cancelled — the process is SIGSTOP/SIGCONT'd and killed
on cancel, and interrupted jobs are marked FAILED on recovery (never blindly
resumed):

```text
job: 5438dffc09 -> state: RUNNING
pause -> PAUSED
resume -> QUEUED
cancel -> CANCELLING
```

Job state is inspectable at any time:

```bash
python3 -m ksec job list
python3 -m ksec job status <job_id>
```

```text
cddfd8ff6ff2 COMPLETED  http_probe       example.com          exit=0
20748f394254 COMPLETED  dns_lookup       example.com          exit=0
f7eee8ff29eb COMPLETED  port_scan        example.com          exit=0
8f6feed0b4ed COMPLETED  dns_lookup       example.com          exit=0

state: COMPLETED | capability: http_probe | exit: 0
```

---

## 14. Reporting

Reports aggregate the full engagement picture — scope, assets, findings with
risk, evidence, cases — as Markdown or HTML:

```bash
python3 -m ksec report create --engagement 1 --title "Walkthrough Report" --user admin
python3 -m ksec report show 1
```

```text
# Walkthrough Report

- Generated: 2026-09-04T00:05:43.638781+00:00
- Engagement: Walkthrough Engagement (open)

## Scope
- **allow** `*` → `example.com`
- **deny** `*` → `10.0.0.0/8`

## Assets (3)
- example.com (domain, criticality=low)
- 104.20.23.154 (ip, criticality=low)
- 172.66.147.243 (ip, criticality=low)

## Findings (1)
- **[MEDIUM]** DNS answers resolve to shared CDN hosts (status=open, risk=Medium score=5.23)
  - example.com resolves to CDN IPs 104.20.23.154 and 172.66.147.243
  - **Recommendation:** Verify origin IPs are not exposed

## Evidence (1)
- `f04ed6321232cfbb…` dig — collected

## Cases (2 open)
- CRITICAL alert: beacon 203.0.113.66 (severity=critical, status=open)
- Walkthrough: CDN exposure review (severity=medium, status=open)
```

---

## 15. Learning curriculum

```bash
python3 -m ksec learn lesson --id orientation.what-is-ksec
python3 -m ksec learn complete --id orientation.what-is-ksec --user operator --password 'Operator!123' -q
python3 -m ksec learn progress --user operator --password 'Operator!123'
```

```text
{"lesson_id": "orientation.what-is-ksec", "phase": 0, "title": "What is KSEC?",
 "summary": "KSEC is one unified interface that orchestrates Kali security tools.", ...}

{
  "completed_lessons": 1,
  "total_lessons": 18,
  "percent": 5.6,
  "level": 1,
  "level_name": "Explorer",
  ...
}
```

---

## 16. Backup and integrity

```bash
python3 -m ksec backup create
python3 -m ksec backup list
python3 -m ksec backup verify 1
```

```text
backup_id: 20260904-000605-cb805c | sha256: 9cb2a80a6cf545e7...
  1  20260904-000605-cb805c     299008 bytes  9cb2a80a6cf545e7…
{"id": 1, "verified": true, "reason": "backup integrity verified"}
```

---

## 17. Dashboard API and TUI

The local dashboard serves live JSON over HTTP (stdlib, loopback only):

```text
/api/v1/status     -> ['version', 'db_path', 'config_source', 'jobs', 'sessions', 'findings']
/api/v1/jobs       -> ['jobs']
/api/v1/findings   -> ['findings']
/api/v1/engagements -> ['engagements']
```

The curses TUI renders the five-workspace header with mode-aware views
(beginner shows plain-language explanations, expert shows raw commands).
Without an interactive terminal it exits gracefully:

```text
TUI requires an interactive terminal.
```

---

## 18. Audit trail

Every security-relevant action is recorded in the append-only audit log:

```text
total audit events: 9
recent types: {'backup.create': 1, 'session.open': 6, 'admin.user.create': 1, 'init.admin_user': 1}
```

---

## 19. Final state

A single shared, queryable store now holds the complete picture — from raw
tool evidence to SOC cases:

```text
users: 2        | assets: 3         | findings: 1      | evidence: 1
cases: 2        | iocs: 6           | actors: 1        | campaigns: 1
ttps: 1         | dfir artifacts: 1 | soc events: 2    | soc alerts: 1
soc rules: 1    | workflow runs: 2  | reports: 1       | backups: 1
notifications: 1| audit events: 9   | db schema: v7
```

### What this walkthrough demonstrated

| Module | What you saw |
|---|---|
| Core | `init`, `status`, `doctor`, config, schema v7 |
| Identity/RBAC | admin + operator users, roles |
| Sessions | 5-workspace model, RED_TEAM session |
| Engagements/scope | allow `example.com`, deny `10.0.0.0/8` |
| Policy | out-of-scope dry run blocked; in-scope allowed |
| Kali layer | tool discovery (9/10 ready), adapters, parsers |
| Workflow/scheduler | real `recon` + custom workflow runs; pause/resume/cancel |
| Correlation | parsed entities → assets |
| IOC pipeline | auto-extraction from evidence with confidence |
| Findings/risk/evidence | risk-scored finding + IOC correlation + hash-verified evidence |
| Cases/DFIR | case with finding; artifact + timeline |
| Threat intel | actor/campaign/TTP/IOC with enrichment |
| SOC | event → enrich → rule → risk → alert → auto-case |
| Reporting | full engagement report (scope, assets, findings, evidence, cases) |
| Learning | 12-phase curriculum + progress |
| Backup | SHA-256-verified backup |
| Interfaces | dashboard JSON API + mode-aware TUI |
| Audit | append-only security events |

**Recreate it yourself:** run the snippets in order against a fresh
`KSEC_HOME` — all data above was produced by these exact commands.

---

## 20. Live demo — SIEM ingestion + windowed brute-force detection

> **How this section was produced:** every command below ran for real on a
> fresh data directory (`KSEC_HOME=/tmp/ksec-siem-demo`). Three raw sshd
> syslog lines were pushed over **UDP** to `ksec siem listen`; a windowed
> detection rule (`3 auth_failures from one IP in 5 minutes`) fired on the
> third datagram and auto-opened a case. Output is the actual command
> output.

### 20.1 The detection rule — count inside a window

```bash
export PYTHONPATH=src KSEC_HOME=/tmp/ksec-siem-demo
python3 -m ksec init --username admin --password 'demo-pass'

python3 -m ksec soc rule add --name ssh-brute-3in5 \
    --event-type auth_failure --field ip --operator eq \
    --value 203.0.113.77 --within 5 --count 3 \
    --severity high --risk-boost 2.5
```

```json
{
  "id": 1,
  "name": "ssh-brute-3in5",
  "enabled": true,
  "event_type": "auth_failure",
  "field": "ip",
  "operator": "eq",
  "value": "203.0.113.77",
  "severity": "high",
  "risk_boost": 2.5,
  "open_case": true,
  "window_minutes": 5,
  "window_count": 3
}
```

The `--within 5 --count 3` pair makes this a **windowed rule**: it counts
matching events (`event_type=auth_failure` **and** `ip=203.0.113.77`) inside
a 5-minute window and fires exactly once — when the third event arrives.
One alert per burst, never a flood.

### 20.2 A real log stream over UDP (`ksec siem listen`)

Terminal 1 — start the listener, stop after 3 datagrams:

```bash
python3 -m ksec siem listen --port 15515 --source ssh_syslog --run 3 --json
```

Terminal 2 — three raw sshd lines, the way rsyslog would forward them
(`*.* @127.0.0.1:15514`):

```bash
python3 - <<'EOF'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
lines = [
    '<134>Sep  4 10:01:21 edge01 sshd[2213]: Failed password for root from 203.0.113.77 port 51234 ssh2',
    '<134>Sep  4 10:01:22 edge01 sshd[2213]: Failed password for root from 203.0.113.77 port 51235 ssh2',
    '<134>Sep  4 10:01:23 edge01 sshd[2213]: Failed password for root from 203.0.113.77 port 51236 ssh2',
]
for line in lines:
    s.sendto(line.encode(), ('127.0.0.1', 15515))
    time.sleep(0.4)
s.close()
EOF
```

Listener summary (real output) — every record parsed, all three ingested,
and the windowed rule **fired once**:

```json
{
  "lines": 3,
  "parsed": 3,
  "duplicates": 0,
  "ingested": 3,
  "alerts": 1,
  "errors": 0,
  "dry_run": false
}
```

### 20.3 What the pipeline stored

Raw `Failed password ... from 203.0.113.77` lines were normalized into
structured events — the attacker IP extracted from the message body, host
`edge01`, tag `sshd` (parsed from the RFC3164 header):

```text
$ python3 -m ksec soc event list
   3  auth_failure     medium   203.0.113.77             ssh_syslog
   2  auth_failure     medium   203.0.113.77             ssh_syslog
   1  auth_failure     medium   203.0.113.77             ssh_syslog
```

The alert carries the correlation context and auto-opened a high-risk case:

```text
$ python3 -m ksec soc alert list
   1  [HIGH    ] risk=7.2  open         auth_failure     HIGH auth_failure 203.0.113.77 (rule ssh-brute-3in5)

1 alert(s) — 1 open

$ python3 -m ksec soc alert show 1
{
  "id": 1,
  "severity": "high",
  "risk_score": 7.2,
  "status": "open",
  "rule_id": 1,
  "case_id": 1,
  "summary": "HIGH auth_failure 203.0.113.77 (rule ssh-brute-3in5)",
  "details": {
    "entity": ["203.0.113.77", "edge01"],
    "related_event_count": 2,
    "matched_rule": "ssh-brute-3in5",
    "severity_gate": false
  }
}

$ python3 -m ksec case list
  1  high     open         findings=0   HIGH alert: auth_failure 203.0.113.77
```

### 20.4 More formats via file watch (`ksec siem watch --once`)

The same feed parses **JSONL** (Zeek), **RFC3164 syslog** (Suricata) and
**auditd key=value** records from a growing log file:

```bash
printf '%s\n' \
  '<134>Sep  4 10:05:01 fw01 suricata: ET SCAN Potential TCP Scan from 198.51.100.10' \
  '{"event_id": "zeek-conn-1", "source": "zeek", "event_type": "conn", "ip": "203.0.113.202", "severity": "low", "details": {"proto": "tcp", "port": 4444}}' \
  'type=SYSCALL msg=audit(1725433201.123:456): pid=2213 uid=0 auid=1000 msg="su root" key=privilege' \
  > mixed.log
python3 -m ksec siem watch mixed.log --once --source filewatch
```

```text
siem feed: 3 line(s), 3 parsed, 3 ingested, 0 duplicate(s), 0 alert(s), 0 error(s)
```

```text
$ python3 -m ksec soc event list
   6  syscall          medium   -                        filewatch
   5  conn             low      203.0.113.202            zeek
   4  port_scan        medium   198.51.100.10            filewatch
   ...
```

### 20.5 Idempotent intake — re-sending never duplicates

Re-feeding the exact same file (what happens when rsyslog restarts and
replays a burst) produces **zero new events** — deterministic per-record
ids make intake idempotent:

```text
$ python3 -m ksec siem watch mixed.log --once --source filewatch
siem feed: 3 line(s), 3 parsed, 0 ingested, 3 duplicate(s), 0 alert(s), 0 error(s)
```

Alert count is still 1 — no duplicate alerts, no duplicate cases:

```text
$ python3 -m ksec soc alert list | tail -1
1 alert(s) — 1 open
```

### 20.6 The audit trail sees everything

SIEM-driven events produce the same audited chain as manual ingestion:

```text
$ python3 -m ksec audit list --limit 6 --user admin --password demo-pass
dcd41300ac1a  2026-09-04T04:16:01  alert.create   -          success alert.create
80acad90715e  2026-09-04T04:16:01  case.create    -          success case.create
b45dfc56140d  2026-09-04T04:15:51  init.admin_user admin      success init.admin_user

3 audit event(s)
```

### What this section demonstrated

| Capability | What you saw |
|---|---|
| Windowed rules | 3 events in 5 min → exactly 1 alert on the crossing event |
| SIEM listen | real UDP syslog datagrams → normalized events (IP from message body) |
| SIEM watch | JSONL / syslog / auditd auto-detected from one file |
| Deduplication | replay of the same lines = 0 new events, 0 duplicate alerts |
| Pipeline | normalize → correlate → rule → risk 7.2 → alert → auto-case |
| Audit | `alert.create` + `case.create` recorded for streamed events |
