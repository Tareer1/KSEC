# KSEC — CLI Reference

Every command accepts the same global options:

```
-h, --help                 show help and exit
-q, --quiet                reduce output
--verbose                  verbose diagnostics
--json                     machine-readable JSON output
--mode {beginner,professional,expert}
                           operation mode (default from config core.mode)
```

Invocation: `ksec <command> ...` (when installed) or
`PYTHONPATH=src python3 -m ksec <command> ...` (from a checkout).

Full per-flag help for any command:

```bash
ksec <group> <sub> --help
```

## Command groups

| Group | Purpose | Key subcommands |
|---|---|---|
| `init` | First-run: config, database, roles, admin | `--username --password` |
| `status` | Platform status (schema, paths, counts) | `--json` |
| `doctor` | Health checks (db, migrations, tools, plugins, backup) | |
| `version` | Show `ksec <version>` | |
| `config` | Configuration | `show` |
| `env` | Kali environment fingerprint | `--json` |
| `admin user` | User management | `create --username --role`, `list` |
| `audit` | Append-only audit log (requires `audit.read`) | `list [--limit --event-type --actor] --user --password` |
| `tools` | Kali tool / capability discovery | `list`, `info <tool>`, `health`, `explain <tool>`, `install --capability` |
| `session` | Workspace session lifecycle | `open --user --workspace`, `list`, `status <id>`, `pause`, `resume`, `close` |
| `engagement` | Engagements, authorizations, scope | `create --name`, `list`, `scope add --engagement --target [--effect deny]`, `scope list` |
| `assess` | Policy-gated assessment run | `assess <target> --workflow --engagement --user --dry-run --explain` |
| `workflow` | User-defined workflows | `list`, `create --name --step`, `edit`, `validate`, `run <name> <target>`, `history` |
| `run` | Alias for `workflow run` | `run <name> <target> ...` |
| `job` | Job lifecycle + recurring schedules | `list [--state]`, `status <id>`, `pause`, `resume`, `cancel`, `schedule add <cap> <target> --cron '0 6 * * *'`, `schedule list\|remove\|run <id>` |
| `asset` | Auto-registered assets | `list [--engagement]` |
| `finding` | Findings + risk | `create --title --severity [--risk ...]`, `list`, `explain <id>` |
| `evidence` | Evidence (SHA-256) | `add [--content|--file]`, `list`, `verify <id>` |
| `case` | Cases | `create --title --severity`, `list`, `add-finding --case --finding`, `close <id>` |
| `report` | Reporting | `create --engagement --title [--format markdown\|html] [--out]`, `list`, `show <id>` |
| `learn` | Learning curriculum | `list`, `lesson --id`, `complete --id --user`, `progress --user` |
| `dfir` | Digital forensics / IR | `artifact add|list|hash <id> --path`, `event add`, `timeline [--case]`, `export --case [--format csv\|jsonl] [--out]` |
| `intel` | Threat intelligence | `ioc add|list|correlate|enrich|extract`, `actor add|list`, `campaign add|list`, `ttp add|list`, `link` |
| `plugin` | Plugin lifecycle | `list`, `info <name>`, `new <name> [--capability --tool --category --safety --trust]`, `install <path> --trust`, `enable\|disable\|block <name>`, `uninstall`, `check` |
| `adversary` | Adversary simulation | `profile add|list|show|delete`, `coverage [--profile]`, `exercise new|list|run|chain [--dry-run]`, `report <id>` (kill-chain order + phase coverage) |
| `vuln` | Authorized deterministic vuln checks | `checks`, `check <target> [--port] --engagement --user` |
| `atomic` | Atomic red tests (detection validation) | `list`, `info <id>`, `run <id> <target> --engagement --user` |
| `soc` | SOC alert pipeline | `ingest`, `event list`, `alert list|show|action ack\|resolve\|close`, `rule add [--within M --count N]|list|enable|disable|delete` |
| `notify` | Notifications | `list [--limit]`, `test [--title --body]` |
| `update` | Update readiness | `check` |
| `backup` | Backup / restore | `create`, `list`, `verify <id>`, `restore <id> --yes` |
| `tui` | Terminal UI | `--mode beginner\|professional\|expert` |
| `dashboard` | Local web dashboard | `start --host --port [--background]` |
| `ask` | In-tool mentor: answer anything in plain language | `ask "<question>"`, `--list` (all topics) |
| `role` | Role playbook shortcut | `red \| blue \| purple \| learner` |
| `api` | REST API (bearer tokens + server) | `token create --name --user`, `token list`, `token revoke <id>`, `serve --host --port` |
| `siem` | SIEM auto-ingestion (logs -> SOC pipeline) | `listen --host --port [--run]`, `watch <path> [--once]`, `demo [--ingest]` |

## In-tool mentor (`ksec ask` / `ksec role`)

No question is too basic — answers live inside the tool and always end with
the exact command to run next. Fully offline, no AI dependency.

```bash
ksec ask "what is an ip address"      # concept, from zero
ksec ask "nmap kya hai"               # tool card (Roman-Urdu routes fine)
ksec ask "red team kaise shuru karun" # role playbook
ksec role red                         # same playbook, shortcut
ksec ask --list                       # every topic in the knowledge base
ksec ask "hydra kya hai" --json       # machine-readable answer
```

## Common workflows

```bash
# Reconnaissance lifecycle
ksec engagement create --name eng-1
ksec engagement scope add --engagement 1 --target example.com
ksec assess example.com --engagement 1 --user admin --password '...' --dry-run   # plan + policy
ksec assess example.com --engagement 1 --user admin --password '...'             # live
ksec asset list --engagement 1
ksec intel ioc list                      # IOCs auto-extracted from the run

# Findings -> evidence -> case -> report
ksec finding create --title "TLS 1.0 on port 443" --severity medium --risk --engagement 1
ksec evidence add --content "openssl output ..." --engagement 1
ksec case create --title "Eng 1 issues" --engagement 1
ksec case add-finding --case 1 --finding 1
ksec report create --engagement 1 --title "Eng 1 report" --out report.md

# SOC
ksec soc rule add --name c2-beacon --event-type beacon --field domain \
    --operator contains --value .top --severity critical
ksec soc rule add --name ssh-brute --event-type auth_failure --field ip \
    --operator eq --value 203.0.113.66 --within 5 --count 5 --severity high  # windowed
ksec soc ingest --event-id ev-9 --source endpoint --event-type beacon \
    --severity medium --domain evil-c2.top
ksec soc alert list
ksec soc alert action ack 1

# SIEM auto-ingestion: real log streams into the same pipeline
ksec siem listen --port 5514          # UDP syslog (rsyslog: *.* @127.0.0.1:5514)
ksec siem watch /var/log/auth.log     # appended lines -> events
ksec siem watch /var/log --once       # bulk backfill
ksec siem demo --ingest               # see all supported formats

# DFIR forensics
ksec dfir artifact add --case 1 --type file --name dump.bin
ksec dfir artifact hash 1 --path /evidence/dump.bin    # SHA-256/SHA-1 recorded
ksec dfir export --case 1 --format jsonl --out case1.jsonl

# Interactive dashboard triage
ksec dashboard start --port 8080      # http://127.0.0.1:8080/soc — ack/resolve/close
```

## JSON output

Add `--json` for machine-readable output:

```bash
ksec status --json | jq .db_version
ksec job list --json | jq '.[] | select(.state=="COMPLETED") | .id'
ksec soc alert list --json | jq '.alerts[] | {id, severity, status}'
```

## Exit codes

- `0` — success (and for `--help`)
- `1` — handled KSEC error (printed to stderr with a code and
  correlation_id; add `--verbose` for the full error object)
- `130` — interrupted (Ctrl-C)

Never expect a Python traceback for user errors: invalid input, missing
permissions, and policy denials are all handled errors.
