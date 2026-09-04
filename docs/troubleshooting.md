# KSEC — Troubleshooting Guide

Mirrors `specs/10-docs-operations-dod.md` §45–48. Start with `ksec doctor` —
it checks database/schema, migrations, tools, plugins and backup state in
one command. Most problems below are diagnosed by its output.

## Common problems and fixes

| Symptom | Cause | Fix |
|---|---|---|
| `"Target ... not authorized for ..."` (`REQUIRE_AUTHORIZATION`) | Target is outside every engagement allow-rule (or inside a deny-rule) | `ksec engagement scope add --engagement N --target <target>` or fix the engagement ID |
| `"User ... lacks permission ..."` | Role lacks the permission | Assign a role with it (`ksec admin user create --role admin --username ...`) |
| `"No adapter for capability ..."` | Capability known, no adapter registered | Built-ins: `port_scan`→nmap, `dns_lookup`→dig, `http_probe`→curl, `test_scan`→null. Plugins add more |
| `"Tool not found"` | Kali tool missing | `ksec env` (fingerprint), then `ksec tools install --capability ... --user admin --yes` |
| Tool shows unhealthy but is installed | Not on `PATH`, or version mismatch | Check `ksec tools info <tool>`, ensure the binary is reachable |
| `Evidence verify` fails (hash mismatch) | Content altered after collection | Re-collect from source; evidence is tamper-evident by design |
| Backup restore refuses | Hash mismatch or missing `--yes` | `ksec backup verify <id>` first; re-run with `--yes` |
| `update check` says rollback FAIL | No verified backup yet | `ksec backup create` then `ksec update check` again |
| Plugin listed but capability missing | Plugin disabled/blocked at load or execution time | `ksec plugin list`; `ksec plugin enable <name> --user ...`; `ksec plugin check` |
| `ksec tui` refuses to start | No interactive TTY | Run in a real terminal, not a pipe/CI job (`script -qec "ksec tui" /dev/null` for a pty) |
| Dashboard won't bind | Port in use | `ksec dashboard start --port <other>` |
| SOC rule never fires | Field/operator mismatch with normalized event | `ksec soc ingest` output shows the normalized fields; match rule to them. `ksec soc rule list --enabled-only` |
| `session status <id>` unknown | Session/Job IDs are short UUIDs, not integers | Copy the full id from `ksec session list` / `ksec job list --json` |
| Notifications not delivered | No provider configured | Configure `[notifications.providers]`; `ksec notify test` |
| Findings list empty after a run | Findings are created deliberately, scans auto-register assets/IOCs only | `ksec finding create ...` to record issues |

## Error output format

Handled errors print to stderr as:

```
error: <message> (code=<CODE>, correlation_id=<id>)
```

`correlation_id` links the failure to its audit-log entry. Add `--verbose`
for the full structured error (fields, causes). A Python traceback means a
bug — please report it with the `--verbose` output.

## Diagnostics bundle

Gather everything support needs in one go:

```bash
ksec doctor --json
ksec status --json
ksec env --json
ksec version
ksec update check --json
ksec plugin check --json
ksec config show         # paths (db, log, config source)
```

Logs (secret-redacted) are written to `$KSEC_HOME/ksec.log`.

## Still stuck?

Check the [Operations Guide](operations.md) (daily/weekly/monthly checks,
incident runbook) and the [User Guide](user-guide.md) sections for the
feature involved.
