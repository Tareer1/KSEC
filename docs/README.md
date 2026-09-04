# KSEC Documentation

Documentation for the KSEC security operations platform. KSEC is built
directly against the master specification in [`../specs/`](../specs/).

## Guides

| Document | Contents |
|----------|----------|
| [User Guide](user-guide.md) | Complete walkthrough of every implemented command with examples |
| [CLI Reference](cli-reference.md) | Every command group, global flags, exit codes, JSON output |
| [End-to-End Walkthrough](walkthrough.md) | Real run through every module with captured output |
| [Installation Guide](installation.md) | Requirements, first run, post-install checklist, upgrades |
| [Architecture](architecture.md) | Module map, design decisions, data flow, schema (mirrors spec 02) |
| [Security Model](security-model.md) | Identity, RBAC, scope/policy, safe execution, audit (mirrors spec 06) |
| [Operations Guide](operations.md) | Daily/weekly/monthly checks, backup/restore, incident runbook |
| [Troubleshooting](troubleshooting.md) | Symptom → fix table, error format, diagnostics bundle |
| [QA & Release](qa-release.md) | Quality gates, pre-release checklist, versioning, release procedure |
| [Adapter / Plugin Development](../plugins/README.md) | Writing and installing plugins (manifest, trust, permissions) |

## Status

- [x] User Guide (all implemented commands)
- [x] CLI Reference (all command groups)
- [x] End-to-End Walkthrough (real run, captured output)
- [x] Installation Guide
- [x] Architecture
- [x] Security Model
- [x] Operations Guide
- [x] Troubleshooting
- [x] QA & Release Process
- [x] Plugin Development Guide (`plugins/README.md`)
- [x] Changelog (`../CHANGELOG.md`) and feature checklist (`../README.md`)

## Implementation status

See [`../README.md`](../README.md) for the feature/status checklist and the
[`../CHANGELOG.md`](../CHANGELOG.md) for version history.
