# KSEC — Installation Guide

KSEC targets a Kali Linux environment (or any Linux with Python ≥ 3.11).
It is a pure-stdlib Python application: **no third-party dependencies** are
required to run it.

## 1. Requirements

- Python 3.11+ (`python3 --version`)
- Kali tooling for real execution: `nmap`, `dnsutils` (dig), `curl`
  (optional — KSEC runs without them; only the matching capabilities are
  marked unavailable)
- Outbound network for live scans (only to targets you are authorized to
  test)

## 2. Install

### 2.1 From a checkout (recommended)

```bash
git clone <repository-url> ksec
cd ksec
make install        # pip install -e .  (optional; not required to run)
```

### 2.2 Run without installing

```bash
cd ksec
PYTHONPATH=src python3 -m ksec --help
```

Add a shell alias for convenience:

```bash
echo 'alias ksec="PYTHONPATH=/path/to/ksec/src python3 -m ksec"' >> ~/.bashrc
```

## 3. First run

```bash
ksec init --username admin --password 'choose-a-strong-password'
```

`init` creates:

- `$KSEC_HOME` (default `~/.ksec`): `ksec.db` (SQLite), `ksec.log`, config
- `$KSEC_HOME/config.toml` — your configuration file
- The schema (runs all migrations) and seeds roles/permissions/workspaces
- The admin user (scrypt-hashed password)

Verify:

```bash
ksec status      # schema version, paths, counts
ksec doctor      # health checks: db, migrations, tools, plugins, backup
```

> `KSEC_HOME` and `KSEC_CONFIG` override the defaults, e.g.
> `KSEC_HOME=/tmp/ops KSEC_CONFIG=/tmp/ops/config.toml ksec init ...`.
> This is how you keep separate environments (test vs. production).

## 4. Post-install checklist

1. `ksec env` — confirm the Kali fingerprint and which tools were found.
2. `ksec tools list` / `ksec tools health` — see capability readiness.
3. `ksec admin user create --username operator --role operator` — add a
   non-admin operator.
4. `ksec engagement create --name "Eng 1"` then
   `ksec engagement scope add --engagement 1 --target example.com` — define
   what is authorized.
5. `ksec session open --user admin --workspace RED_TEAM` — open a workspace
   session.
6. `ksec backup create` — take the first backup (also makes future
   `ksec update check` rollback-ready).
7. `ksec update check` — everything should report `ok` (except
   "latest version" if you are not on the newest release).

## 5. Uninstall

```bash
pip uninstall ksec            # if installed via pip
rm -rf ~/.ksec                # local state (db, logs, config, backups)
```

There is no system-level footprint: everything lives under `$KSEC_HOME`.

## 6. Upgrades

See the [Operations Guide](operations.md) — in short:

1. `ksec backup create`
2. `ksec update check` (confirm rollback-ready)
3. Pull the new code
4. `ksec doctor` (migrations apply automatically on first use)
5. `ksec plugin check`
