# HTTP Headers Collector (ksec.http-headers)

A minimal, working KSEC plugin that adds a new capability — `http_headers` —
**without changing the core engine** (spec 04#52). It uses `curl -sSI` to
fetch the HTTP response headers of a URL.

## What it demonstrates

| Component | File | Notes |
|---|---|---|
| Manifest | `manifest.json` | declares id, version, category, **trust level**, **permissions**, capabilities, dependencies, adapter + parser descriptors |
| Adapter | `adapter.py` | `ToolAdapter` subclass → builds a validated `curl` command |
| Parser | `parser.py` | `OutputParser` subclass → header lines into `http_header` entities |
| Health check | `health.py` | `ksec plugin check` invokes it |

## Lifecycle

```bash
ksec plugin list        # bundled plugins appear as CORE_TRUSTED / ENABLED
ksec plugin info ksec.http-headers
ksec plugin check       # health + manifest + hash verification
ksec plugin disable ksec.http-headers   # unregisters its adapter
ksec plugin enable ksec.http-headers    # re-registers
```

Because it declares `tool.execute` + `network.access` and ships with
`CORE_TRUSTED`, it loads at bootstrap and its capability is immediately
usable in workflows:

```bash
ksec run http_headers example.com --user admin
```

## Writing your own plugin

See `plugins/README.md` for the full plugin development guide.