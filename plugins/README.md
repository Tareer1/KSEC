# KSEC Plugin System

Plugins add new capabilities (tools, adapters, parsers) to KSEC without
changing the core engine (spec 04#52). A plugin is a directory containing a
`manifest.json` plus optional Python modules.

```
plugins/
├── web/
│   └── http_headers/        ← bundled example plugin (read this first!)
│       ├── manifest.json
│       ├── adapter.py
│       ├── parser.py
│       ├── health.py
│       └── README.md
├── discovery/   network/    api/     wireless/    vulnerability/
├── cloud/       containers/ endpoint/ dfir/        malware/
├── threat_intel/ reporting/ compliance/ integrations/
└── README.md
```

Bundled plugins live in the repository `plugins/` tree and are treated as
`CORE_TRUSTED`. User plugins are installed into
`<data_dir>/plugins/` via `ksec plugin install`.

---

## 1. Manifest (`manifest.json`)

```json
{
  "id": "org.example.my-tool",
  "name": "My Tool Plugin",
  "version": "1.0.0",
  "description": "What this plugin does.",
  "author": "you",
  "category": "network",
  "trust_level": "THIRD_PARTY",
  "permissions": ["network.access", "tool.execute"],
  "capabilities": ["my_scan"],
  "dependencies": {"tools": ["nmap"], "python": ">=3.10"},
  "safety": "ACTIVE_SAFE",
  "adapters": [
    {
      "capability": "my_scan",
      "tool": "nmap",
      "safety": "ACTIVE_SAFE",
      "parser": "my_scan",
      "module": "adapter.py",
      "class": "MyScanAdapter"
    }
  ],
  "parsers": [
    {"name": "my_scan", "module": "parser.py", "class": "MyScanParser"}
  ],
  "health_check": {"module": "health.py", "class": "check"}
}
```

### Required fields

| Field | Description |
|---|---|
| `id` | Unique dotted identifier, `^[a-z0-9][a-z0-9_.-]*$` |
| `name` | Human-readable name |
| `version` | Semantic version (e.g. `1.0.0`) |
| `description` / `author` | Strings |
| `category` | One of the spec categories (web, network, dfir, ...) |
| `trust_level` | `CORE_TRUSTED` \| `VERIFIED` \| `LOCAL` \| `THIRD_PARTY` \| `UNTRUSTED` \| `BLOCKED` |
| `permissions` | Declared permissions (see below) |
| `capabilities` | Capability identifiers the plugin provides |

### Permissions (spec 06#44)

Plugins must declare **exactly** the privileges they use. The declared set is
validated against a fixed list; undeclared privileges are rejected at install:

```
network.access   — connect out to targets
network.listen   — listen on sockets
filesystem.read  — read files
filesystem.write — write files
tool.execute     — run external binaries
database.read    — read KSEC data
database.write   — write KSEC data
```

Additionally, the `safety` class (`PASSIVE` / `ACTIVE_SAFE` /
`ACTIVE_AGGRESSIVE`) implies a minimum permission set that the manifest must
declare. A plugin that runs tools must declare `tool.execute`; an active
scanner must also declare `network.access`.

### Trust levels (spec 06#45)

| Level | Executes? | Notes |
|---|---|---|
| `CORE_TRUSTED` | yes | Ships with KSEC |
| `VERIFIED` | yes | Reviewed by the KSEC project |
| `LOCAL` | yes | Written/verified locally |
| `THIRD_PARTY` | yes | Reviewed before enabling |
| `UNTRUSTED` | **no** | Never loaded or executed |
| `BLOCKED` | **no** | Permanently denied |

`UNTRUSTED` and `BLOCKED` plugins are never loaded. Enabling a plugin whose
trust level is not executable fails.

## 2. Adapter

Subclass `ksec.adapters.base.ToolAdapter`. The adapter must return a
**validated argument list** (never a shell string) from `build_command`:

```python
from ksec.adapters.base import CommandRequest, ToolAdapter
from ksec.execution.command_builder import validate_target

class MyScanAdapter(ToolAdapter):
    name = "nmap"
    capability = "my_scan"
    description = "..."            # optional
    safety = "ACTIVE_SAFE"         # optional
    default_parser = "my_scan"     # optional; wired from the manifest

    def build_command(self, request: CommandRequest) -> list[str]:
        target = validate_target(request.target)
        return ["nmap", "-oX", "-", target]
```

## 3. Parser

Subclass `ksec.parsers.base.OutputParser` and return a `ParsedResult` with
structured `entities`:

```python
from ksec.parsers.base import OutputParser, ParsedResult

class MyScanParser(OutputParser):
    name = "my_scan"
    formats = ("text", "xml")

    def parse(self, output: str) -> ParsedResult:
        return ParsedResult(tool="nmap", entities=[...], raw=output)
```

## 4. Health check (optional)

A module with a `check()` callable returning `{"ok": bool, ...}`. Used by
`ksec plugin check`.

## 5. Installing

```bash
ksec plugin install /path/to/my-plugin --trust THIRD_PARTY --yes
ksec plugin list
ksec plugin check
ksec plugin disable my-id
ksec plugin enable my-id
ksec plugin uninstall my-id --yes
```

Install requires a valid manifest, declared permissions and (for anything but
`CORE_TRUSTED`/`VERIFIED`) explicit approval with `--yes`. The plugin
directory is copied into `<data_dir>/plugins/` and recorded in the
`plugin_registry` table; its SHA-256 is stored for tamper detection.

## 6. Safety rules

* Only modules **inside the plugin directory** can be imported; a manifest
  cannot point at arbitrary paths.
* Plugin adapters never shadow built-in capabilities.
* The scheduler re-checks the plugin's status/trust/permissions before every
  plugin-provided job (spec: "the plugin must not receive undeclared
  privileges").
* A failed plugin never prevents KSEC core from starting.

## 7. Testing your plugin

Write unit tests for the adapter and parser; they run against the same base
classes as built-ins:

```bash
PYTHONPATH=src python3 -m unittest tests/test_plugins.py
```