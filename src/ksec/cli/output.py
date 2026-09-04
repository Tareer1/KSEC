"""CLI output helpers: human-readable and ``--json`` machine output."""
from __future__ import annotations

import json
import sys


def emit(data, as_json: bool = False, quiet: bool = False) -> None:
    """Print ``data`` either as JSON (default=str safe) or plain text."""
    if as_json:
        print(json.dumps(data, indent=2, default=str))
        return
    if quiet:
        return
    if isinstance(data, str):
        print(data)
    elif isinstance(data, (list, tuple)):
        for item in data:
            print(item)
    else:
        print(json.dumps(data, indent=2, default=str))


def error(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)