"""Tool execution engine (spec: EXECUTION ENGINE).

Simple blocking execution used by CLI/tests. The scheduler uses its own
cancellable variant (``ksec.scheduler.service``) that can pause (SIGSTOP),
resume (SIGCONT) and kill in-flight processes.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass

from ksec.core.errors import KSECError


@dataclass(frozen=True)
class ExecutionResult:
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool


def run_command(
    executable: str,
    args: list[str],
    timeout: int = 300,
    cwd: str | None = None,
    env: dict | None = None,
) -> ExecutionResult:
    if shutil.which(executable) is None:
        raise KSECError(f"Tool not found: {executable}")
    started = time.monotonic()
    try:
        proc = subprocess.run(
            [executable, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
        return ExecutionResult(
            exit_code=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration_seconds=time.monotonic() - started,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        return ExecutionResult(
            exit_code=None,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            duration_seconds=time.monotonic() - started,
            timed_out=True,
        )
    except OSError as exc:
        raise KSECError(f"Failed to execute {executable}: {exc}") from exc