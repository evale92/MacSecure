"""
correlate/_shell.py — the ONLY place the correlate package is allowed
to run a subprocess (mirrors every other package's own `_shell.py`
copy — see PROJECT_NOTES.md's "keep every monitoring feature in its
own module"). Used for exactly one thing: reading this Mac's boot time
via `sysctl -n kern.boottime`, for the benign-context annotation in
context.py — everything else in secure/correlate/ only reads the
database, no subprocess involved.

Same rules as everywhere else in this app: read-only, no sudo, ever.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class ShellResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: "int | None"


def run(args: "list[str]", timeout: float = 5.0) -> ShellResult:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return ShellResult(
            ok=completed.returncode == 0,
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
        )
    except FileNotFoundError:
        return ShellResult(ok=False, stdout="", stderr="command not found", returncode=None)
    except subprocess.TimeoutExpired:
        return ShellResult(ok=False, stdout="", stderr="command timed out", returncode=None)
