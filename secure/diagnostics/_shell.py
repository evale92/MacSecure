"""
diagnostics/_shell.py — the ONLY place the diagnostics package is
allowed to run a subprocess (mirrors secure/listening/_shell.py,
secure/checks/_shell.py, secure/inventory/_shell.py, secure/connections/
_shell.py — kept as its own copy rather than a shared import, same
"keep every monitoring feature independent" reasoning those modules'
own docstrings give).

Same rules as everywhere else in this app: read-only, no sudo, ever.
Every command this package runs (sysctl, vm_stat, pmset, ps) is a
read-only status query — nothing here can change system state.
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
