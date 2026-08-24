"""
bluetooth/_shell.py — the ONLY place the bluetooth package is allowed
to run a subprocess (mirrors secure/checks/_shell.py,
secure/inventory/_shell.py, secure/connections/_shell.py,
secure/listening/_shell.py, secure/arpwatch/_shell.py, and
secure/wifi/_shell.py — kept as its own copy rather than a shared
import so every monitoring feature stays independent of the others,
per PROJECT_NOTES.md's "keep every monitoring feature in its own
module").

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
