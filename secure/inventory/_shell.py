"""
inventory/_shell.py — the ONLY place the inventory package is allowed
to run a subprocess (mirrors secure/checks/_shell.py — kept as its own
copy rather than a shared import so the two packages stay independent
of each other, per PROJECT_NOTES.md's "keep every monitoring feature
in its own module").

Same rules as everywhere else in this app: read-only, no sudo, ever.
Bare command names resolve from fixed system directories, never from
`$PATH`, the same rule secure/checks/_shell.py follows (J-0251).
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

# Where macOS keeps the read-only tools this package asks for. Only root
# can write these; `$PATH` is deliberately not consulted.
_SYSTEM_BIN_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")


@dataclass
class ShellResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: "int | None"


def _resolve(program: str) -> "str | None":
    """Absolute path for `program`, or None if it isn't a system tool.

    A program given with a slash in it is an explicit path and is
    returned unchanged. A bare name is looked up in `_SYSTEM_BIN_DIRS`
    only, so a shim earlier in `$PATH` can never answer for `arp`,
    `route`, `ifconfig` or `ping` and decide which devices the local
    inventory records.
    """
    if "/" in program:
        return program
    for directory in _SYSTEM_BIN_DIRS:
        candidate = os.path.join(directory, program)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def run(args: "list[str]", timeout: float = 5.0) -> ShellResult:
    if args:
        resolved = _resolve(args[0])
        if resolved is None:
            return ShellResult(
                ok=False,
                stdout="",
                stderr=f"{args[0]}: not found in {', '.join(_SYSTEM_BIN_DIRS)}",
                returncode=None,
            )
        args = [resolved, *args[1:]]
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
