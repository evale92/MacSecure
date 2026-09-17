"""
loghunt/_shell.py — the ONLY place the log hunts run a subprocess (a copy
of secure/checks/_shell.py, kept separate so each feature stays
independent). The one command it is asked to run is `/usr/bin/log show`.

Every command run through this module is:

    - read-only — nothing here changes system state.
    - run as the current user — this never invokes `sudo` or otherwise
      escalates privileges. A check that needs administrator access
      for a definitive answer reports WARNING and explains how to
      check manually instead.
    - given a timeout, so a hung command can't hang the whole posture
      check.
    - resolved from a fixed list of system directories, never from
      `$PATH`. A bare name like `csrutil` would otherwise be whatever
      binary the inherited environment points at first, and on a
      typical Mac `/opt/homebrew/bin` is both user-writable and ahead
      of `/usr/bin`, so an unprivileged shim could decide what the
      posture report says.

Routing every subprocess call through one function keeps "what
commands does this app actually run on my Mac" auditable from a single
file, instead of subprocess.run() calls scattered across every check
module.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

# Where macOS keeps the read-only tools the checks ask for. Only root
# can write these; `$PATH` is deliberately not consulted.
_SYSTEM_BIN_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")


@dataclass
class ShellResult:
    ok: bool                    # True if the command ran and exited 0
    stdout: str
    stderr: str
    returncode: "int | None"    # None if the command couldn't even start


def _resolve(program: str) -> "str | None":
    """Absolute path for `program`, or None if it isn't a system tool.

    A program given with a slash in it is already an explicit path and
    is returned unchanged — the caller named the file it wants. A bare
    name is looked up in `_SYSTEM_BIN_DIRS` only, so `$PATH` never
    chooses the binary.
    """
    if "/" in program:
        return program
    for directory in _SYSTEM_BIN_DIRS:
        candidate = os.path.join(directory, program)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def run(args: "list[str]", timeout: float = 120.0) -> ShellResult:
    """Run a read-only command and capture its output.

    Never raises for a missing binary or a non-zero exit code — a
    non-zero exit is sometimes the *expected* way a check reports a
    finding (e.g. some tools exit non-zero when a feature is off), so
    callers decide what a given result means, not this function.
    """
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
