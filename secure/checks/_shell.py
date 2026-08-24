"""
checks/_shell.py — the ONLY place posture checks are allowed to run a
subprocess.

Every command run through this module is:

    - read-only — nothing here changes system state.
    - run as the current user — this never invokes `sudo` or otherwise
      escalates privileges. A check that needs administrator access
      for a definitive answer reports WARNING and explains how to
      check manually instead.
    - given a timeout, so a hung command can't hang the whole posture
      check.

Routing every subprocess call through one function keeps "what
commands does this app actually run on my Mac" auditable from a single
file, instead of subprocess.run() calls scattered across every check
module.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class ShellResult:
    ok: bool                    # True if the command ran and exited 0
    stdout: str
    stderr: str
    returncode: "int | None"    # None if the command couldn't even start


def run(args: "list[str]", timeout: float = 5.0) -> ShellResult:
    """Run a read-only command and capture its output.

    Never raises for a missing binary or a non-zero exit code — a
    non-zero exit is sometimes the *expected* way a check reports a
    finding (e.g. some tools exit non-zero when a feature is off), so
    callers decide what a given result means, not this function.
    """
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
