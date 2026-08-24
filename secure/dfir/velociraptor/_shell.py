"""
secure/dfir/velociraptor/_shell.py — the only file in this integration
that runs a subprocess. Same shape as
secure/integrations/suricata/_shell.py, with one difference: the binary
to invoke is never a hardcoded constant here, since Velociraptor has no
one conventional install location the way `suricata`/`zeek` do on a
Homebrew-managed Mac — every caller passes `cfg.
velociraptor_binary_resolved()` (empty config resolves to the bare
"velociraptor" command, which still works if it's on PATH).
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import List, Optional

_VERSION_RE = re.compile(r"\d+\.\d+\.\d+")


@dataclass
class ShellResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: "Optional[int]"


def run(binary: str, args: List[str], timeout: float = 30.0) -> ShellResult:
    """Run `binary` with `args`, capturing output. Never raises — a
    missing binary or a timeout is reported as `ok=False` with a
    human-readable stderr, the same graceful-degradation discipline
    every other _shell.py in this codebase already follows.
    """
    try:
        completed = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)
        return ShellResult(
            ok=completed.returncode == 0,
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
        )
    except FileNotFoundError:
        return ShellResult(ok=False, stdout="", stderr=f"{binary}: command not found", returncode=None)
    except subprocess.TimeoutExpired:
        return ShellResult(ok=False, stdout="", stderr=f"{binary}: command timed out after {timeout:.0f}s", returncode=None)


def try_get_version(binary: str, timeout: float = 5.0) -> "Optional[str]":
    """Best-effort `<binary> version` output, or None on anything other
    than a clean success — never raises, never required for the rest of
    this integration to function. Mirrors
    suricata/_shell.py's try_get_version() exactly.
    """
    result = run(binary, ["version"], timeout=timeout)
    if not result.ok:
        return None
    match = _VERSION_RE.search(result.stdout)
    if match:
        return match.group(0)
    text = result.stdout.strip()
    return text or None
