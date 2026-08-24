"""
integrations/zeek/_shell.py — the ONLY place this integration runs a
subprocess, and even this is optional: a single, read-only `zeek
--version` call purely to attach a `tool_version` string to
IntegrationHealth. Mirrors secure/integrations/suricata/_shell.py
exactly (kept as its own copy rather than a shared import, per this
codebase's "keep every monitoring feature/integration independent of
the others" convention).

Secure's ability to read Zeek's own log files does NOT depend on this
binary being found — Zeek may be running on a different host, inside a
container or VM, or simply not on this Mac's PATH even though its log
output directory is still reachable (e.g. shared via a mounted volume
or Syncthing). A missing/failing `zeek` binary therefore never affects
IntegrationHealth.status here; it only means `tool_version` stays None.
See availability.py.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Optional

ZEEK_BIN = "zeek"

_VERSION_RE = re.compile(r"\d+\.\d+\.\d+")


@dataclass
class ShellResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: "int | None"


def run(args: "list[str]", timeout: float = 5.0) -> ShellResult:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
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


def try_get_version(timeout: float = 5.0) -> "Optional[str]":
    """Best-effort `zeek --version` version string, or None on anything
    other than a clean success — never raises, never required for the
    rest of this integration to function.
    """
    result = run([ZEEK_BIN, "--version"], timeout=timeout)
    if not result.ok:
        return None
    match = _VERSION_RE.search(result.stdout)
    if match:
        return match.group(0)
    text = result.stdout.strip()
    return text or None
