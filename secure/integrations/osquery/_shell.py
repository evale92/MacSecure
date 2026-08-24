"""
integrations/osquery/_shell.py — the ONLY place the osquery integration
is allowed to run a subprocess (mirrors secure/listening/_shell.py,
secure/connections/_shell.py, secure/checks/_shell.py, and
secure/inventory/_shell.py — kept as its own copy rather than a shared
import so every monitoring feature/integration stays independent of the
others, per PROJECT_NOTES.md's "keep every monitoring feature in its
own module").

Same rules as everywhere else in this app: read-only, no sudo, ever.
`osqueryi` is queried directly (its interactive/one-shot binary), never
the `osqueryd` daemon or any config that would need installing or
modifying anything.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

OSQUERYI_BIN = "osqueryi"


@dataclass
class ShellResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: "int | None"


def run(args: "list[str]", timeout: float = 10.0) -> ShellResult:
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


def run_query(sql: str, timeout: float = 10.0) -> ShellResult:
    """Run one SQL query through `osqueryi --json "<sql>"` and return its
    raw result. Parsing/validating the JSON is the caller's job (see
    parser.py) — this function only knows how to invoke the binary.
    """
    return run([OSQUERYI_BIN, "--json", sql], timeout=timeout)
