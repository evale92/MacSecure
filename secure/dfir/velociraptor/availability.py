"""
secure/dfir/velociraptor/availability.py — whether the `velociraptor`
binary can actually be used right now, and its version. Mirrors
secure/integrations/yarax/availability.py's own reasoning: don't infer
"present, so surely fine" from a bare version-string success — but
unlike yara_x (a Python-importable library), Velociraptor is invoked as
an external binary, so this checks the same way
secure/integrations/osquery/availability.py checks osqueryi: run a
real, harmless subcommand and see whether it actually completes.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from secure.config import AppConfig
from secure.dfir.velociraptor._shell import run
from secure.integrations.base import (
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    IntegrationHealth,
)


def check_availability(cfg: AppConfig, timeout: float = 10.0) -> IntegrationHealth:
    """ok — the binary ran `version` successfully. unavailable — the
    binary isn't installed/reachable at all (routine, not an error —
    Velociraptor is an optional specialist tool most installs won't
    have). error — the binary exists but the version check itself
    failed (a broken install, a permissions issue, an incompatible
    build).
    """
    now = datetime.now(timezone.utc).isoformat()
    binary = cfg.velociraptor_binary_resolved()

    result = run(binary, ["version"], timeout=timeout)
    if result.returncode is None and "not found" in result.stderr:
        return IntegrationHealth(
            status=STATUS_UNAVAILABLE,
            detail=f"velociraptor binary not found ({binary!r}). Set AppConfig."
            "velociraptor_binary_path if it's installed somewhere not on PATH.",
            collected_at=now,
        )
    if not result.ok:
        return IntegrationHealth(
            status=STATUS_ERROR,
            detail=f"velociraptor is present at {binary!r} but the version check failed: {result.stderr.strip() or 'unknown error'}",
            collected_at=now,
        )

    version = None
    text = result.stdout.strip()
    if text:
        match = re.search(r"\d+\.\d+\.\d+", text)
        version = match.group(0) if match else text

    return IntegrationHealth(
        status=STATUS_OK,
        detail=f"velociraptor is available at {binary!r}.",
        collected_at=now,
        tool_version=version,
    )
