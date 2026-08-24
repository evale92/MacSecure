"""
integrations/osquery/availability.py — determines whether osqueryi can
be used right now, and if so, its own version. This is the ONLY
osquery-specific place that decides between IntegrationHealth's four
statuses (secure/integrations/base.py) — every other osquery module
just receives an already-classified IntegrationHealth and acts on it.

Deliberately a single lightweight query (`SELECT version FROM
osquery_info`) rather than assuming success from `which osqueryi` alone
— a binary can be on PATH but still fail to actually run a query (wrong
architecture, broken install, sandboxing, permission issues, ...), and
Phase 15's instruction is that failure must show up as unavailable/
error, never be inferred as "present, so surely fine."
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from secure.integrations.base import (
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    IntegrationHealth,
)
from secure.integrations.osquery._shell import run_query

_VERSION_QUERY = "SELECT version FROM osquery_info;"


def check_availability(timeout: float = 10.0) -> IntegrationHealth:
    """Run one cheap osquery_info query and classify the result.

    unavailable — osqueryi isn't installed/on PATH, or timed out before
                  even returning (ShellResult.returncode is None).
    error       — osqueryi ran but this specific query failed (bad
                  exit code) or returned something that isn't the JSON
                  shape expected.
    ok          — osqueryi ran, returned exactly one row, and a version
                  string was read from it.
    """
    now = datetime.now(timezone.utc).isoformat()
    result = run_query(_VERSION_QUERY, timeout=timeout)

    if result.returncode is None:
        # Distinguishes "not installed/found" from "installed but timed
        # out" using the same stderr text _shell.run() already sets —
        # both are routine unavailability, not a Secure-side bug.
        detail = (
            "osqueryi not found on PATH"
            if result.stderr == "command not found"
            else f"osqueryi did not respond: {result.stderr}"
        )
        return IntegrationHealth(status=STATUS_UNAVAILABLE, detail=detail, collected_at=now)

    if not result.ok:
        detail = f"osqueryi exited {result.returncode}: {result.stderr.strip() or '(no stderr)'}"
        return IntegrationHealth(status=STATUS_ERROR, detail=detail, collected_at=now)

    try:
        rows = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        return IntegrationHealth(
            status=STATUS_ERROR,
            detail=f"osqueryi returned unparseable output: {exc}",
            collected_at=now,
        )

    if not isinstance(rows, list) or not rows or "version" not in rows[0]:
        return IntegrationHealth(
            status=STATUS_ERROR,
            detail="osqueryi returned no usable osquery_info row",
            collected_at=now,
        )

    version = rows[0].get("version")
    return IntegrationHealth(
        status=STATUS_OK,
        detail="osqueryi is available",
        collected_at=now,
        tool_version=version,
    )
