"""
integrations/zeek/availability.py — determines whether Zeek's own log
output can actually be read right now.

Four honest outcomes, matching IntegrationHealth's four statuses:

    unavailable — no Zeek log directory configured, or the configured
                  directory doesn't exist. Routine, not an error: Zeek
                  is simply not set up yet.
    error       — the directory exists but couldn't be listed/read at
                  all (permissions, I/O error).
    degraded    — the directory exists and is readable, but either NONE
                  of the four recognized log files (conn.log, dns.log,
                  ssl.log, http.log) are present, or every log file
                  that IS present hasn't been modified recently (stale
                  — Zeek may not be running, or has stopped writing
                  this log).
    ok          — at least one recognized log file is present and was
                  modified within `stale_after_seconds`.

Deliberately narrower than Suricata's own availability.py: this
integration does NOT attempt to confirm packet-capture-level visibility
(Suricata's own `stats` capture counters) — that honesty requirement
was Suricata's phase-specific instruction (Phase 18), tied to
Suricata's specific role as the detection engine whose silence needs to
be distinguishable from "confirmed clean." Zeek's role here is
behavioral telemetry, not detection (see scanner.py's module
docstring) — "at least one target log file exists and is being
actively written to" is a proportionate, honestly-stated health bar for
that role, not a claim about what fraction of network packets Zeek
itself is seeing.

File MODIFICATION TIME (not log content) is used for the freshness
check — cheap, doesn't require parsing, and is a standard, honest
signal that a log-writing process is still alive; the exact same kind
of signal `secure listening`/`secure connections` already implicitly
rely on when they note "Secure only reports what its last scan saw."
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from secure.config import AppConfig
from secure.integrations.base import (
    STATUS_DEGRADED,
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    IntegrationHealth,
)
from secure.integrations.zeek._logs import LOG_FILES
from secure.integrations.zeek._shell import try_get_version

DEFAULT_STALE_AFTER_SECONDS = 600.0  # 10 minutes with no fresh write to any target log


def check_availability(
    cfg: AppConfig, stale_after_seconds: float = DEFAULT_STALE_AFTER_SECONDS
) -> IntegrationHealth:
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    tool_version = try_get_version()

    log_dir = cfg.zeek_log_dir_resolved()
    if log_dir is None:
        return IntegrationHealth(
            status=STATUS_UNAVAILABLE,
            detail="No Zeek log directory configured (AppConfig.zeek_log_dir).",
            collected_at=now,
            tool_version=tool_version,
        )
    if not log_dir.is_dir():
        return IntegrationHealth(
            status=STATUS_UNAVAILABLE,
            detail=f"Zeek log directory not found at {log_dir}.",
            collected_at=now,
            tool_version=tool_version,
        )

    try:
        present = [name for name in LOG_FILES if (log_dir / name).is_file()]
    except OSError as exc:
        return IntegrationHealth(
            status=STATUS_ERROR,
            detail=f"Could not read Zeek log directory at {log_dir}: {exc}",
            collected_at=now,
            tool_version=tool_version,
        )

    if not present:
        return IntegrationHealth(
            status=STATUS_DEGRADED,
            detail=(
                f"Zeek log directory {log_dir} exists but none of the recognized "
                f"log files ({', '.join(LOG_FILES)}) were found — Zeek may not be "
                "configured to log these, or hasn't started yet."
            ),
            collected_at=now,
            tool_version=tool_version,
        )

    fresh: "list[str]" = []
    stale: "list[str]" = []
    for name in present:
        try:
            mtime = datetime.fromtimestamp((log_dir / name).stat().st_mtime, tz=timezone.utc)
        except OSError:
            stale.append(name)
            continue
        age_seconds = (now_dt - mtime).total_seconds()
        if age_seconds <= stale_after_seconds:
            fresh.append(name)
        else:
            stale.append(name)

    if not fresh:
        return IntegrationHealth(
            status=STATUS_DEGRADED,
            detail=(
                f"Found {len(present)} recognized log file(s) in {log_dir} "
                f"({', '.join(present)}), but none have been updated within "
                f"{stale_after_seconds:.0f}s — Zeek may not be running, or has "
                "stopped writing these logs."
            ),
            collected_at=now,
            tool_version=tool_version,
        )

    detail = f"{len(fresh)} of {len(LOG_FILES)} target log(s) present and fresh: {', '.join(fresh)}."
    if stale:
        detail += f" Stale (not updated recently): {', '.join(stale)}."
    return IntegrationHealth(status=STATUS_OK, detail=detail, collected_at=now, tool_version=tool_version)
