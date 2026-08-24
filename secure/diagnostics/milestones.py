"""
diagnostics/milestones.py — Phase 30 requirement 6 ("performance
history"): thin convenience wrapper over
secure/storage/models/perf.py's `perf_milestones` table.

Deliberately does nothing automatically — a milestone is written only
when `secure diagnostics milestone record "<label>"` is run explicitly
(per this phase's own "avoid high-frequency telemetry" instruction).
This module's only job is filling in the numbers a caller would
otherwise have to gather by hand (current self-usage peak RSS/db size,
secure_version) so recording a milestone is a one-line CLI command.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Optional

from secure import __version__ as SECURE_VERSION
from secure.diagnostics.self_usage import SecureSelfUsage
from secure.storage.models import add_perf_milestone, list_perf_milestones
from secure.storage.models.perf import PerfMilestoneRecord


def record_milestone(
    conn: sqlite3.Connection,
    *,
    label: str,
    self_usage: SecureSelfUsage,
    run_all_duration_seconds: "Optional[float]" = None,
    notes: str = "",
) -> int:
    return add_perf_milestone(
        conn,
        label=label,
        recorded_at=datetime.now(timezone.utc).isoformat(),
        secure_version=SECURE_VERSION,
        run_all_duration_seconds=run_all_duration_seconds,
        secure_peak_rss_bytes=self_usage.peak_rss_bytes,
        db_size_bytes=self_usage.db_size_bytes,
        notes=notes,
    )


def latest_milestone(conn: sqlite3.Connection) -> "Optional[PerfMilestoneRecord]":
    rows = list_perf_milestones(conn, limit=1)
    return rows[0] if rows else None
