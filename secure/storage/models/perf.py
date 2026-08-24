"""
perf.py — Phase 30 (Performance & Diagnostics): `perf_module_runs` and
`perf_milestones` — see secure/diagnostics/ and database.py's own
schema comment for the full design reasoning.

Same "this module doesn't interpret, it only persists" separation
every other domain file in this package keeps: this file has no idea
how a duration was measured, what counts as an expensive module, or
what a milestone label means — it only stores and retrieves the
already-decided rows secure/diagnostics/ hands it.

Deliberately the smallest storage surface Phase 30 could get away
with, per its own governing instruction ("keep storage minimal... do
not build high-frequency performance telemetry"): no live
hardware/system-health table exists at all — those reads
(secure/diagnostics/hardware.py, system.py) are always computed fresh,
never persisted. `perf_module_runs` is append-only (one row per
instrumented scan/integration operation, written only when that
operation actually runs — never on a timer) and `perf_milestones` is
written only by an explicit `secure diagnostics milestone record`
call, never automatically.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Optional


@dataclass
class PerfModuleRunRecord:
    id: int
    run_group_id: str
    module: str
    operation: str
    external_tool: "Optional[str]"
    started_at: str
    completed_at: str
    duration_seconds: float
    cpu_time_seconds: "Optional[float]"
    rss_bytes_at_end: "Optional[int]"
    observations_processed: "Optional[int]"
    findings_produced: "Optional[int]"
    error: "Optional[str]"
    timed_out: bool


@dataclass
class PerfMilestoneRecord:
    id: int
    label: str
    recorded_at: str
    secure_version: str
    run_all_duration_seconds: "Optional[float]"
    secure_peak_rss_bytes: "Optional[int]"
    db_size_bytes: "Optional[int]"
    notes: str


def _row_to_module_run(row: sqlite3.Row) -> PerfModuleRunRecord:
    data = dict(row)
    data["timed_out"] = bool(data["timed_out"])
    return PerfModuleRunRecord(**data)


def _row_to_milestone(row: sqlite3.Row) -> PerfMilestoneRecord:
    return PerfMilestoneRecord(**dict(row))


def add_perf_module_run(
    conn: sqlite3.Connection,
    *,
    run_group_id: str,
    module: str,
    operation: str,
    external_tool: "Optional[str]",
    started_at: str,
    completed_at: str,
    duration_seconds: float,
    cpu_time_seconds: "Optional[float]",
    rss_bytes_at_end: "Optional[int]",
    observations_processed: "Optional[int]",
    findings_produced: "Optional[int]",
    error: "Optional[str]",
    timed_out: bool = False,
) -> int:
    cursor = conn.execute(
        "INSERT INTO perf_module_runs (run_group_id, module, operation, external_tool, "
        "started_at, completed_at, duration_seconds, cpu_time_seconds, rss_bytes_at_end, "
        "observations_processed, findings_produced, error, timed_out) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_group_id, module, operation, external_tool, started_at, completed_at,
            duration_seconds, cpu_time_seconds, rss_bytes_at_end, observations_processed,
            findings_produced, error, 1 if timed_out else 0,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def list_recent_perf_module_runs(
    conn: sqlite3.Connection, limit: int = 100, module: "Optional[str]" = None
) -> "list[PerfModuleRunRecord]":
    if module is not None:
        rows = conn.execute(
            "SELECT * FROM perf_module_runs WHERE module = ? ORDER BY id DESC LIMIT ?",
            (module, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM perf_module_runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_module_run(row) for row in rows]


def list_perf_module_runs_for_group(
    conn: sqlite3.Connection, run_group_id: str
) -> "list[PerfModuleRunRecord]":
    rows = conn.execute(
        "SELECT * FROM perf_module_runs WHERE run_group_id = ? ORDER BY id", (run_group_id,)
    ).fetchall()
    return [_row_to_module_run(row) for row in rows]


def add_perf_milestone(
    conn: sqlite3.Connection,
    *,
    label: str,
    recorded_at: str,
    secure_version: str,
    run_all_duration_seconds: "Optional[float]",
    secure_peak_rss_bytes: "Optional[int]",
    db_size_bytes: "Optional[int]",
    notes: str = "",
) -> int:
    cursor = conn.execute(
        "INSERT INTO perf_milestones (label, recorded_at, secure_version, "
        "run_all_duration_seconds, secure_peak_rss_bytes, db_size_bytes, notes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            label, recorded_at, secure_version, run_all_duration_seconds,
            secure_peak_rss_bytes, db_size_bytes, notes,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def list_perf_milestones(conn: sqlite3.Connection, limit: int = 100) -> "list[PerfMilestoneRecord]":
    rows = conn.execute(
        "SELECT * FROM perf_milestones ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_milestone(row) for row in rows]


# Fixed allowlist of every *_alerts/finding table in the schema, same
# "never build a dynamic query against an arbitrary table name" caution
# secure/storage/integrity.py's KNOWN_EVIDENCE_SOURCE_TABLES established
# in Phase 29 Stage 6 — used here only to answer "how many findings has
# Secure ever produced" for `secure diagnostics performance`'s summary,
# a read-only diagnostic count, never a security judgment of its own.
_FINDING_TABLES = (
    "arp_alerts",
    "wifi_alerts",
    "bluetooth_alerts",
    "ble_alerts",
    "persistence_alerts",
    "correlation_alerts",
    "correlation_chain_alerts",
    "file_integrity_alerts",
    "integration_alerts",
    "anomaly_events",
)


def count_total_findings(conn: sqlite3.Connection) -> "dict[str, int]":
    """{table_name: row_count} for every known finding/alert table.
    Bounded, fixed set — never derived from sqlite_master, so a rename
    or drop shows up as a KeyError at development time, not a silently
    wrong count in production.
    """
    counts = {}
    for table in _FINDING_TABLES:
        row = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
        counts[table] = row["n"]
    return counts
