"""
correlate.py — Cross-module correlation: correlation_alerts — see secure/correlate/.

Split out of the original secure/storage/models.py (Phase 14.5 Stage C)
purely mechanically — behavior, SQL, and function signatures are
unchanged; only the file this code lives in changed. See
secure/storage/models/__init__.py for the full original module
docstring and the re-export surface that preserves
`from secure.storage.models import X` for every name.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

# ---------- Cross-Module Correlation ----------


@dataclass
class CorrelationAlertRecord:
    id: int
    created_at: str
    run_id: str
    fingerprint: str
    window_seconds: float
    cluster_start: str
    cluster_end: str
    module_count: int
    signal_count: int
    score: int
    severity: str
    triggered_by: str | None
    context_notes: str | None
    explanation: str
    members: list  # parsed from JSON — see secure/correlate/analysis.py for the shape
    known: bool


def _row_to_correlation_alert(row: sqlite3.Row) -> CorrelationAlertRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    data["members"] = json.loads(data["members"])
    return CorrelationAlertRecord(**data)


def add_correlation_alert(
    conn: sqlite3.Connection,
    run_id: str,
    fingerprint: str,
    window_seconds: float,
    cluster_start: str,
    cluster_end: str,
    module_count: int,
    signal_count: int,
    score: int,
    severity: str,
    triggered_by: "str | None",
    context_notes: "str | None",
    explanation: str,
    members: list,
) -> tuple[CorrelationAlertRecord, bool]:
    """Record one correlation cluster; insert if new, do nothing if a
    cluster with this exact fingerprint is already on record.

    Unlike every other add_*_alert() in this module, this is
    idempotent by design rather than append-only: `secure correlate`
    is meant to be safe to re-run over overlapping history (the same
    --lookback-hours window, run again an hour later) without
    re-alerting on a cluster it already reported. `fingerprint` (a
    hash of the cluster's member rows' identities — see
    secure/correlate/analysis.py) is UNIQUE-constrained, so
    `INSERT OR IGNORE` silently does nothing on a repeat. `known`
    defaults to 0 for a genuinely new cluster.

    Returns (record, was_new) — was_new is False when this exact
    cluster was already recorded (the returned record is the existing
    one), True only when this call actually inserted a new row.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT OR IGNORE INTO correlation_alerts "
        "(created_at, run_id, fingerprint, window_seconds, cluster_start, cluster_end, "
        "module_count, signal_count, score, severity, triggered_by, context_notes, "
        "explanation, members, known) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        (
            created_at,
            run_id,
            fingerprint,
            window_seconds,
            cluster_start,
            cluster_end,
            module_count,
            signal_count,
            score,
            severity,
            triggered_by,
            context_notes,
            explanation,
            json.dumps(members),
        ),
    )
    conn.commit()

    if cursor.rowcount == 0:
        # Already existed — INSERT OR IGNORE silently skipped it.
        row = conn.execute(
            "SELECT * FROM correlation_alerts WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return _row_to_correlation_alert(row), False

    row = conn.execute(
        "SELECT * FROM correlation_alerts WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return _row_to_correlation_alert(row), True


def list_correlation_alerts(conn: sqlite3.Connection, limit: int = 100) -> list[CorrelationAlertRecord]:
    """Return the most recent correlation alerts, newest first."""
    rows = conn.execute(
        "SELECT * FROM correlation_alerts ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_correlation_alert(row) for row in rows]


def find_correlation_alert_by_id(conn: sqlite3.Connection, alert_id: int) -> CorrelationAlertRecord | None:
    row = conn.execute("SELECT * FROM correlation_alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row_to_correlation_alert(row) if row else None


def set_correlation_alert_known(conn: sqlite3.Connection, alert_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE correlation_alerts SET known = ? WHERE id = ?",
        (1 if known else 0, alert_id),
    )
    conn.commit()
