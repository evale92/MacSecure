"""
correlate_chains.py — Phase 22: provenance-aware behavioral correlation
— the `correlation_chain_alerts` table. See secure/correlate/chains.py.

Same idempotent-by-fingerprint discipline secure/storage/models/
correlate.py's own add_correlation_alert() already established for
temporal-cluster alerts, applied to chain alerts — a SEPARATE table,
not a variant of the same one (see database.py's schema comment on
correlation_chain_alerts for why "add alongside, don't replace" was
the approved design for this phase).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class CorrelationChainAlertRecord:
    id: int
    created_at: str
    run_id: str
    fingerprint: str
    start_source_table: str
    start_source_id: int
    raw_observation_count: int
    independent_fact_count: int
    module_count: int
    source_count: int
    meaningful_relationship_count: int
    concentration: float
    raw_score: int
    score: int
    severity: str
    confidence: str
    uncertainty_notes: list  # parsed from JSON
    benign_context_notes: "str | None"
    explanation: str
    members: list  # parsed from JSON — see secure/correlate/chains.py for the shape
    edges: list    # parsed from JSON
    known: bool


def _row_to_chain_alert(row: sqlite3.Row) -> CorrelationChainAlertRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    data["uncertainty_notes"] = json.loads(data["uncertainty_notes"])
    data["members"] = json.loads(data["members"])
    data["edges"] = json.loads(data["edges"])
    return CorrelationChainAlertRecord(**data)


def add_correlation_chain_alert(
    conn: sqlite3.Connection,
    run_id: str,
    fingerprint: str,
    start_source_table: str,
    start_source_id: int,
    raw_observation_count: int,
    independent_fact_count: int,
    module_count: int,
    source_count: int,
    meaningful_relationship_count: int,
    concentration: float,
    raw_score: int,
    score: int,
    severity: str,
    confidence: str,
    uncertainty_notes: list,
    benign_context_notes: "str | None",
    explanation: str,
    members: list,
    edges: list,
) -> "tuple[CorrelationChainAlertRecord, bool]":
    """Record one scored chain; insert if new, do nothing if a chain
    with this exact fingerprint (every member node's exact identity —
    see secure/correlate/chains.py's fingerprint_for_chain()) is already
    on record. Returns (record, was_new), same idempotent-write shape
    as add_correlation_alert().
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT OR IGNORE INTO correlation_chain_alerts "
        "(created_at, run_id, fingerprint, start_source_table, start_source_id, "
        "raw_observation_count, independent_fact_count, module_count, source_count, "
        "meaningful_relationship_count, concentration, raw_score, score, severity, confidence, "
        "uncertainty_notes, benign_context_notes, explanation, members, edges, known) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        (
            created_at, run_id, fingerprint, start_source_table, start_source_id,
            raw_observation_count, independent_fact_count, module_count, source_count,
            meaningful_relationship_count, concentration, raw_score, score, severity, confidence,
            json.dumps(uncertainty_notes), benign_context_notes, explanation,
            json.dumps(members), json.dumps(edges),
        ),
    )
    conn.commit()

    if cursor.rowcount == 0:
        row = conn.execute(
            "SELECT * FROM correlation_chain_alerts WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return _row_to_chain_alert(row), False

    row = conn.execute(
        "SELECT * FROM correlation_chain_alerts WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return _row_to_chain_alert(row), True


def list_correlation_chain_alerts(
    conn: sqlite3.Connection, limit: int = 100
) -> "list[CorrelationChainAlertRecord]":
    """Return the most recent chain alerts, newest first."""
    rows = conn.execute(
        "SELECT * FROM correlation_chain_alerts ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_chain_alert(row) for row in rows]


def find_correlation_chain_alert_by_id(
    conn: sqlite3.Connection, alert_id: int
) -> "CorrelationChainAlertRecord | None":
    row = conn.execute("SELECT * FROM correlation_chain_alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row_to_chain_alert(row) if row else None


def set_correlation_chain_alert_known(conn: sqlite3.Connection, alert_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE correlation_chain_alerts SET known = ? WHERE id = ?",
        (1 if known else 0, alert_id),
    )
    conn.commit()
