"""
secure/storage/integrity.py — Phase 29 Stage 6: read-only referential-
integrity checks over evidence_links, the one place this app links two
existing rows together across tables (see secure/evidence/model.py).

This is a DIAGNOSTIC, not a detection capability: it never scores,
alerts, or blocks anything, and it changes no Phase 29 scope other than
"harden... database migrations, historical-data integrity, provenance,
deduplication." It answers one narrow, high-value question this
phase's own audit needs answered with evidence, not assertion: does
every evidence_links row still point at a real, existing row in the
table it names? An orphaned reference here would mean a link claims a
relationship to evidence that no longer resolves — silently misleading
anyone reading the evidence chain (secure/evidence/chain.py,
secure/investigate/timeline.py) into trusting a reference that doesn't
actually exist.

Read-only: every query here is a SELECT. Nothing in this module writes,
deletes, or repairs anything — it only reports what it finds.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import List

# Every table name this app has ever used as an evidence_links
# from_source_table/to_source_table value — confirmed by a repo-wide
# search across secure/ for ObservationRef(source_table=...) calls that
# feed record_link()/add_evidence_link() specifically (Stage 6 audit).
# A table name NOT in this set is itself reported as a finding
# ("unknown_table") rather than silently assumed fine or crashing this
# diagnostic with an unsafe dynamic query — the same "no missing sensor
# may appear as a clean result" discipline applied to this checker
# itself: an unrecognized reference is not evidence of health.
KNOWN_EVIDENCE_SOURCE_TABLES = frozenset({
    "connection_events",
    "integration_alerts",
    "integration_observations",
    "listening_services",
    "persistence_entries",
    "persistence_alerts",
    "persistence_observations",
    "process_entries",
    "forensic_collections",
    "file_integrity_alerts",
})


@dataclass(frozen=True)
class IntegrityIssue:
    evidence_link_id: int
    side: str  # "from" or "to"
    source_table: str
    source_id: int
    problem: str  # "unknown_table" or "missing_row"


@dataclass(frozen=True)
class AuditTrailIssue:
    """Represents a potential tampering or deletion in audit trail."""
    table_name: str
    record_id: int
    issue_type: str  # "hash_mismatch" | "chain_break" | "deletion_detected"
    details: str


def check_evidence_link_referential_integrity(conn: sqlite3.Connection) -> List[IntegrityIssue]:
    """Walk every evidence_links row and confirm both sides still
    resolve to a real row in the table they name. Returns one
    IntegrityIssue per broken reference found — an empty list means
    every evidence_links row currently resolves cleanly on both sides.

    O(n) in evidence_links row count, one indexed primary-key lookup
    per side per row — cheap enough to run as a manual audit pass or
    from `secure validate` without special-casing scale. `table` is
    always checked against KNOWN_EVIDENCE_SOURCE_TABLES before being
    interpolated into a query, so this never executes a query against
    an arbitrary/attacker-influenced table name.
    """
    issues: List[IntegrityIssue] = []
    rows = conn.execute(
        "SELECT id, from_source_table, from_source_id, to_source_table, to_source_id FROM evidence_links"
    ).fetchall()

    for row in rows:
        for side, table, source_id in (
            ("from", row["from_source_table"], row["from_source_id"]),
            ("to", row["to_source_table"], row["to_source_id"]),
        ):
            if table not in KNOWN_EVIDENCE_SOURCE_TABLES:
                issues.append(IntegrityIssue(row["id"], side, table, source_id, "unknown_table"))
                continue
            found = conn.execute(f"SELECT 1 FROM {table} WHERE id = ?", (source_id,)).fetchone()
            if found is None:
                issues.append(IntegrityIssue(row["id"], side, table, source_id, "missing_row"))

    return issues


def check_alert_decisions_integrity(conn: sqlite3.Connection) -> List[AuditTrailIssue]:
    """
    Verify audit trail integrity by checking:
    1. Hash chain continuity (prior_hash links records)
    2. No gaps in sequence (deletion detection)
    3. No orphaned records (prior_hash pointing to deleted row)

    Returns list of issues found; empty list means clean audit trail.
    """
    issues: List[AuditTrailIssue] = []

    # Check if alert_decisions table exists
    check_table = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='alert_decisions'"
    ).fetchone()

    if not check_table:
        return issues  # Table doesn't exist yet, no audit trail to check

    # Get all alert decisions ordered by creation time
    records = conn.execute(
        "SELECT id, created_at, decision_hash, prior_hash FROM alert_decisions ORDER BY created_at ASC"
    ).fetchall()

    if not records:
        return issues  # No records yet

    # First record should have NULL prior_hash (chain start)
    if records[0]["prior_hash"] is not None:
        issues.append(AuditTrailIssue(
            table_name="alert_decisions",
            record_id=records[0]["id"],
            issue_type="chain_break",
            details="First record has non-NULL prior_hash (chain integrity broken)"
        ))

    # Check chain continuity: each record's prior_hash should match previous record's decision_hash
    for i in range(1, len(records)):
        prev_record = records[i - 1]
        curr_record = records[i]

        if curr_record["prior_hash"] != prev_record["decision_hash"]:
            issues.append(AuditTrailIssue(
                table_name="alert_decisions",
                record_id=curr_record["id"],
                issue_type="chain_break",
                details=f"prior_hash doesn't match previous decision_hash (record {prev_record['id']} → {curr_record['id']} broken)"
            ))

    # Check for orphaned prior_hash references (prior_hash pointing to deleted record)
    for record in records:
        if record["prior_hash"] is not None:
            found = conn.execute(
                "SELECT 1 FROM alert_decisions WHERE decision_hash = ?",
                (record["prior_hash"],)
            ).fetchone()
            if found is None:
                issues.append(AuditTrailIssue(
                    table_name="alert_decisions",
                    record_id=record["id"],
                    issue_type="deletion_detected",
                    details=f"prior_hash {record['prior_hash'][:8]}... points to deleted record"
                ))

    return issues


def check_remediation_request_log_integrity(conn: sqlite3.Connection) -> List[AuditTrailIssue]:
    """
    Verify remediation approval log integrity using same hash chain method.
    Returns list of issues found; empty list means clean request log.
    """
    issues: List[AuditTrailIssue] = []

    # Check if remediation_request_log table exists
    check_table = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='remediation_request_log'"
    ).fetchone()

    if not check_table:
        return issues

    # Get all request logs ordered by creation time
    records = conn.execute(
        "SELECT id, created_at, entry_hash, prior_hash FROM remediation_request_log ORDER BY created_at ASC"
    ).fetchall()

    if not records:
        return issues

    # First record should have NULL prior_hash
    if records[0]["prior_hash"] is not None:
        issues.append(AuditTrailIssue(
            table_name="remediation_request_log",
            record_id=records[0]["id"],
            issue_type="chain_break",
            details="First record has non-NULL prior_hash (chain integrity broken)"
        ))

    # Check chain continuity
    for i in range(1, len(records)):
        prev_record = records[i - 1]
        curr_record = records[i]

        if curr_record["prior_hash"] != prev_record["entry_hash"]:
            issues.append(AuditTrailIssue(
                table_name="remediation_request_log",
                record_id=curr_record["id"],
                issue_type="chain_break",
                details=f"prior_hash doesn't match previous entry_hash (record {prev_record['id']} → {curr_record['id']} broken)"
            ))

    # Check for orphaned references
    for record in records:
        if record["prior_hash"] is not None:
            found = conn.execute(
                "SELECT 1 FROM remediation_request_log WHERE entry_hash = ?",
                (record["prior_hash"],)
            ).fetchone()
            if found is None:
                issues.append(AuditTrailIssue(
                    table_name="remediation_request_log",
                    record_id=record["id"],
                    issue_type="deletion_detected",
                    details=f"prior_hash {record['prior_hash'][:8]}... points to deleted record"
                ))

    return issues
