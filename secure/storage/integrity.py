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
