"""
evidence.py — Phase 21 Unified Evidence, Lineage, and Deduplication:
the `evidence_links` and `evidence_link_observations` tables — see
secure/evidence/.

This module has no idea what "relationship" values mean, what
"identity+timing" is, which integration produced a link, or what a
"logical fingerprint" represents beyond an opaque string — it only
knows how to store and retrieve the already-computed fields
secure/evidence/record.py hands it, the same "this module doesn't
interpret, it only persists" separation every other domain file in
this package keeps (see storage/models/threatintel.py's own docstring
for the identical discipline applied to Phase 20).

CORRECTION (still within Phase 21, before this table was ever reported
finished — see database.py's evidence_links schema comment for the
full story): `evidence_links` now represents one LOGICAL relationship,
not one scan's confirmation of it. A relationship already on file gets
touched (last_seen/times_seen/from_source_id updated) rather than
duplicated; `evidence_link_observations` is the new append-only table
that keeps exact per-confirmation provenance regardless of how many
times the same relationship gets re-observed.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional


@dataclass
class EvidenceLinkRecord:
    id: int
    created_at: str
    from_source_table: str
    from_source_id: int          # the MOST RECENT confirming observation's row id
    first_source_id: int         # the FIRST confirming observation's row id — never overwritten
    from_fingerprint: str
    to_source_table: str
    to_source_id: int
    to_fingerprint: str
    relationship: str
    match_basis: str
    time_delta_seconds: "Optional[float]"
    detail: str
    created_by: str
    first_seen: str
    last_seen: str
    times_seen: int


@dataclass
class EvidenceLinkObservationRecord:
    id: int
    evidence_link_id: int
    from_source_table: str
    from_source_id: int
    observed_at: str


def _row_to_link(row: sqlite3.Row) -> EvidenceLinkRecord:
    return EvidenceLinkRecord(**dict(row))


def _row_to_link_observation(row: sqlite3.Row) -> EvidenceLinkObservationRecord:
    return EvidenceLinkObservationRecord(**dict(row))


def add_evidence_link(
    conn: sqlite3.Connection,
    from_source_table: str,
    from_source_id: int,
    from_fingerprint: str,
    to_source_table: str,
    to_source_id: int,
    to_fingerprint: str,
    relationship: str,
    match_basis: str,
    detail: str,
    created_by: str,
    time_delta_seconds: "Optional[float]" = None,
    observed_at: "Optional[str]" = None,
) -> int:
    """Insert one brand-new LOGICAL evidence_links row and return its
    new id. Always an INSERT — idempotence (never creating a second
    logical link for a (from_fingerprint, to_fingerprint, relationship)
    that already exists) is the CALLER's responsibility (see
    secure/evidence/record.py's record_link(), which checks via
    find_evidence_link_by_fingerprint() before ever calling this — the
    same check-then-insert discipline
    secure/baseline/engine.py's maybe_record_anomaly_event() already
    uses for its own dedup index). This function itself will raise
    sqlite3.IntegrityError if the same (from_fingerprint, to_fingerprint,
    relationship) tuple is inserted twice, since evidence_links' own
    unique index is a real backstop, not just documentation.

    `first_source_id` is set to `from_source_id` (this IS the first
    confirmation); `first_seen`/`last_seen`/`created_at` are all this
    same moment; `times_seen` starts at 1.
    """
    now = observed_at or datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO evidence_links "
        "(created_at, from_source_table, from_source_id, first_source_id, from_fingerprint, "
        "to_source_table, to_source_id, to_fingerprint, relationship, match_basis, "
        "time_delta_seconds, detail, created_by, first_seen, last_seen, times_seen) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
        (
            now, from_source_table, from_source_id, from_source_id, from_fingerprint,
            to_source_table, to_source_id, to_fingerprint, relationship, match_basis,
            time_delta_seconds, detail, created_by, now, now,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def touch_evidence_link(
    conn: sqlite3.Connection,
    link_id: int,
    latest_source_id: int,
    observed_at: "Optional[str]" = None,
) -> None:
    """Record a REPEAT confirmation of an already-known logical
    relationship: advance `last_seen`, increment `times_seen`, and move
    `from_source_id` to this confirmation's own row id (it now means
    "most recent", not "only" — see EvidenceLinkRecord's own docstring).
    `first_source_id`/`first_seen`/`created_at`/`detail` are
    deliberately NOT touched here — the first classification's own
    provenance is preserved exactly as it was first observed, same
    append-only-history discipline every other table in this app
    follows for its own "first observed" fields.
    """
    now = observed_at or datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE evidence_links SET last_seen = ?, times_seen = times_seen + 1, "
        "from_source_id = ? WHERE id = ?",
        (now, latest_source_id, link_id),
    )
    conn.commit()


def add_evidence_link_observation(
    conn: sqlite3.Connection,
    evidence_link_id: int,
    from_source_table: str,
    from_source_id: int,
    observed_at: "Optional[str]" = None,
) -> int:
    """Append one exact-provenance row: "this specific observation
    confirmed this specific logical relationship at this moment" — the
    per-scan detail evidence_links itself no longer carries once a
    relationship is already known (see this module's own CORRECTION
    docstring above). Always an INSERT; there is no dedup concept here
    at all — every call is, by definition, a genuinely new confirmation
    event, whether or not the logical relationship itself was new.
    """
    now = observed_at or datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO evidence_link_observations "
        "(evidence_link_id, from_source_table, from_source_id, observed_at) "
        "VALUES (?, ?, ?, ?)",
        (evidence_link_id, from_source_table, from_source_id, now),
    )
    conn.commit()
    return cursor.lastrowid


def find_evidence_link_by_fingerprint(
    conn: sqlite3.Connection,
    from_fingerprint: str,
    to_fingerprint: str,
    relationship: str,
) -> "Optional[EvidenceLinkRecord]":
    """Exact-match lookup on evidence_links' own unique index — the
    idempotence check secure/evidence/record.py's record_link() runs
    before ever inserting. Keyed on LOGICAL identity (fingerprints), not
    raw source ids — see database.py's evidence_links schema comment
    for why that distinction is the entire point of this correction.
    """
    row = conn.execute(
        "SELECT * FROM evidence_links WHERE from_fingerprint = ? AND to_fingerprint = ? "
        "AND relationship = ?",
        (from_fingerprint, to_fingerprint, relationship),
    ).fetchone()
    return _row_to_link(row) if row else None


def find_evidence_link_by_id(conn: sqlite3.Connection, link_id: int) -> "Optional[EvidenceLinkRecord]":
    row = conn.execute("SELECT * FROM evidence_links WHERE id = ?", (link_id,)).fetchone()
    return _row_to_link(row) if row else None


def list_evidence_links_for(
    conn: sqlite3.Connection,
    source_table: str,
    source_id: int,
    *,
    limit: int = 200,
) -> "list[EvidenceLinkRecord]":
    """Every link touching one row's EXACT raw id, from EITHER side (a
    row can be the "from" side of one link and the "to" side of
    another). Most recent first.

    Note the same caveat this correction introduces everywhere else:
    for a repeatedly-observed source (osquery), `from_source_id` here
    means "the most recent confirming observation" — looking this up by
    an OLDER, since-superseded observation id will not find the link.
    Every native ("to" side) table this app has today is upserted in
    place with a stable id, so lookups from that side are unaffected;
    only a lookup from an ephemeral, ever-changing "from" side has this
    limitation, and no caller in this codebase does that today.
    """
    rows = conn.execute(
        "SELECT * FROM evidence_links WHERE "
        "(from_source_table = ? AND from_source_id = ?) OR (to_source_table = ? AND to_source_id = ?) "
        "ORDER BY id DESC LIMIT ?",
        (source_table, source_id, source_table, source_id, limit),
    ).fetchall()
    return [_row_to_link(row) for row in rows]


def list_evidence_link_observations(
    conn: sqlite3.Connection,
    evidence_link_id: int,
    *,
    limit: int = 500,
) -> "list[EvidenceLinkObservationRecord]":
    """Every individual confirmation event behind one logical
    evidence_links row, most recent first — the exact per-scan history
    that `times_seen`/`last_seen` summarize without exposing.
    """
    rows = conn.execute(
        "SELECT * FROM evidence_link_observations WHERE evidence_link_id = ? "
        "ORDER BY id DESC LIMIT ?",
        (evidence_link_id, limit),
    ).fetchall()
    return [_row_to_link_observation(row) for row in rows]
