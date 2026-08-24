"""
secure/evidence/record.py — Phase 21 Stage 2 (corrected in Stage 3c):
the one I/O entry point in secure/evidence/. Idempotent
check-then-insert-or-touch persistence of one EvidenceLink, the same
"check via the dedup index before inserting, never rely on a raw
INSERT failing" discipline secure/baseline/engine.py's
maybe_record_anomaly_event() already established for anomaly_events.

CORRECTION (see secure/storage/database.py's evidence_links schema
comment for the full story): idempotence is now keyed on each ref's
LOGICAL identity (secure/evidence/fingerprint.py's
logical_ref_identity()), not the raw source_id — because a source like
osquery, with no ingestion cursor, writes a genuinely NEW
integration_observations row every scan for the same unchanged real-
world fact, and keying idempotence off that ever-changing row id meant
a fresh evidence_links row was written on every single scan for one
ongoing, unchanged relationship. Zeek and Suricata don't pass a
logical_key on their refs, so their fingerprint falls back to
source_id exactly as before — their already-idempotent behavior
(a rescan produces zero new observations for an already-classified
match, so record_link() simply never re-fires for them) is completely
unchanged by this correction.

Deliberately the ONLY function in this package that touches the
database — model.py and fingerprint.py stay pure, matching every other
"one file does the I/O" split in this codebase.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Tuple

from secure.evidence.fingerprint import logical_ref_identity
from secure.evidence.model import EvidenceLink
from secure.storage.models import (
    EvidenceLinkRecord,
    add_evidence_link,
    add_evidence_link_observation,
    find_evidence_link_by_fingerprint,
    touch_evidence_link,
)


def record_link(conn: sqlite3.Connection, link: EvidenceLink) -> "Tuple[EvidenceLinkRecord, bool]":
    """Persist `link` if no logically-identical relationship
    (from_fingerprint, to_fingerprint, relationship) already exists;
    otherwise TOUCH the existing row (advance last_seen, increment
    times_seen, move from_source_id to this confirmation's own row id)
    rather than inserting a second one. Either way, every call also
    appends one evidence_link_observations row — exact provenance for
    THIS confirmation specifically is never lost, even when the
    relationship itself isn't new (see evidence.py's own CORRECTION
    docstring).

    Returns (record, created) so a caller can tell "this is a brand-new
    logical relationship" from "this relationship was already known and
    has now been reconfirmed" without a second query — the same
    boolean-return-on-idempotent-write shape this codebase already uses
    elsewhere (e.g. secure/baseline/history.py's own recorders).

    Never overwrites an existing link's own first-classification fields
    (detail, first_source_id, first_seen/created_at) — the same
    "append-only, never silently revise history" discipline every other
    table in this app already follows.
    """
    observed_at = datetime.now(timezone.utc).isoformat()
    from_fp = logical_ref_identity(
        link.from_ref.source_table, link.from_ref.source_id, link.from_ref.logical_key
    )
    to_fp = logical_ref_identity(
        link.to_ref.source_table, link.to_ref.source_id, link.to_ref.logical_key
    )

    existing = find_evidence_link_by_fingerprint(conn, from_fp, to_fp, link.relationship)
    if existing is not None:
        touch_evidence_link(conn, existing.id, latest_source_id=link.from_ref.source_id, observed_at=observed_at)
        add_evidence_link_observation(
            conn,
            evidence_link_id=existing.id,
            from_source_table=link.from_ref.source_table,
            from_source_id=link.from_ref.source_id,
            observed_at=observed_at,
        )
        refreshed = find_evidence_link_by_fingerprint(conn, from_fp, to_fp, link.relationship)
        assert refreshed is not None
        return refreshed, False

    new_id = add_evidence_link(
        conn,
        from_source_table=link.from_ref.source_table,
        from_source_id=link.from_ref.source_id,
        from_fingerprint=from_fp,
        to_source_table=link.to_ref.source_table,
        to_source_id=link.to_ref.source_id,
        to_fingerprint=to_fp,
        relationship=link.relationship,
        match_basis=link.match_basis,
        detail=link.detail,
        created_by=link.created_by,
        time_delta_seconds=link.time_delta_seconds,
        observed_at=observed_at,
    )
    add_evidence_link_observation(
        conn,
        evidence_link_id=new_id,
        from_source_table=link.from_ref.source_table,
        from_source_id=link.from_ref.source_id,
        observed_at=observed_at,
    )
    created = find_evidence_link_by_fingerprint(conn, from_fp, to_fp, link.relationship)
    assert created is not None and created.id == new_id  # the row we just inserted must be findable
    return created, True
