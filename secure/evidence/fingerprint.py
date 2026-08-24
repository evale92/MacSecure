"""
secure/evidence/fingerprint.py — pure, reusable identity+timing
matching and stable-hashing helpers. No I/O, no database, no
integration-specific knowledge.

This module GENERALIZES a pattern that already exists, independently
implemented twice, in secure/integrations/suricata/correlate.py's
find_process_correlation() and secure/integrations/zeek/dedup.py's
classify_conn_dedup(): try a small set of "candidate sides" (an alert
or log record doesn't itself say which endpoint is "this Mac", so both
sides are tried), require an EXACT identity match (address+port+proto)
AND a timestamp within a bounded window, and keep the closest-in-time
match.

Deliberate scope decision for Phase 21 Stage 1: this toolkit is built
and tested standalone here, but secure/integrations/suricata/
correlate.py and secure/integrations/zeek/dedup.py are NOT refactored
to call it. Both already have full test coverage against their exact
current behavior; forcing them onto a shared helper would be an
internal refactor with no user-visible benefit and real regression
risk, for a phase whose own approval was scoped to "additive, no
output changes." This toolkit exists so a FUTURE third matcher (a
future integration, or a future Stage 4+ effort) can reuse it directly
instead of writing a fourth near-identical loop — see stable_fingerprint()
below for the same reasoning applied to
secure/correlate/analysis.py's own fingerprint_for_cluster().
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class CandidateSide:
    """One endpoint identity worth trying as a match key — e.g. an
    alert's src side and dest side, since the record itself doesn't say
    which one is "this Mac" (see correlate.py's and dedup.py's own
    docstrings on exactly this ambiguity).
    """

    label: str  # e.g. "src" / "dest" / "orig" / "resp"
    addr: str
    port: int


@dataclass(frozen=True)
class MatchTarget:
    """One existing row worth checking a candidate side against —
    already-normalized identity/timing fields pulled from whatever
    table is being searched (connection_events, integration_observations,
    ...). `id` is that row's own real primary key, never a deduplicated
    identity-table id — same discipline as ObservationRef in model.py.
    """

    id: int
    proto: str
    addr: str
    port: int
    timestamp: datetime


@dataclass(frozen=True)
class MatchOutcome:
    target_id: int
    matched_side: str
    time_delta_seconds: float


def find_best_identity_timing_match(
    sides: Sequence[CandidateSide],
    proto: str,
    timestamp: datetime,
    targets: Iterable[MatchTarget],
    window_seconds: float,
) -> Optional[MatchOutcome]:
    """The closest-in-time target whose (addr, port) exactly matches
    ANY of `sides`, whose `proto` matches (case-sensitivity is the
    caller's responsibility — pass already-normalized values), and
    whose timestamp is within `window_seconds` of `timestamp`. Returns
    None (never raises, never guesses) when no candidate satisfies both
    constraints — matching the "no match is a genuine, useful
    classification, not an error" discipline
    secure/integrations/zeek/dedup.py's classify_conn_dedup() already
    documents.

    Tries every side against every target rather than stopping at the
    first match, so the genuinely CLOSEST-in-time candidate is always
    returned even when multiple targets/sides technically qualify —
    same behavior as both existing hand-written implementations this
    generalizes.
    """
    best: Optional[MatchOutcome] = None
    best_delta: Optional[float] = None

    for target in targets:
        if target.proto != proto:
            continue
        delta = abs((target.timestamp - timestamp).total_seconds())
        if delta > window_seconds:
            continue
        for side in sides:
            if target.addr != side.addr or target.port != side.port:
                continue
            if best is None or delta < best_delta:
                best = MatchOutcome(target_id=target.id, matched_side=side.label, time_delta_seconds=delta)
                best_delta = delta

    return best


def stable_fingerprint(parts: Iterable[str]) -> str:
    """A stable, order-independent sha256 hash of a set of string
    parts — generalizes secure/correlate/analysis.py's own
    fingerprint_for_cluster() (which hashes a cluster's own
    "source_table:source_id" member strings) into a standalone,
    reusable helper. Sorted before hashing so the same underlying set
    of parts always fingerprints identically regardless of collection/
    iteration order.
    """
    return hashlib.sha256("|".join(sorted(parts)).encode("utf-8")).hexdigest()


def logical_ref_identity(source_table: str, source_id: int, logical_key: Optional[str] = None) -> str:
    """The stable identity string evidence_links' own idempotence keys
    off (see database.py's evidence_links schema comment for the full
    "CORRECTION" story). NOT the same thing as exact provenance —
    provenance is still source_id, always; this is only about deciding
    whether two ObservationRefs describe the SAME logical relationship.

    When `logical_key` is given, identity is (source_table, logical_key)
    — independent of the specific row id, for sources that write a
    genuinely NEW row every scan for the same unchanged real-world fact
    (osquery has no ingestion cursor; see
    secure/integrations/osquery/scanner.py). When `logical_key` is
    omitted, the row's own id IS the logical identity — true for
    sources whose row already represents one distinct real-world event
    that will never recur identically on a rescan (Zeek/Suricata's own
    cursor mechanisms), so falling back to `source_id` changes nothing
    about their existing, already-idempotent behavior.

    Deliberately a plain, readable "table:key" string rather than a
    sha256 hash (unlike stable_fingerprint() above) — there's no
    variable-length unordered set to normalize here, just one
    (table, key) pair, and keeping it human-readable makes a stored
    evidence_links row directly inspectable (`sqlite3 ... "select
    from_fingerprint from evidence_links"`) without a lookup table.
    """
    key = logical_key if logical_key else str(source_id)
    return f"{source_table}:{key}"


def observation_part(source_table: str, source_id: int) -> str:
    """The canonical "source_table:source_id" string form used both by
    stable_fingerprint() callers here and by
    correlate/analysis.py's existing fingerprint_for_cluster() — kept
    as one small shared helper so the exact same string shape is used
    everywhere a (source_table, source_id) pair needs to become a
    fingerprint component.
    """
    return f"{source_table}:{source_id}"
