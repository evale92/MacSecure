"""
secure/correlate/chain_scanner.py — Phase 22 Stage 4: orchestrates one
CHAIN correlation pass, the run_id-per-pass / lookback-windowed
counterpart to secure/correlate/scanner.py's correlate() — but for
chain alerts (correlation_chain_alerts). Entirely separate from, and
runs independently of, the existing temporal-clustering pass; nothing
here reads or writes correlation_alerts, and nothing in scanner.py
knows this module exists (see chains.py's own module docstring for why
"add alongside, don't replace" is this phase's approved design).

Candidate starting points are every DISTINCT node that appears on
either side of at least one evidence_links row whose last_seen falls
within the lookback window — an isolated observation with no
evidence_links row at all can never produce more than a trivial 1-node
chain (module_count<=1 -> INSUFFICIENT_EVIDENCE, see chains.py's
_compute_confidence()), so walking it would only waste a table row
without ever surfacing anything reviewable. Because
fingerprint_for_chain() is stable regardless of which member node a
walk started from (Stage 3), scoring the same connected component from
two different starting nodes in the same pass is wasted work, not a
correctness problem — this scanner tracks fingerprints it has already
scored THIS PASS and skips re-walking them, purely to avoid redundant
sqlite reads. persist_chain_score()'s own idempotent-by-fingerprint
write would have caught it anyway even without that guard.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Set

from secure.correlate.chains import ChainScore, fingerprint_for_chain, persist_chain_score, score_chain
from secure.correlate.context import get_boot_time
from secure.evidence.chain import DEFAULT_MAX_HOPS
from secure.evidence.model import ObservationRef
from secure.storage.models.correlate_chains import CorrelationChainAlertRecord

DEFAULT_LOOKBACK_HOURS = 24.0


@dataclass
class ChainCorrelationResult:
    run_id: str
    scanned_at: str
    lookback_hours: float
    candidate_start_count: int  # distinct nodes considered as a walk's starting point
    chains_scored: int          # distinct chains actually walked/scored this pass (post-fingerprint-dedup)
    new_alerts: List[CorrelationChainAlertRecord] = field(default_factory=list)
    # Chains that scored this run but were already on record from an
    # earlier pass over overlapping history — proof the idempotent
    # fingerprint dedup worked, not an error. Mirrors
    # CorrelationResult.already_known_clusters exactly.
    already_known_chains: int = 0


def _candidate_starts(conn: sqlite3.Connection, lookback_hours: float) -> List[ObservationRef]:
    """Every node touched by an evidence_links row recently enough to
    matter. Reads evidence_links directly (not via
    list_evidence_links_for(), which needs a specific node to query
    around) — this is the one place a chain-correlation pass needs to
    ask "which nodes have ANY link at all," a different question from
    anything secure/evidence/ already exposes.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()
    rows = conn.execute(
        "SELECT from_source_table AS t, from_source_id AS i FROM evidence_links WHERE last_seen >= ? "
        "UNION "
        "SELECT to_source_table AS t, to_source_id AS i FROM evidence_links WHERE last_seen >= ?",
        (cutoff, cutoff),
    ).fetchall()
    return [ObservationRef(source_table=row["t"], source_id=row["i"]) for row in rows]


def run_chain_correlation(
    conn: sqlite3.Connection,
    *,
    lookback_hours: float = DEFAULT_LOOKBACK_HOURS,
    max_hops: int = DEFAULT_MAX_HOPS,
) -> ChainCorrelationResult:
    """Run one chain-correlation pass: find every candidate starting
    node touched by recent evidence_links activity, walk+score+persist
    the chain reachable from each one, skipping any fingerprint already
    scored earlier in this SAME pass (a connected component with N
    member nodes would otherwise be walked N times). Safe to re-run
    repeatedly over overlapping history — persist_chain_score()'s own
    idempotent-by-fingerprint write handles cross-run repeats exactly
    like add_correlation_alert() already does for temporal clusters.
    """
    run_id = uuid.uuid4().hex[:12]
    scanned_at = datetime.now(timezone.utc).isoformat()
    boot_time = get_boot_time()

    starts = _candidate_starts(conn, lookback_hours)

    seen_fingerprints: Set[str] = set()
    new_alerts: List[CorrelationChainAlertRecord] = []
    already_known = 0
    chains_scored = 0

    for start_ref in starts:
        score: ChainScore = score_chain(
            conn, start_ref, max_hops=max_hops, boot_time=boot_time, boot_time_resolved=True
        )
        fingerprint = fingerprint_for_chain(score.chain)
        if fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(fingerprint)
        chains_scored += 1

        record, was_new = persist_chain_score(conn, run_id, score)
        if was_new:
            new_alerts.append(record)
        else:
            already_known += 1

    return ChainCorrelationResult(
        run_id=run_id,
        scanned_at=scanned_at,
        lookback_hours=lookback_hours,
        candidate_start_count=len(starts),
        chains_scored=chains_scored,
        new_alerts=new_alerts,
        already_known_chains=already_known,
    )
