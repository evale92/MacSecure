"""
secure/evidence/chain.py — Phase 22 Stage 2: the chain-walking read
layer over evidence_links. secure/evidence/record.py is the only
WRITE path into evidence_links; this is the first READ path beyond
single-hop lookups (`list_evidence_links_for()`), and the first place
in this codebase that treats evidence_links as a graph to traverse
rather than a table to query by exact row.

Deliberately generic — nothing here knows what a "chain" MEANS
security-wise (that's secure/correlate/chains.py, Stage 3), what a
module is, or how to score anything. This module answers exactly one
question: "starting from this row, what does evidence_links say is
connected to it, and in what real-world order did those things
happen?" That question is useful to more than just correlation scoring
— Phase 23's own investigation/pivot model is expected to reuse this
same walk, which is why it lives in secure/evidence/ (the shared,
integration-neutral package) rather than inside secure/correlate/.

No traversal helper existed before this — model.py's own docstring
named "event family... computed on read as the transitive closure over
evidence_links rows" as an intended future capability; this is that
capability, arriving now that Phase 22 needs it.
"""

from __future__ import annotations

import sqlite3
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from secure.evidence.model import ObservationRef
from secure.storage.models import EvidenceLinkRecord, list_evidence_links_for

DEFAULT_MAX_HOPS = 6

# Which column on each table holds a real-world "when did this happen"
# timestamp — used to order a walked chain causally rather than trusting
# each evidence_links row's own from/to direction blindly (see
# docs/EVIDENCE.md's Phase 21 "direction is a convention, not an
# enforced invariant" finding). Deliberately a plain dict, not a schema
# introspection — every table here is one this app already writes,
# and a table missing from this map just means its nodes resolve with
# timestamp=None (handled gracefully, never an error) rather than the
# walk failing.
_TIMESTAMP_COLUMN_BY_TABLE: Dict[str, str] = {
    "connection_events": "created_at",
    "listening_events": "created_at",
    "listening_services": "last_seen",
    "remote_endpoints": "last_seen",
    "process_entries": "last_seen",
    "persistence_observations": "created_at",
    "persistence_entries": "last_seen",
    "persistence_alerts": "created_at",
    "file_change_events": "created_at",
    "file_integrity_alerts": "created_at",
    "integration_observations": "collected_at",
    "integration_alerts": "created_at",
    "anomaly_events": "created_at",
    "correlation_alerts": "created_at",
    "arp_alerts": "created_at",
    "wifi_alerts": "created_at",
    "bluetooth_alerts": "created_at",
    "ble_alerts": "created_at",
    "threat_intel_lookups": "queried_at",
    "forensic_collections": "created_at",
    "forensic_evidence_items": "created_at",
}


@dataclass(frozen=True)
class ChainNode:
    """One row visited during a walk — exact provenance
    (source_table, source_id), same discipline as ObservationRef,
    plus the real-world timestamp resolved from that row's own table
    (None when the table isn't in `_TIMESTAMP_COLUMN_BY_TABLE` or the
    row no longer exists — a walk never raises just because one hop's
    timestamp couldn't be resolved).
    """

    source_table: str
    source_id: int
    timestamp: Optional[datetime]


@dataclass(frozen=True)
class ChainEdge:
    """One evidence_links row encountered during the walk, together
    with the two ChainNodes it connects — a thin wrapper so a caller
    never has to re-derive which node is which side of `link`.
    """

    link: EvidenceLinkRecord
    from_node: ChainNode
    to_node: ChainNode


@dataclass
class Chain:
    """The result of one walk: every node reached (starting node
    included, always first) and every edge traversed to reach them.
    Deliberately does NOT compute anything about the nodes/edges
    (module diversity, concentration, severity, ...) — that
    interpretation belongs to whichever caller asked for the walk
    (secure/correlate/chains.py for Stage 3 scoring; a future
    investigation view for Phase 23), not to the walk itself.
    """

    nodes: List[ChainNode] = field(default_factory=list)
    edges: List[ChainEdge] = field(default_factory=list)

    @property
    def hop_count(self) -> int:
        return len(self.edges)


def _resolve_timestamp(conn: sqlite3.Connection, source_table: str, source_id: int) -> Optional[datetime]:
    column = _TIMESTAMP_COLUMN_BY_TABLE.get(source_table)
    if column is None:
        return None
    try:
        row = conn.execute(
            f"SELECT {column} FROM {source_table} WHERE id = ?", (source_id,)
        ).fetchone()
    except sqlite3.OperationalError:
        # An unrecognized/renamed table shape — same "never let a
        # resolution failure abort the walk" discipline as everything
        # else here.
        return None
    if row is None or row[column] is None:
        return None
    try:
        return datetime.fromisoformat(row[column])
    except (TypeError, ValueError):
        return None


def walk_chain(
    conn: sqlite3.Connection,
    start_ref: ObservationRef,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
    max_links_per_node: int = 200,
) -> Chain:
    """Breadth-first walk outward from `start_ref` over evidence_links,
    up to `max_hops` edges away. Cycle-guarded (a row is only ever
    visited once, however many paths reach it) and hop-capped (a
    pathological, densely-linked graph can't make this walk unbounded).

    Uses only the existing `list_evidence_links_for()` — no new storage
    function was needed; that single-hop "everything touching this
    exact row" lookup is sufficient to build outward from repeatedly.
    """
    start_node = ChainNode(
        source_table=start_ref.source_table,
        source_id=start_ref.source_id,
        timestamp=_resolve_timestamp(conn, start_ref.source_table, start_ref.source_id),
    )

    nodes: List[ChainNode] = [start_node]
    edges: List[ChainEdge] = []
    visited: Dict[Tuple[str, int], ChainNode] = {
        (start_node.source_table, start_node.source_id): start_node
    }
    seen_link_ids: set = set()

    queue: deque = deque([(start_node, 0)])
    while queue:
        current, hops = queue.popleft()
        if hops >= max_hops:
            continue

        links = list_evidence_links_for(
            conn, current.source_table, current.source_id, limit=max_links_per_node
        )
        for link in links:
            if link.id in seen_link_ids:
                continue
            seen_link_ids.add(link.id)

            is_from_side = (
                link.from_source_table == current.source_table and link.from_source_id == current.source_id
            )
            other_table = link.to_source_table if is_from_side else link.from_source_table
            other_id = link.to_source_id if is_from_side else link.from_source_id
            other_key = (other_table, other_id)

            other_node = visited.get(other_key)
            newly_discovered = other_node is None
            if newly_discovered:
                other_node = ChainNode(
                    source_table=other_table,
                    source_id=other_id,
                    timestamp=_resolve_timestamp(conn, other_table, other_id),
                )
                visited[other_key] = other_node
                nodes.append(other_node)

            from_node = current if is_from_side else other_node
            to_node = other_node if is_from_side else current
            edges.append(ChainEdge(link=link, from_node=from_node, to_node=to_node))

            if newly_discovered:
                queue.append((other_node, hops + 1))

    return Chain(nodes=nodes, edges=edges)
