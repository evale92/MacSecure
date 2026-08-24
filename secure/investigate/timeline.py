"""
secure/investigate/timeline.py — Phase 23 Stage 3: investigation
timeline + related-evidence view.

Composed entirely from existing read layers — no new detection logic,
no new SQL, no new storage. Two entry points:

    build_timeline(conn, entity) -> Timeline
        Every observation on record that is either this entity itself
        (via resolve_entity()'s anchors) or evidence-linked to it (via
        secure/evidence/chain.py's walk_chain(), reused unchanged from
        Phase 22 — exactly the reuse that module's own docstring named
        as the reason it lives in secure/evidence/ rather than
        secure/correlate/), ordered chronologically. This is the "what
        happened, in what order" view.

    related_evidence(conn, entity) -> RelatedEvidence
        The same underlying walk, but organized by hop-distance from
        the entity rather than by time — "what's connected, and how
        directly" — for progressive disclosure (closest evidence first,
        deeper context available on demand rather than one flat dump).

Both walk from EVERY anchor resolve_entity() returns (an entity can
have more than one anchor — e.g. a wifi SSID with multiple BSSIDs), and
dedupe by (source_table, source_id) so evidence reachable from more
than one anchor is never shown twice. Neither function computes
severity, confidence, or "what does this mean" — that stays entirely
with secure/explain/dispatch.py's explain(), which a caller (the
Stage 5 view/CLI layer) applies per-observation on top of the refs
returned here. This module only answers "what's here and when/how far
away," never "how bad is it."
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from secure.evidence.chain import DEFAULT_MAX_HOPS, ChainEdge, ChainNode, walk_chain
from secure.evidence.model import ObservationRef
from secure.investigate.entity import EntityRef
from secure.investigate.resolve import resolve_entity

_NodeKey = Tuple[str, int]


@dataclass(frozen=True)
class TimelineEvent:
    """One observation, positioned in time. `is_anchor` marks whether
    this row IS the investigated entity itself (vs. evidence-linked
    context reached by walking outward from it) — the timeline view can
    use this to visually distinguish "this" from "what's connected to
    this" without re-deriving it. `hops_from_entity` is 0 for anchors
    and the shortest evidence_links distance from any anchor otherwise.
    """

    source_table: str
    source_id: int
    timestamp: Optional[datetime]
    is_anchor: bool
    hops_from_entity: int

    def as_observation_ref(self) -> ObservationRef:
        return ObservationRef(source_table=self.source_table, source_id=self.source_id)


@dataclass
class Timeline:
    entity: EntityRef
    exists: bool
    events: List[TimelineEvent] = field(default_factory=list)


@dataclass(frozen=True)
class RelatedEvidenceGroup:
    """Every observation reached at exactly `hops` evidence_links edges
    away from the entity's own anchors (the entity's own anchors
    themselves are never included — see related_evidence()'s
    docstring)."""

    hops: int
    observations: List[ObservationRef] = field(default_factory=list)


@dataclass
class RelatedEvidence:
    entity: EntityRef
    exists: bool
    groups: List[RelatedEvidenceGroup] = field(default_factory=list)
    edges: List[ChainEdge] = field(default_factory=list)


def _hops_from_start(chain) -> Dict[_NodeKey, int]:
    """Recover each node's hop-distance from one chain's own starting
    node using its edge list — walk_chain() discovers nodes in BFS
    order but doesn't expose hop distance on ChainNode itself, so this
    reconstructs it from the edges alone (also produced in BFS order,
    so a single forward pass is sufficient — no node's distance is
    resolved before the edge that reaches it has been seen).
    """
    if not chain.nodes:
        return {}
    start = chain.nodes[0]
    hops: Dict[_NodeKey, int] = {(start.source_table, start.source_id): 0}
    for edge in chain.edges:
        from_key = (edge.from_node.source_table, edge.from_node.source_id)
        to_key = (edge.to_node.source_table, edge.to_node.source_id)
        if from_key in hops and to_key not in hops:
            hops[to_key] = hops[from_key] + 1
        elif to_key in hops and from_key not in hops:
            hops[from_key] = hops[to_key] + 1
    return hops


def _walk_all_anchors(
    conn: sqlite3.Connection,
    anchors: List[ObservationRef],
    *,
    max_hops: int,
) -> Tuple[Dict[_NodeKey, ChainNode], Dict[_NodeKey, int], List[ChainEdge]]:
    """Walk outward from every anchor, merging results: the deduped
    node map, each node's minimum hop-distance from ANY anchor (an
    entity's own anchors always sit at hop 0), and the deduped edge
    list (dedup keyed by the underlying evidence_links row id, since
    the same edge can be re-discovered walking from a second anchor).
    """
    nodes: Dict[_NodeKey, ChainNode] = {}
    hops_by_key: Dict[_NodeKey, int] = {(a.source_table, a.source_id): 0 for a in anchors}
    edges: Dict[int, ChainEdge] = {}

    for anchor in anchors:
        chain = walk_chain(conn, anchor, max_hops=max_hops)
        node_hops = _hops_from_start(chain)
        for node in chain.nodes:
            key = (node.source_table, node.source_id)
            nodes[key] = node
            this_hop = node_hops.get(key, 0)
            if key not in hops_by_key or this_hop < hops_by_key[key]:
                hops_by_key[key] = this_hop
        for edge in chain.edges:
            edges[edge.link.id] = edge

    return nodes, hops_by_key, list(edges.values())


def build_timeline(
    conn: sqlite3.Connection,
    entity: EntityRef,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
) -> Timeline:
    """Chronological view: the entity's own anchor row(s) plus every
    row evidence_links connects to them, oldest first. Rows with no
    resolvable timestamp (see chain.py's own
    `_TIMESTAMP_COLUMN_BY_TABLE` note — not every table is in that map,
    and a row can vanish between linking and viewing) sort last rather
    than breaking a mixed-timestamp sort or being silently dropped.
    """
    resolution = resolve_entity(conn, entity)
    if not resolution.exists:
        return Timeline(entity=entity, exists=False)

    anchor_keys = {(a.source_table, a.source_id) for a in resolution.anchors}
    nodes, hops_by_key, _edges = _walk_all_anchors(conn, resolution.anchors, max_hops=max_hops)

    events = [
        TimelineEvent(
            source_table=node.source_table,
            source_id=node.source_id,
            timestamp=node.timestamp,
            is_anchor=key in anchor_keys,
            hops_from_entity=hops_by_key.get(key, 0),
        )
        for key, node in nodes.items()
    ]
    events.sort(key=lambda e: (e.timestamp is None, e.timestamp, e.source_table, e.source_id))
    return Timeline(entity=entity, exists=True, events=events)


def related_evidence(
    conn: sqlite3.Connection,
    entity: EntityRef,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
) -> RelatedEvidence:
    """Progressive-disclosure view: evidence connected to the entity,
    grouped by how many evidence_links hops away it is (closest first).
    The entity's own anchors are deliberately excluded from every group
    here — resolve_entity()'s `anchors` field is already the place an
    analyst finds "what IS this entity"; this function only answers
    "what else is connected to it."
    """
    resolution = resolve_entity(conn, entity)
    if not resolution.exists:
        return RelatedEvidence(entity=entity, exists=False)

    anchor_keys = {(a.source_table, a.source_id) for a in resolution.anchors}
    nodes, hops_by_key, edges = _walk_all_anchors(conn, resolution.anchors, max_hops=max_hops)

    by_hop: Dict[int, List[ObservationRef]] = {}
    for key, node in nodes.items():
        if key in anchor_keys:
            continue
        hop = hops_by_key.get(key, 0)
        by_hop.setdefault(hop, []).append(
            ObservationRef(source_table=node.source_table, source_id=node.source_id)
        )

    groups = [RelatedEvidenceGroup(hops=hop, observations=refs) for hop, refs in sorted(by_hop.items())]
    return RelatedEvidence(entity=entity, exists=True, groups=groups, edges=edges)
