"""
secure/correlate/chains.py — Phase 22 Stage 3: provenance-aware
behavioral correlation. Consumes secure/evidence/chain.py's
walk_chain() output and scores it deterministically — additive
components with named caps, never multipliers, the same discipline
secure/correlate/analysis.py and secure/baseline/scoring.py already
established (see PROJECT_NOTES.md's Phase 22 research note on why: a
cap, never a multiplier, was already the corrected design for
baseline's own maturity discount before this phase existed).

This module is entirely NEW and additive: secure/correlate/analysis.py,
signals.py, and the existing temporal-clustering correlation_alerts
table are completely untouched by it. A "chain alert" is a SEPARATE,
parallel kind of correlation finding (correlation_chain_alerts, its own
table) — not a replacement. Temporal proximity remains available as
evidence (`time_delta_seconds` on individual evidence_links rows, and a
chain's own earliest/latest node timestamps), but it is no longer the
PRIMARY definition of relatedness the way cluster_signals()'s window
chaining is for the existing model — that role now belongs to actual
evidence_links relationships walked via secure/evidence/chain.py.

The core problem this solves, in one sentence: raw observation count is
not corroboration. Three tools observing the SAME underlying event (a
Suricata alert, a Zeek conn.log entry, and osquery's own crosscheck, all
pointing at one connection) must not outscore two tools observing TWO
GENUINELY DIFFERENT events. Phase 21's evidence_links relationship
vocabulary is what tells the difference apart:

    - duplicate_observation / same_event_confirmation links mean "these
      rows are the SAME fact, observed twice (or more)" — before
      anything is scored, every node reachable through only these
      relationship types is collapsed into one CONFIRMATION GROUP
      (see build_confirmation_groups() below). A confirmation group is
      the unit corroboration counting actually operates on, never a
      raw node.
    - derived_evidence links mean "this fact follows FROM that fact" —
      they're what makes something a genuine multi-step CHAIN (file
      created -> YARA finding -> process execution -> persistence ->
      unusual destination -> network IDS finding), as opposed to just
      one well-corroborated single fact restated by several sensors.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from secure.correlate.analysis import (
    CRITICAL,
    HIGH,
    INFORMATIONAL,
    LOW,
    MEDIUM_SEVERITY,
    severity_for_score,
)
from secure.correlate.context import DEFAULT_BOOT_PROXIMITY_MINUTES, get_boot_time, is_recent_boot
from secure.evidence.chain import Chain, ChainEdge, ChainNode, DEFAULT_MAX_HOPS, walk_chain
from secure.evidence.fingerprint import observation_part, stable_fingerprint
from secure.evidence.model import (
    ObservationRef,
    RELATIONSHIP_DERIVED_EVIDENCE,
    RELATIONSHIP_DUPLICATE_OBSERVATION,
    RELATIONSHIP_SAME_EVENT_CONFIRMATION,
)
from secure.explain.vocab import CONFIRMED, INSUFFICIENT_EVIDENCE, LIKELY, UNCERTAIN
from secure.storage.models import add_correlation_chain_alert
from secure.storage.models.correlate_chains import CorrelationChainAlertRecord

_CONFIRMATION_RELATIONSHIPS = (RELATIONSHIP_DUPLICATE_OBSERVATION, RELATIONSHIP_SAME_EVENT_CONFIRMATION)

# table -> coarse module name, the SAME vocabulary secure/correlate/
# signals.py already uses (see its own module docstring) — reused, not
# reinvented, so a chain's module diversity means the same thing a
# temporal cluster's module diversity already means elsewhere in this
# app. Deliberately not exhaustive of every table in the schema — only
# tables that can actually appear as an evidence_links from/to side
# today (see docs/EVIDENCE.md's Phase 22 section for the exact list);
# anything unrecognized falls back to the table name itself as its own
# module (see _classify_node()) rather than raising.
_MODULE_BY_TABLE: Dict[str, str] = {
    "connection_events": "connections",
    "remote_endpoints": "connections",
    "process_destinations": "connections",
    "listening_events": "listening",
    "listening_services": "listening",
    "arp_alerts": "arpwatch",
    "arp_mappings": "arpwatch",
    "wifi_alerts": "wifi",
    "wifi_networks": "wifi",
    "bluetooth_alerts": "bluetooth",
    "bluetooth_devices": "bluetooth",
    "ble_alerts": "ble",
    "ble_peripherals": "ble",
    "process_entries": "process",
    "persistence_entries": "persistence",
    "persistence_observations": "persistence",
    "persistence_alerts": "persistence",
    "file_change_events": "file_integrity",
    "file_integrity_alerts": "file_integrity",
    "anomaly_events": "baseline",
    "correlation_alerts": "correlate",
    "threat_intel_lookups": "threatintel",
    "devices": "inventory",
}

# integration_observations/integration_alerts share two generic tables
# across five different tools (osquery/yarax/sigma/suricata/zeek) — the
# row's own `integration` column names the real, specific SOURCE (never
# just the coarse "integrations" module bucket signals.py uses), so a
# Suricata finding and a Zeek finding are never conflated as "the same
# source" just because they share a table.
_INTEGRATION_TABLES = ("integration_observations", "integration_alerts")

_SEVERITY_COLUMN_BY_TABLE: Dict[str, str] = {
    "integration_alerts": "severity",
    "persistence_alerts": "severity",
    "file_integrity_alerts": "severity",
    "arp_alerts": "severity",
    "wifi_alerts": "severity",
    "bluetooth_alerts": "severity",
    "ble_alerts": "severity",
    "correlation_alerts": "severity",
}
_SEVERITY_WEIGHT: Dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 3}
# Plain observation rows (connection_events, process_entries,
# integration_observations, ...) carry no severity of their own — they
# are facts, not findings. Weighted the same as the existing cluster
# model's own WEAK tier (strength.py's WEIGHT[WEAK] == 1), never
# assumed to be more than that. anomaly_events is deliberately NOT
# given its own weight here despite carrying anomaly_score/tier —
# baseline's tier vocabulary isn't reused elsewhere in secure/correlate/
# today and guessing at it would risk misreading it; falls back to this
# same default until a follow-up phase confirms the right mapping.
_DEFAULT_NODE_WEIGHT = 1

NodeKey = Tuple[str, int]


@dataclass(frozen=True)
class NodeInfo:
    node: ChainNode
    module: str
    source: str
    weight: int


@dataclass(frozen=True)
class ConfirmationGroup:
    """One or more ChainNodes collapsed into a single independent fact
    because they're connected only by duplicate_observation/
    same_event_confirmation links — the anti-inflation unit this
    module's own docstring describes. A group with 5 member nodes from
    3 different modules is still exactly ONE fact for corroboration
    purposes; its `modules`/`sources` sets exist so module DIVERSITY
    can still be read off it without re-counting nodes.
    """

    id: int
    node_keys: FrozenSet[NodeKey]
    modules: FrozenSet[str]
    sources: FrozenSet[str]
    max_weight: int
    earliest_timestamp: Optional[datetime]

    @property
    def raw_node_count(self) -> int:
        return len(self.node_keys)


@dataclass
class ChainScore:
    chain: Chain
    groups: List[ConfirmationGroup]
    raw_observation_count: int          # every node walked, duplicates included
    independent_fact_count: int         # len(groups) — the anti-inflation count
    module_count: int                   # distinct modules across all groups
    source_count: int                   # distinct sources across all groups (finer than module)
    meaningful_relationship_count: int  # derived_evidence edges crossing two different-module groups
    concentration: float                # largest module's share of groups, 0..1
    raw_score: int
    score: int                          # after benign-context reduction
    severity: str
    confidence: str
    uncertainty_notes: List[str] = field(default_factory=list)
    benign_context_notes: Optional[str] = None
    explanation: str = ""
    # Kept for callers that need to build a members/edges JSON payload
    # (see persist_chain_score() below) without re-walking or
    # re-classifying every node a second time. Not part of this
    # dataclass's own "public" summary fields (raw_observation_count
    # etc. above) — those are what a caller should read; these two are
    # plumbing.
    node_info_by_key: Dict[NodeKey, "NodeInfo"] = field(default_factory=dict, repr=False)
    node_key_to_group_id: Dict[NodeKey, int] = field(default_factory=dict, repr=False)


def _row_integration(conn: sqlite3.Connection, table: str, source_id: int) -> Optional[str]:
    row = conn.execute(f"SELECT integration FROM {table} WHERE id = ?", (source_id,)).fetchone()
    if row is None:
        return None
    return row["integration"]


def _row_severity(conn: sqlite3.Connection, table: str, source_id: int) -> Optional[str]:
    column = _SEVERITY_COLUMN_BY_TABLE.get(table)
    if column is None:
        return None
    row = conn.execute(f"SELECT {column} FROM {table} WHERE id = ?", (source_id,)).fetchone()
    if row is None:
        return None
    return row[column]


def _classify_node(conn: sqlite3.Connection, node: ChainNode) -> NodeInfo:
    """Resolve one node's module/source/severity-weight by reading its
    own row — the only place in this module that needs a fresh query
    per node (walk_chain() itself stays generic and doesn't do this).
    Never raises: an unrecognized table or a row that's disappeared
    since the walk falls back to safe, honest defaults rather than
    aborting the whole scoring pass.
    """
    table = node.source_table
    module = _MODULE_BY_TABLE.get(table, table)
    source = module

    if table in _INTEGRATION_TABLES:
        integration_name = _row_integration(conn, table, node.source_id)
        module = "integrations"
        source = integration_name or "integrations"

    severity = _row_severity(conn, table, node.source_id)
    weight = _SEVERITY_WEIGHT.get(severity, _DEFAULT_NODE_WEIGHT) if severity else _DEFAULT_NODE_WEIGHT

    return NodeInfo(node=node, module=module, source=source, weight=weight)


class _UnionFind:
    """Minimal union-find over NodeKey — used only to build confirmation
    groups. Not exposed outside this module.
    """

    def __init__(self, keys: "List[NodeKey]") -> None:
        self._parent: Dict[NodeKey, NodeKey] = {k: k for k in keys}

    def find(self, key: NodeKey) -> NodeKey:
        root = key
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[key] != root:
            self._parent[key], key = root, self._parent[key]
        return root

    def union(self, a: NodeKey, b: NodeKey) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[rb] = ra


def build_confirmation_groups(
    chain: Chain, node_info_by_key: Dict[NodeKey, NodeInfo]
) -> "tuple[List[ConfirmationGroup], Dict[NodeKey, int]]":
    """Collapse every node reachable through ONLY duplicate_observation/
    same_event_confirmation edges into one ConfirmationGroup. Returns
    (groups, node_key_to_group_id) so callers can map an edge's
    endpoints back to their groups.
    """
    keys = [(n.source_table, n.source_id) for n in chain.nodes]
    uf = _UnionFind(keys)

    for edge in chain.edges:
        if edge.link.relationship not in _CONFIRMATION_RELATIONSHIPS:
            continue
        from_key = (edge.from_node.source_table, edge.from_node.source_id)
        to_key = (edge.to_node.source_table, edge.to_node.source_id)
        uf.union(from_key, to_key)

    members_by_root: Dict[NodeKey, List[NodeKey]] = {}
    for key in keys:
        root = uf.find(key)
        members_by_root.setdefault(root, []).append(key)

    groups: List[ConfirmationGroup] = []
    node_key_to_group_id: Dict[NodeKey, int] = {}
    # Sorted for determinism — dict/set iteration order must never
    # decide which group gets id 0 vs id 1 across otherwise-identical runs.
    for group_id, root in enumerate(sorted(members_by_root.keys())):
        member_keys = members_by_root[root]
        infos = [node_info_by_key[k] for k in member_keys]
        timestamps = [i.node.timestamp for i in infos if i.node.timestamp is not None]
        group = ConfirmationGroup(
            id=group_id,
            node_keys=frozenset(member_keys),
            modules=frozenset(i.module for i in infos),
            sources=frozenset(i.source for i in infos),
            max_weight=max(i.weight for i in infos),
            earliest_timestamp=min(timestamps) if timestamps else None,
        )
        groups.append(group)
        for key in member_keys:
            node_key_to_group_id[key] = group_id

    return groups, node_key_to_group_id


def count_meaningful_relationships(
    chain: Chain, node_key_to_group_id: Dict[NodeKey, int], groups: List[ConfirmationGroup]
) -> int:
    """A derived_evidence edge connecting two DIFFERENT confirmation
    groups whose modules differ is a genuine causal step across
    independent sources — the "file created -> YARA finding" /
    "process execution -> persistence" shape the worked examples use.
    A derived_evidence edge that stays within one group's own module
    (or links two groups that happen to share a module) doesn't count —
    it's not yet clear that crossing sources actually happened.
    """
    seen_pairs: Set[FrozenSet[int]] = set()
    count = 0
    for edge in chain.edges:
        if edge.link.relationship != RELATIONSHIP_DERIVED_EVIDENCE:
            continue
        from_key = (edge.from_node.source_table, edge.from_node.source_id)
        to_key = (edge.to_node.source_table, edge.to_node.source_id)
        from_group_id = node_key_to_group_id[from_key]
        to_group_id = node_key_to_group_id[to_key]
        if from_group_id == to_group_id:
            continue
        from_group = groups[from_group_id]
        to_group = groups[to_group_id]
        if from_group.modules.isdisjoint(to_group.modules):
            pair = frozenset((from_group_id, to_group_id))
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                count += 1
    return count


def evidence_concentration(groups: List[ConfirmationGroup]) -> float:
    """The largest single module's share of independent facts (groups),
    AFTER duplicate-observation collapsing — the same 0..1 concentration
    concept secure/explain/correlation_explainer.py already computes for
    temporal clusters, but evidence-link-aware: a fact confirmed by
    three tools no longer counts as three separate observations pushing
    concentration around, because it was already collapsed into one
    group before this ever runs.
    """
    if not groups:
        return 0.0
    module_counts: Dict[str, int] = {}
    for g in groups:
        # A group spanning multiple modules (e.g. an osquery+native
        # same_event_confirmation) credits each of its modules once —
        # it's one fact, but a genuinely multi-vantage-point one.
        for m in g.modules:
            module_counts[m] = module_counts.get(m, 0) + 1
    largest = max(module_counts.values())
    total = sum(module_counts.values())
    return largest / total if total else 0.0


_CONCENTRATION_THRESHOLD = 0.6  # same threshold correlation_explainer.py already uses


def chain_raw_score(groups: List[ConfirmationGroup], meaningful_relationship_count: int) -> int:
    """Additive, deterministic — mirrors secure/correlate/analysis.py's
    own correlation_score() shape exactly (weighted sum + corroboration
    bonus + meaningful-combo bonus), just computed over confirmation
    GROUPS instead of raw signals, and over asserted derived_evidence
    relationships instead of a hardcoded module-pair table.
    """
    raw = sum(g.max_weight for g in groups)
    modules = {m for g in groups for m in g.modules}
    corroboration_bonus = 2 * (len(modules) - 1) if len(modules) > 1 else 0
    meaningful_bonus = 4 * min(meaningful_relationship_count, 3)  # capped — a 10-hop chain isn't 10x as meaningful
    return raw + corroboration_bonus + meaningful_bonus


def apply_weak_evidence_cap(severity: str, groups: List[ConfirmationGroup]) -> str:
    """Never let an all-weight-1 chain (every group backed only by
    plain observation rows, no real alert/severity anywhere in it)
    reach HIGH or CRITICAL — the same weak-signal ceiling
    secure/correlate/analysis.py's apply_weak_signal_cap() already
    enforces for temporal clusters, applied to chains.
    """
    if any(g.max_weight > 1 for g in groups):
        return severity
    if severity in (HIGH, CRITICAL):
        return MEDIUM_SEVERITY
    return severity


def _compute_confidence(concentration: float, module_count: int, meaningful_relationship_count: int) -> str:
    # module_count<=1 is checked FIRST, ahead of the concentration
    # check: a chain backed by only one module's worth of facts always
    # has concentration == 1.0 (there's nothing else for that one
    # module's share to be measured against), so ordering the
    # concentration check first would make this branch unreachable and
    # silently relabel "we only have one vantage point at all" as
    # UNCERTAIN (which implies conflicting/lopsided evidence FROM
    # multiple sources, not simply "too little independent evidence to
    # have an opinion yet") — the two are different findings and the
    # explain/vocab.py vocabulary already has a dedicated word for the
    # latter.
    if module_count <= 1:
        return INSUFFICIENT_EVIDENCE
    if concentration >= _CONCENTRATION_THRESHOLD:
        return UNCERTAIN
    # CONFIRMED's condition (module_count>=3, meaningful>=2) is strictly
    # STRONGER than LIKELY's (module_count>=2, meaningful>=1) — every
    # chain that qualifies for CONFIRMED also qualifies for LIKELY, so
    # the stronger check must run first. Checking LIKELY first would
    # make CONFIRMED unreachable (exactly the same "weaker branch
    # shadows the stronger one" mistake fixed above for
    # INSUFFICIENT_EVIDENCE vs UNCERTAIN).
    if module_count >= 3 and meaningful_relationship_count >= 2:
        return CONFIRMED
    if module_count >= 2 and meaningful_relationship_count >= 1:
        return LIKELY
    return UNCERTAIN


def _build_explanation(
    chain: Chain,
    groups: List[ConfirmationGroup],
    raw_score: int,
    score: int,
    severity: str,
    confidence: str,
    concentration: float,
    meaningful_relationship_count: int,
    benign_context_notes: Optional[str],
) -> str:
    ordered = sorted(groups, key=lambda g: (g.earliest_timestamp is None, g.earliest_timestamp))
    lines = [
        f"{len(chain.nodes)} raw observation(s) across {chain.hop_count} evidence-link hop(s) "
        f"collapsed into {len(groups)} independent fact(s) after Phase 21 lineage deduplication.",
    ]
    for g in ordered:
        modules_text = ", ".join(sorted(g.modules))
        lines.append(f"  - fact #{g.id}: {g.raw_node_count} observation(s), module(s) [{modules_text}]")
    lines.append(
        f"{meaningful_relationship_count} meaningful cross-source relationship(s) "
        "(derived_evidence links crossing independent facts from different modules)."
    )
    lines.append(f"Evidence concentration: {concentration:.2f} (>= {_CONCENTRATION_THRESHOLD} counts as concentrated).")
    if raw_score != score:
        lines.append(f"Score: {raw_score} -> {score} after benign-context reduction -> severity {severity}.")
    else:
        lines.append(f"Score: {score} -> severity {severity}.")
    lines.append(f"Confidence: {confidence}.")
    if benign_context_notes:
        lines.append(benign_context_notes)
    lines.append(
        "This reflects asserted evidence-link relationships between specific stored rows, not mere "
        "temporal coincidence — but a relationship being LINKED does not by itself prove a single "
        "malicious cause."
    )
    return "\n".join(lines)


def score_chain(
    conn: sqlite3.Connection,
    start_ref: ObservationRef,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
    boot_time: "Optional[datetime]" = None,
    boot_time_resolved: bool = False,
) -> ChainScore:
    """Walk outward from `start_ref` and score the resulting chain.
    Pure orchestration over already-pure pieces (walk_chain(),
    build_confirmation_groups(), chain_raw_score(), ...) — the only I/O
    here beyond the walk itself is classifying each node's
    module/source/severity (_classify_node()) and, unless
    `boot_time_resolved` is True, one real `sysctl` read for benign
    boot-time context (same seam secure/correlate/context.py's own
    get_boot_time() already provides — tests pass `boot_time=...,
    boot_time_resolved=True` to bypass the real subprocess call, the
    same "patch the wrapper" pattern this codebase uses everywhere).
    """
    chain = walk_chain(conn, start_ref, max_hops=max_hops)
    node_info_by_key: Dict[NodeKey, NodeInfo] = {
        (n.source_table, n.source_id): _classify_node(conn, n) for n in chain.nodes
    }
    groups, node_key_to_group_id = build_confirmation_groups(chain, node_info_by_key)
    meaningful_count = count_meaningful_relationships(chain, node_key_to_group_id, groups)
    concentration = evidence_concentration(groups)

    modules = {m for g in groups for m in g.modules}
    sources = {s for g in groups for s in g.sources}

    raw_score = chain_raw_score(groups, meaningful_count)

    resolved_boot_time = boot_time if boot_time_resolved else get_boot_time()
    earliest = min((g.earliest_timestamp for g in groups if g.earliest_timestamp is not None), default=None)
    benign_notes: Optional[str] = None
    score = raw_score
    if earliest is not None and is_recent_boot(earliest, resolved_boot_time, DEFAULT_BOOT_PROXIMITY_MINUTES):
        benign_notes = (
            f"This chain's earliest evidence falls within {DEFAULT_BOOT_PROXIMITY_MINUTES:.0f} minutes "
            "of this Mac's last boot — startup churn is a common, usually benign explanation."
        )
        if all(g.max_weight <= 1 for g in groups):
            score = max(0, raw_score - 3)

    severity = apply_weak_evidence_cap(severity_for_score(score), groups)
    confidence = _compute_confidence(concentration, len(modules), meaningful_count)

    uncertainty_notes: List[str] = [
        "A chain of linked evidence is not proof of a single malicious cause — "
        "it shows that specific stored rows are related, not why."
    ]
    if concentration >= _CONCENTRATION_THRESHOLD:
        uncertainty_notes.append(
            f"Most of this chain's independent facts ({concentration:.0%}) come from a single module — "
            "treat the apparent corroboration with caution."
        )
    if benign_notes:
        uncertainty_notes.append(benign_notes)

    explanation = _build_explanation(
        chain, groups, raw_score, score, severity, confidence, concentration, meaningful_count, benign_notes
    )

    return ChainScore(
        chain=chain,
        groups=groups,
        raw_observation_count=len(chain.nodes),
        independent_fact_count=len(groups),
        module_count=len(modules),
        source_count=len(sources),
        meaningful_relationship_count=meaningful_count,
        concentration=concentration,
        raw_score=raw_score,
        score=score,
        severity=severity,
        confidence=confidence,
        uncertainty_notes=uncertainty_notes,
        benign_context_notes=benign_notes,
        explanation=explanation,
        node_info_by_key=node_info_by_key,
        node_key_to_group_id=node_key_to_group_id,
    )


def fingerprint_for_chain(chain: Chain) -> str:
    """Stable, order-independent hash over every node's exact
    (source_table, source_id) — reuses secure/evidence/fingerprint.py's
    existing stable_fingerprint()/observation_part() helpers directly
    (the same "table:id" convention correlation_alerts.fingerprint
    already uses for temporal clusters) rather than inventing a new
    hashing scheme. Two chains reached from different starting nodes
    but covering the exact same node set fingerprint identically.
    """
    parts = [observation_part(n.source_table, n.source_id) for n in chain.nodes]
    return stable_fingerprint(parts)


def _build_members(chain_score: ChainScore) -> "List[dict]":
    """One JSON-serializable entry per raw node, in chain order —
    intentionally NOT deduplicated to the group level here, because a
    caller inspecting a stored chain alert should still be able to see
    every raw observation that fed it (Phase 21's "keep every
    observation" principle applies to how a chain alert is *displayed*
    too, not just to how it's scored). group_id lets a caller re-derive
    the confirmation grouping without recomputing anything.
    """
    members = []
    for node in chain_score.chain.nodes:
        key = (node.source_table, node.source_id)
        info = chain_score.node_info_by_key[key]
        group_id = chain_score.node_key_to_group_id[key]
        members.append(
            {
                "source_table": node.source_table,
                "source_id": node.source_id,
                "timestamp": node.timestamp.isoformat() if node.timestamp is not None else None,
                "module": info.module,
                "source": info.source,
                "weight": info.weight,
                "group_id": group_id,
            }
        )
    return members


def _build_edges(chain_score: ChainScore) -> "List[dict]":
    """One JSON-serializable entry per evidence_links row the walk
    crossed — every field a caller needs to re-fetch the exact
    underlying evidence_links row (evidence_link_id) or re-derive
    grouping (from/to group_id) without a second walk.
    """
    edges = []
    for edge in chain_score.chain.edges:
        from_key = (edge.from_node.source_table, edge.from_node.source_id)
        to_key = (edge.to_node.source_table, edge.to_node.source_id)
        edges.append(
            {
                "relationship": edge.link.relationship,
                "from_source_table": edge.from_node.source_table,
                "from_source_id": edge.from_node.source_id,
                "to_source_table": edge.to_node.source_table,
                "to_source_id": edge.to_node.source_id,
                "match_basis": edge.link.match_basis,
                "evidence_link_id": edge.link.id,
                "from_group_id": chain_score.node_key_to_group_id[from_key],
                "to_group_id": chain_score.node_key_to_group_id[to_key],
            }
        )
    return edges


def persist_chain_score(
    conn: sqlite3.Connection, run_id: str, chain_score: ChainScore
) -> "tuple[CorrelationChainAlertRecord, bool]":
    """Record one scored chain into correlation_chain_alerts. Idempotent
    by fingerprint_for_chain() — rescanning the same underlying evidence
    and re-walking to the same node set never creates a duplicate row
    (same "touch, don't insert" discipline Phase 21 established for
    evidence_links itself), matching add_correlation_alert()'s existing
    (record, was_new) return shape for the temporal-cluster table.

    The starting node recorded is always chain.nodes[0] — walk_chain()
    guarantees the node passed to it as start_ref is always first.
    """
    start_node = chain_score.chain.nodes[0]
    fingerprint = fingerprint_for_chain(chain_score.chain)
    return add_correlation_chain_alert(
        conn,
        run_id=run_id,
        fingerprint=fingerprint,
        start_source_table=start_node.source_table,
        start_source_id=start_node.source_id,
        raw_observation_count=chain_score.raw_observation_count,
        independent_fact_count=chain_score.independent_fact_count,
        module_count=chain_score.module_count,
        source_count=chain_score.source_count,
        meaningful_relationship_count=chain_score.meaningful_relationship_count,
        concentration=chain_score.concentration,
        raw_score=chain_score.raw_score,
        score=chain_score.score,
        severity=chain_score.severity,
        confidence=chain_score.confidence,
        uncertainty_notes=chain_score.uncertainty_notes,
        benign_context_notes=chain_score.benign_context_notes,
        explanation=chain_score.explanation,
        members=_build_members(chain_score),
        edges=_build_edges(chain_score),
    )
