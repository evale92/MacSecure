"""
secure/evidence/ — Phase 21: the unified evidence, lineage, and
deduplication model.

Deliberately minimal, matching the same discipline
secure/integrations/base.py and secure/threatintel/base.py already
established for their own boundaries — see model.py's own module
docstring for the full concept-by-concept mapping (entity, observation,
finding, source, provenance, event family) onto what this codebase
already has, and for exactly why only ONE genuinely new storage concept
(the evidence_links relationship) was added rather than a larger
rewrite.

    model.py       — pure vocabulary: SourceRef, ObservationRef,
                     EvidenceLink, and the RELATIONSHIP_* constants
                     (duplicate_observation / same_event_confirmation /
                     derived_evidence — "independent corroboration" is
                     represented structurally, by the absence of a
                     link, not a fourth stored value).
    fingerprint.py — pure, reusable identity+timing matching toolkit
                     (find_best_identity_timing_match) and a stable-hash
                     helper (stable_fingerprint), generalizing patterns
                     already duplicated in
                     secure/integrations/suricata/correlate.py and
                     secure/integrations/zeek/dedup.py, and in
                     secure/correlate/analysis.py's own
                     fingerprint_for_cluster(). Existing modules are NOT
                     refactored to use this in Stage 1 — see that
                     module's own docstring for why.
    record.py      — (Stage 2) the one I/O entry point: idempotent
                     check-then-insert persistence of an EvidenceLink.
    chain.py       — (Phase 22 Stage 2) the read-side counterpart to
                     record.py: walk_chain() traverses evidence_links
                     outward from a starting row (breadth-first,
                     cycle-guarded, hop-capped), resolving each visited
                     row's own real-world timestamp so a chain can be
                     read in causal order. Deliberately generic — knows
                     nothing about scoring, modules, or severity; see
                     secure/correlate/chains.py (Stage 3) for the
                     security-specific interpretation built on top, and
                     this module's own docstring for why it's expected
                     to be reused by Phase 23's investigation model too.

Storage: one new table, `evidence_links` (secure/storage/database.py,
secure/storage/models/evidence.py) — purely additive; no existing table
is altered and no existing row is ever rewritten by this phase.
"""

from secure.evidence.chain import (
    Chain,
    ChainEdge,
    ChainNode,
    DEFAULT_MAX_HOPS,
    walk_chain,
)
from secure.evidence.fingerprint import (
    CandidateSide,
    MatchOutcome,
    MatchTarget,
    find_best_identity_timing_match,
    logical_ref_identity,
    observation_part,
    stable_fingerprint,
)
from secure.evidence.model import (
    RELATIONSHIP_DERIVED_EVIDENCE,
    RELATIONSHIP_DUPLICATE_OBSERVATION,
    RELATIONSHIP_SAME_EVENT_CONFIRMATION,
    SOURCE_INTEGRATION,
    SOURCE_NATIVE,
    SOURCE_THREATINTEL,
    EvidenceLink,
    ObservationRef,
    SourceRef,
)
from secure.evidence.record import record_link

__all__ = [
    "Chain", "ChainEdge", "ChainNode", "DEFAULT_MAX_HOPS", "walk_chain",
    "CandidateSide", "MatchOutcome", "MatchTarget",
    "find_best_identity_timing_match", "logical_ref_identity", "observation_part", "stable_fingerprint",
    "RELATIONSHIP_DERIVED_EVIDENCE", "RELATIONSHIP_DUPLICATE_OBSERVATION",
    "RELATIONSHIP_SAME_EVENT_CONFIRMATION",
    "SOURCE_INTEGRATION", "SOURCE_NATIVE", "SOURCE_THREATINTEL",
    "EvidenceLink", "ObservationRef", "SourceRef",
    "record_link",
]
