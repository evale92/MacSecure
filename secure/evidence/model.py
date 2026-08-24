"""
secure/evidence/model.py — the pure, provider-neutral vocabulary for
Phase 21's unified evidence/lineage/dedup model. No I/O, no database —
directly testable with plain values, same discipline every other
"base.py"/"model.py" boundary in this codebase already uses
(secure/integrations/base.py, secure/threatintel/base.py).

Deliberately does NOT introduce new physical storage for every concept
Phase 21 names. Most of them already exist; this module documents the
mapping rather than duplicating it:

    Entity      — reuses secure/baseline/entities.py's existing
                  (entity_type, entity_key) vocabulary, unchanged. No
                  new entity table.
    Observation — the existing `*_observations`/`*_events` rows this
                  app has always written (connection_events,
                  integration_observations, arp_observations, ...).
                  Unchanged.
    Finding     — the existing `*_alerts` rows, `anomaly_events`, and
                  `correlation_alerts`. Unchanged — this phase's own
                  instruction is explicit that severity/confidence/
                  anomaly/trust must NOT be collapsed into the evidence
                  model, so a Finding's own table stays exactly what it
                  already is.
    Source      — `SourceRef` below: a name for "which collector
                  produced this" (a native module name, an
                  integrations/base.py `integration` name, or a
                  threatintel `provider` name). Not a new table — the
                  name already lives in existing columns
                  (`integration_observations.integration`,
                  `threat_intel_lookups.provider`, or is simply the
                  owning module itself for native tables).
    Provenance  — the existing `source_table`/`source_id` column pair
                  this app already writes on `anomaly_events`,
                  `baseline_feature_activity`, and
                  `integration_alerts.source_observation_id`. Reused
                  as-is here via `ObservationRef`, not replaced.
    Event family — NOT a new physical table (yet). Computed on read as
                  the transitive closure over `evidence_links` rows
                  (secure/storage/models/evidence.py) — the same
                  "derived view over existing rows, not a new mirror"
                  discipline secure/correlate/ already uses for
                  `correlation_alerts`.
    Parent/derived relationships, duplicate observation, same-event
    confirmation — `EvidenceLink` below, and the RELATIONSHIP_*
                  vocabulary. This is the one genuinely new concept
                  Phase 21 needs storage for — see this module's
                  RELATIONSHIP_* docstrings for exactly what each one
                  means and why "genuinely independent corroboration"
                  deliberately has NO stored constant of its own.

Why not a bigger rewrite: secure/integrations/base.py's own docstring
already stated the founding discipline this file continues — "design
the smallest generic boundary needed for future engines... do not
prematurely build the entire future unified-evidence architecture."
Phase 21 is that future point arriving, but the same minimalism
discipline still applies: reuse what already works, add storage only
for the one relationship concept that has no home yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# ---------- Source ----------
#
# What KIND of thing produced an observation — not stored anywhere new;
# this just names the three kinds of source this app already has.
SOURCE_NATIVE = "native"            # one of Secure's own built-in scanners (connections, wifi, ...)
SOURCE_INTEGRATION = "integration"  # secure/integrations/* (osquery, yara-x, sigma, suricata, zeek)
SOURCE_THREATINTEL = "threatintel"  # secure/threatintel/* providers (local_feed, virustotal)

_VALID_SOURCE_KINDS = (SOURCE_NATIVE, SOURCE_INTEGRATION, SOURCE_THREATINTEL)


@dataclass(frozen=True)
class SourceRef:
    """Which collector produced an observation. `kind` is one of the
    three SOURCE_* constants above; `name` is that source's own short
    stable identifier — a native module name ("connections"), an
    IntegrationIdentity.name ("suricata"), or a ProviderIdentity.name
    ("virustotal"). A naming convenience only — never persisted as its
    own row; the equivalent information already lives in existing
    columns wherever an observation/finding is actually stored.
    """

    kind: str
    name: str

    def __post_init__(self) -> None:
        if self.kind not in _VALID_SOURCE_KINDS:
            raise ValueError(f"invalid SourceRef.kind: {self.kind!r}")
        if not self.name:
            raise ValueError("SourceRef.name must not be empty")


@dataclass(frozen=True)
class ObservationRef:
    """Exact provenance for one row already sitting in this database —
    the same `(source_table, source_id)` pair this app has used for
    provenance since Phase 14 (`anomaly_events.source_table/source_id`,
    `baseline_feature_activity.source_table/source_id`,
    `integration_alerts.source_observation_id`). Never a deduplicated
    identity-table row (e.g. never `remote_endpoints`, always
    `connection_events`) — the same "exact observation, not something
    resolved after the fact" discipline every prior provenance link in
    this codebase already follows.

    `logical_key` (optional) is a SEPARATE concept from `source_id`,
    added after Stage 3 revealed that the two don't always mean the same
    thing. For most sources, one row IS one distinct real-world event
    that will never recur (Zeek's log-cursor, Suricata's timestamp
    cursor — a rescan produces zero new rows for something already
    ingested), so `source_id` itself is already a perfectly good logical
    identity and `logical_key` should be left None. But a source with no
    ingestion cursor (osquery: every scan re-runs live queries and
    inserts a genuinely NEW row for the same unchanged fact — see
    secure/integrations/osquery/scanner.py) needs a DIFFERENT, stable
    identity for evidence_links' own idempotence to key off — one that
    doesn't change just because this pass's observation row id differs
    from last pass's. `logical_key` is that identity (e.g. built from an
    osquery Match's own `identity_key`); see
    secure/evidence/fingerprint.py's logical_ref_identity(), which reads
    this field.
    """

    source_table: str
    source_id: int
    logical_key: "Optional[str]" = None

    def __post_init__(self) -> None:
        if not self.source_table:
            raise ValueError("ObservationRef.source_table must not be empty")
        if self.source_id is None:
            raise ValueError("ObservationRef.source_id must not be None")
        if self.logical_key is not None and not self.logical_key:
            raise ValueError("ObservationRef.logical_key must not be empty when provided")


# ---------- Relationship ----------
#
# Three stored values — deliberately not four. "Genuinely independent
# corroboration" (the fourth concept Phase 21 asks to distinguish) is
# represented STRUCTURALLY by the ABSENCE of any link between two
# pieces of evidence, not as a fourth constant that would need to be
# written for every ordinary unrelated pair — the same "make the
# invariant structural, not a value to remember" discipline Phase 20's
# ProviderLookupResult used for "not found is not safe."
RELATIONSHIP_DUPLICATE_OBSERVATION = "duplicate_observation"
# Same collection mechanism (or two mechanisms with no independent
# vantage point at all), same underlying fact, recorded more than once
# — e.g. a defensive re-scan re-observing something already captured a
# moment earlier through the same pipeline. Not the primary case any
# integration wired in Stage 3 produces today; the constant exists so a
# genuinely mechanical duplicate has a real name rather than being
# forced into "same_event_confirmation".

RELATIONSHIP_SAME_EVENT_CONFIRMATION = "same_event_confirmation"
# Different sources — genuinely different vantage points/techniques —
# independently observed the SAME real-world event. This is the
# osquery-vs-native-scan match (secure/integrations/osquery/
# crosscheck.py) and the Zeek-conn.log-vs-Suricata-alert match
# (secure/integrations/zeek/dedup.py): two engines agreeing, not one
# engine restating itself.

RELATIONSHIP_DERIVED_EVIDENCE = "derived_evidence"
# One record exists only BECAUSE of another — the "parent/derived"
# relationship Phase 21 asks to represent. Suricata's process-context
# attribution (secure/integrations/suricata/correlate.py) is exactly
# this: the alert's process context is derived FROM a connection_events
# row, not a duplicate of it and not a second engine confirming the
# same event from its own independent vantage point.

_VALID_RELATIONSHIPS = (
    RELATIONSHIP_DUPLICATE_OBSERVATION,
    RELATIONSHIP_SAME_EVENT_CONFIRMATION,
    RELATIONSHIP_DERIVED_EVIDENCE,
)


@dataclass(frozen=True)
class EvidenceLink:
    """One lineage/dedup fact connecting two existing rows already in
    this database. `from_ref` is the "later"/"dependent" side (the
    record that references another); `to_ref` is the "matched"/
    "explaining" side. `match_basis` is a short label for HOW the match
    was established (e.g. "identity+timing") — free text, not a closed
    vocabulary, since new match techniques shouldn't need a schema
    change to be described. `time_delta_seconds` is populated only when
    the match was timing-based; None when it wasn't (e.g. a structural
    agreement with no independent timestamps to compare).
    `created_by` names the mechanism that recorded this link (e.g.
    "zeek_dedup", "suricata_correlate", "osquery_crosscheck") — its own
    exact provenance, so a link is never anonymous about where it came
    from.

    Deliberately carries NO severity/confidence/trust field of its own
    — per Phase 21's explicit instruction not to collapse those
    concepts into the evidence model. A link states a RELATIONSHIP
    between two rows; what each row's own severity/confidence already
    is stays entirely with that row's own table, untouched.
    """

    from_ref: ObservationRef
    to_ref: ObservationRef
    relationship: str
    match_basis: str
    detail: str
    created_by: str
    time_delta_seconds: Optional[float] = None

    def __post_init__(self) -> None:
        if self.relationship not in _VALID_RELATIONSHIPS:
            raise ValueError(f"invalid EvidenceLink.relationship: {self.relationship!r}")
        if not self.match_basis:
            raise ValueError("EvidenceLink.match_basis must not be empty")
        if not self.created_by:
            raise ValueError("EvidenceLink.created_by must not be empty")
