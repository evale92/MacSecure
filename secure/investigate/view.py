"""
secure/investigate/view.py — Phase 23 Stage 5: the top-level
investigation composition. This is the one function a frontend (CLI
today, GUI/API later — see this package's own docstring on staying
tkinter-independent) actually needs to call to investigate one entity:
everything Stages 2-4 built (resolve_entity, build_timeline,
related_evidence, discover_pivots), assembled into a single read-only
InvestigationView.

Also the one place "progressive disclosure" of raw evidence becomes
concrete: `explain_observation()` lets a caller ask for the FULL
Product-Phase-13 Explanation (severity/confidence/evidence/uncertainty/
recommended action — see secure/explain/) behind any ObservationRef the
timeline or related-evidence view surfaced, but only when that row is
actually alert-shaped (has a real explainer registered). A plain
identity/observation row (a process_entries row, a connection_events
row, ...) has no severity or confidence to explain — asking for one
returns None rather than a fabricated or misleading Explanation, the
same "never fabricate what isn't there" discipline every other honest-
absence concept in this codebase already follows (Phase 20's "not found
is not safe," Phase 16's degraded=True). This function deliberately
does NOT compute anything new about a record; it hands the exact same
record straight to secure/explain/dispatch.explain() the Alerts table
already uses, so an investigation view and the Alerts table can never
disagree about what one alert means — the literal "do not duplicate
detection logic" instruction, satisfied by reuse rather than avoidance.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from secure.evidence.model import ObservationRef
from secure.explain.dispatch import explain
from secure.explain.explanation import Explanation
from secure.investigate.entity import EntityRef
from secure.investigate.pivots import PivotTarget, discover_pivots
from secure.investigate.resolve import resolve_entity
from secure.investigate.timeline import DEFAULT_MAX_HOPS, RelatedEvidence, Timeline, build_timeline, related_evidence
from secure.storage.models import (
    find_arp_alert_by_id,
    find_ble_alert_by_id,
    find_bluetooth_alert_by_id,
    find_correlation_alert_by_id,
    find_correlation_chain_alert_by_id,
    find_file_integrity_alert_by_id,
    find_integration_alert_by_id,
    find_persistence_alert_by_id,
    find_wifi_alert_by_id,
)

# Exactly the same source_table set secure/explain/dispatch.py's own
# _EXPLAINERS registers an explainer for (see that module's docstring)
# — kept as a SEPARATE table->finder mapping here rather than importing
# dispatch._EXPLAINERS directly, since that dict's keys tell us WHICH
# tables are explainable but not HOW to fetch a row from one; every
# find_*_by_id used below already exists and is exercised elsewhere
# (secure/cli/root.py's own _EXPLAIN_SOURCES, keyed by CLI source name
# rather than table, needed the identical set of finders for the same
# reason). Adding a new alert table to dispatch._EXPLAINERS without
# adding it here just means explain_observation() returns None for
# that table's rows — a silent, safe omission, not a crash.
_ALERT_FINDER_BY_TABLE = {
    "arp_alerts": find_arp_alert_by_id,
    "wifi_alerts": find_wifi_alert_by_id,
    "bluetooth_alerts": find_bluetooth_alert_by_id,
    "ble_alerts": find_ble_alert_by_id,
    "persistence_alerts": find_persistence_alert_by_id,
    "file_integrity_alerts": find_file_integrity_alert_by_id,
    "correlation_alerts": find_correlation_alert_by_id,
    "integration_alerts": find_integration_alert_by_id,
    "correlation_chain_alerts": find_correlation_chain_alert_by_id,
}


@dataclass
class InvestigationView:
    """Everything an analyst needs to start investigating one entity,
    read-only, composed from Stages 2-4 with no new computation of its
    own. `exists=False` (entity not on record at all) short-circuits
    every other field to its empty default — there is nothing to show a
    timeline, related evidence, or pivots FOR.
    """

    entity: EntityRef
    exists: bool
    summary: Dict[str, object] = field(default_factory=dict)
    anchors: List[ObservationRef] = field(default_factory=list)
    timeline: Optional[Timeline] = None
    related: Optional[RelatedEvidence] = None
    pivots: List[PivotTarget] = field(default_factory=list)


def investigate(
    conn: sqlite3.Connection,
    entity: EntityRef,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
) -> InvestigationView:
    """The one call a frontend makes to open an investigation on
    `entity`. Read-only — see this package's own __init__.py docstring;
    nothing here writes to the database or changes any known/unknown
    marking.
    """
    resolution = resolve_entity(conn, entity)
    if not resolution.exists:
        return InvestigationView(entity=entity, exists=False)

    return InvestigationView(
        entity=entity,
        exists=True,
        summary=resolution.summary,
        anchors=resolution.anchors,
        timeline=build_timeline(conn, entity, max_hops=max_hops),
        related=related_evidence(conn, entity, max_hops=max_hops),
        pivots=discover_pivots(conn, entity, max_hops=max_hops),
    )


def explain_observation(conn: sqlite3.Connection, ref: ObservationRef) -> Optional[Explanation]:
    """The progressive-disclosure hook: given any ObservationRef
    surfaced by a Timeline or RelatedEvidence, return its full
    Explanation IF it's an alert-shaped row (see this module's own
    docstring) and that row still exists, else None. Never raises —
    an unrecognized table or an already-deleted row is exactly as valid
    an outcome as "this was never alert-shaped to begin with."
    """
    finder = _ALERT_FINDER_BY_TABLE.get(ref.source_table)
    if finder is None:
        return None
    record = finder(conn, ref.source_id)
    if record is None:
        return None
    return explain(record, ref.source_table)
