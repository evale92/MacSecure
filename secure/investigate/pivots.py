"""
secure/investigate/pivots.py — Phase 23 Stage 4: pivot discovery.

Answers "from here, where can an analyst go next" for one EntityRef.
Two pivot sources, both built entirely from work already done in
earlier stages — no new detection logic, and no new SQL beyond what
Stage 2 already added:

  1. Evidence-linked pivots — every ObservationRef reachable from this
     entity (its own anchors, from resolve_entity(), PLUS everything
     Stage 3's related_evidence() reaches by walking evidence_links) is
     run back through resolve_observation() (Stage 2) to recover the
     entity/entities each row belongs to. This is the general-purpose
     path: any relationship Phase 21/22 already recorded as an
     evidence_links row (native scan corroborating an integration
     finding, YARA-X match tied to a process, persistence tied to a
     destination, ...) surfaces here automatically, with zero
     per-entity-type code required.

  2. Native/structural pivots — a small, explicit table of
     relationships that are always true by construction but are NOT
     evidence_links rows. evidence_links exists to record CROSS-SOURCE
     corroboration/derivation between independently-collected rows —
     it was never meant to restate a fact already sitting in one row's
     own column (e.g. "this persistence entry's own program_path IS
     this process" isn't a corroboration between two observations, it's
     one row naming another entity directly). Reuses the exact same
     filtered list_*_for_*() functions Stage 2 added for this purpose
     (list_process_destinations_for_process/_for_remote) plus each
     entity's own already-resolved summary fields — never new SQL.

Every PivotTarget names the entity to pivot to and cites what supports
the suggestion (a short human-readable reason, and the exact
ObservationRef backing it when there is one), so a caller can decide
how prominently to surface it rather than receiving a bare, unexplained
list of entity refs.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from secure.evidence.model import ObservationRef
from secure.investigate.entity import (
    DESTINATION,
    FILE,
    PERSISTENCE,
    PROCESS,
    PROCESS_DESTINATION,
    EntityRef,
    process_destination_key,
    process_key,
)
from secure.investigate.resolve import resolve_entity, resolve_observation
from secure.investigate.timeline import DEFAULT_MAX_HOPS, related_evidence
from secure.storage.models import (
    find_file_entry_by_path,
    list_process_destinations_for_process,
    list_process_destinations_for_remote,
    list_process_entries,
)


@dataclass(frozen=True)
class PivotTarget:
    """One suggested next entity to investigate. `via` is the exact
    ObservationRef that grounds the suggestion when one exists — a
    native/structural pivot (see this module's own docstring) may have
    none, since it's derived from the entity's own identity fields
    rather than a specific linked row.
    """

    entity: EntityRef
    reason: str
    via: Optional[ObservationRef] = None


def discover_pivots(
    conn: sqlite3.Connection,
    entity: EntityRef,
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
) -> List[PivotTarget]:
    """Every entity an analyst can reasonably pivot to from `entity`,
    deduplicated (an entity reachable more than one way is listed
    once, keeping whichever reason was discovered first — evidence-
    linked pivots before native/structural ones). Returns [] for an
    entity not on record at all (mirrors resolve_entity()'s own
    exists=False handling — there is nothing to pivot FROM).
    """
    resolution = resolve_entity(conn, entity)
    if not resolution.exists:
        return []

    targets: Dict[EntityRef, PivotTarget] = {}

    all_refs: List[ObservationRef] = list(resolution.anchors)
    related = related_evidence(conn, entity, max_hops=max_hops)
    for group in related.groups:
        all_refs.extend(group.observations)

    for ref in all_refs:
        for candidate in resolve_observation(conn, ref):
            if candidate == entity or candidate in targets:
                continue
            targets[candidate] = PivotTarget(
                entity=candidate,
                reason=f"evidence-linked via {ref.source_table}#{ref.source_id}",
                via=ref,
            )

    for target in _native_pivots(conn, entity):
        if target.entity == entity or target.entity in targets:
            continue
        targets[target.entity] = target

    return list(targets.values())


def _native_pivots(conn: sqlite3.Connection, entity: EntityRef) -> List[PivotTarget]:
    handler = _NATIVE_PIVOT_HANDLERS.get(entity.entity_type)
    if handler is None:
        return []
    try:
        return handler(conn, entity)
    except Exception:  # noqa: BLE001 — a pivot-discovery failure must never block the rest of an investigation
        return []


def _native_from_process(conn: sqlite3.Connection, entity: EntityRef) -> List[PivotTarget]:
    process_name = resolve_entity(conn, entity).summary.get("process_name")
    if not process_name:
        return []
    out: List[PivotTarget] = []
    for record in list_process_destinations_for_process(conn, process_name):
        key = process_destination_key(record.process_name, record.remote_addr, record.remote_port, record.proto)
        out.append(
            PivotTarget(
                entity=EntityRef(entity_type=PROCESS_DESTINATION, entity_key=key),
                reason=f"process {process_name!r} observed contacting {record.remote_addr}:{record.remote_port}/{record.proto}",
                via=ObservationRef(source_table="process_destinations", source_id=record.id),
            )
        )
    return out


def _native_from_destination(conn: sqlite3.Connection, entity: EntityRef) -> List[PivotTarget]:
    summary = resolve_entity(conn, entity).summary
    remote_addr, remote_port, proto = summary.get("remote_addr"), summary.get("remote_port"), summary.get("proto")
    if remote_addr is None or remote_port is None or proto is None:
        return []
    out: List[PivotTarget] = []
    for record in list_process_destinations_for_remote(conn, remote_addr, remote_port, proto):
        # process_destinations only carries process_name (a short,
        # possibly-ambiguous label), never the executable_path a
        # PROCESS entity's own key is built from — so, same "iterate
        # candidates and compare" discipline resolve.py uses throughout,
        # match against every on-record process_entries row by name
        # rather than guessing executable_path == process_name.
        for candidate in list_process_entries(conn):
            if candidate.process_name == record.process_name:
                out.append(
                    PivotTarget(
                        entity=EntityRef(entity_type=PROCESS, entity_key=process_key(candidate.executable_path)),
                        reason=f"process {record.process_name!r} observed contacting this destination",
                        via=ObservationRef(source_table="process_destinations", source_id=record.id),
                    )
                )
    return out


def _pivot_to_process_if_running(conn: sqlite3.Connection, program_path: str, reason: str) -> List[PivotTarget]:
    process_entity = EntityRef(entity_type=PROCESS, entity_key=process_key(program_path))
    if not resolve_entity(conn, process_entity).exists:
        return []
    return [PivotTarget(entity=process_entity, reason=reason)]


def _native_from_persistence(conn: sqlite3.Connection, entity: EntityRef) -> List[PivotTarget]:
    program_path = resolve_entity(conn, entity).summary.get("program_path")
    if not program_path:
        return []
    return _pivot_to_process_if_running(
        conn, program_path, f"backing executable {program_path!r} also seen running as a process"
    )


def _native_from_file(conn: sqlite3.Connection, entity: EntityRef) -> List[PivotTarget]:
    record = find_file_entry_by_path(conn, entity.entity_key)
    if record is None or not record.program_path:
        return []
    return _pivot_to_process_if_running(
        conn, record.program_path, f"file's owning program {record.program_path!r} also seen running as a process"
    )


_NATIVE_PIVOT_HANDLERS: Dict[str, Callable[[sqlite3.Connection, EntityRef], List[PivotTarget]]] = {
    PROCESS: _native_from_process,
    DESTINATION: _native_from_destination,
    PERSISTENCE: _native_from_persistence,
    FILE: _native_from_file,
}
