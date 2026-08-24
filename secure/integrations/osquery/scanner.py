"""
integrations/osquery/scanner.py — orchestrates one full osquery
integration pass: check availability, run the Phase 15 query subset,
normalize the results into ExternalObservations, persist the run and
every observation, cross-check listening ports and launchd persistence
against Secure's own native tables, and persist any genuine discrepancy
as an integration_alerts row.

This is the only file in the osquery integration that touches the
database — mirrors every native scanner module's own "one file does the
I/O" split (see e.g. secure/listening/scanner.py, secure/persistence/
scanner.py). Like every scanner in this app, it never blocks, disables,
deletes, or modifies anything it finds — it only observes, normalizes,
cross-checks, and records. It also never touches, disables, or replaces
any of Secure's own native collectors — per Phase 15's explicit
instruction, osquery is an additional, cross-checking source only.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List

from secure.evidence import (
    EvidenceLink,
    ObservationRef,
    RELATIONSHIP_SAME_EVENT_CONFIRMATION,
    record_link,
)
from secure.integrations.base import (
    STATUS_DEGRADED,
    STATUS_OK,
    ExternalObservation,
    IntegrationHealth,
)
from secure.integrations.osquery._shell import run_query
from secure.integrations.osquery.availability import check_availability
from secure.integrations.osquery.crosscheck import (
    OSQUERY_ONLY,
    Discrepancy,
    crosscheck_listening_ports,
    crosscheck_persistence,
    find_listening_port_matches,
    find_persistence_matches,
)
from secure.integrations.osquery.parser import (
    build_pid_name_map,
    parse_launchd,
    parse_listening_ports,
    parse_process_open_sockets,
    parse_processes,
    parse_rows,
)
from secure.integrations.osquery.queries import (
    COLLECTION_ORDER,
    LAUNCHD,
    LISTENING_PORTS,
    PROCESS_OPEN_SOCKETS,
    PROCESSES,
    QUERIES,
)
from secure.storage.models import (
    add_integration_alert,
    add_integration_observations,
    add_integration_run,
)

INTEGRATION_NAME = "osquery"

# crosscheck.py's own Discrepancy.kind values ("listening_port",
# "persistence") map to the query kind whose observations they were
# derived from, needed to resolve an 'osquery_only' discrepancy's exact
# source_observation_id below.
_DISCREPANCY_KIND_TO_QUERY_KIND = {
    "listening_port": LISTENING_PORTS,
    "persistence": LAUNCHD,
}


@dataclass
class OsqueryScanResult:
    scanned_at: str
    run_id: str
    health: IntegrationHealth
    observations: List[ExternalObservation] = field(default_factory=list)
    discrepancies: List[Discrepancy] = field(default_factory=list)
    failed_queries: List[str] = field(default_factory=list)
    evidence_links_recorded: int = 0

    @property
    def available(self) -> bool:
        return self.health.available


def _run_one_query(kind: str, timeout: float) -> "tuple[bool, list]":
    """Run and parse one query kind. Returns (ok, rows-as-dicts) — ok is
    False for either a subprocess failure or unparseable JSON output;
    either way this query's contribution is dropped from the pass and
    the caller marks the overall result 'degraded', never silently 'ok'.
    """
    result = run_query(QUERIES[kind], timeout=timeout)
    if not result.ok:
        return False, []
    try:
        return True, parse_rows(result.stdout)
    except ValueError:
        return False, []


def scan_osquery(conn: sqlite3.Connection, timeout: float = 10.0) -> OsqueryScanResult:
    """Run one osquery integration pass and record the results.

    An unavailable/error health check short-circuits immediately: one
    integration_runs row is written reflecting that status and nothing
    else happens this pass — no queries are attempted, no observations
    or alerts are produced, and the scan never looks like a clean
    success (Phase 15: "external-tool failure must appear as
    unavailable/degraded, never clean").
    """
    started_at = datetime.now(timezone.utc)
    now = started_at.isoformat()
    run_id = uuid.uuid4().hex[:12]

    health = check_availability(timeout=timeout)
    if not health.available:
        add_integration_run(
            conn,
            run_id=run_id,
            integration=INTEGRATION_NAME,
            started_at=now,
            completed_at=datetime.now(timezone.utc).isoformat(),
            status=health.status,
            detail=health.detail,
            tool_version=health.tool_version,
            observations_collected=0,
            alerts_generated=0,
        )
        return OsqueryScanResult(scanned_at=now, run_id=run_id, health=health)

    raw_rows: "dict[str, list]" = {}
    failed_queries: List[str] = []
    for kind in COLLECTION_ORDER:
        ok, rows = _run_one_query(kind, timeout)
        raw_rows[kind] = rows
        if not ok:
            failed_queries.append(kind)

    pid_name_map = build_pid_name_map(raw_rows.get(PROCESSES, []))

    observations: List[ExternalObservation] = []
    observations.extend(parse_processes(raw_rows.get(PROCESSES, []), now))
    observations.extend(
        parse_process_open_sockets(raw_rows.get(PROCESS_OPEN_SOCKETS, []), now, pid_name_map)
    )
    observations.extend(
        parse_listening_ports(raw_rows.get(LISTENING_PORTS, []), now, pid_name_map)
    )
    observations.extend(parse_launchd(raw_rows.get(LAUNCHD, []), now))

    overall_status = STATUS_DEGRADED if failed_queries else STATUS_OK
    detail = (
        "osqueryi ran, but these queries failed and were skipped: " + ", ".join(failed_queries)
        if failed_queries
        else "osqueryi ran successfully for every query in this pass"
    )
    effective_health = IntegrationHealth(
        status=overall_status,
        detail=detail,
        collected_at=now,
        tool_version=health.tool_version,
    )

    observation_ids: List[int] = (
        add_integration_observations(
            conn,
            run_id=run_id,
            integration=INTEGRATION_NAME,
            rows=[
                (o.kind, o.identity_key, o.fields, o.source_query, o.collected_at)
                for o in observations
            ],
        )
        if observations
        else []
    )
    # (kind, identity_key) -> real integration_observations.id, so an
    # 'osquery_only' discrepancy below can reference the exact row it
    # came from instead of just the identity string alone — the same
    # exact-observation-provenance discipline as everywhere else in this
    # app. Built from `observations`/`observation_ids`, which share one
    # order by construction (see add_integration_observations()'s
    # docstring).
    observation_id_by_key = {
        (obs.kind, obs.identity_key): obs_id
        for obs, obs_id in zip(observations, observation_ids)
    }

    discrepancies: List[Discrepancy] = []
    # Crosscheck only runs against queries that actually succeeded this
    # pass — treating a FAILED query as "osquery saw nothing" would
    # flood native_only discrepancies for every native entry, and isn't
    # a real disagreement at all, just a missing data point.
    if LISTENING_PORTS not in failed_queries:
        discrepancies.extend(crosscheck_listening_ports(conn, observations))
    if LAUNCHD not in failed_queries:
        discrepancies.extend(crosscheck_persistence(conn, observations))

    for d in discrepancies:
        source_observation_id = None
        if d.discrepancy_type == OSQUERY_ONLY:
            query_kind = _DISCREPANCY_KIND_TO_QUERY_KIND.get(d.kind)
            source_observation_id = observation_id_by_key.get((query_kind, d.identity_key))
        add_integration_alert(
            conn,
            run_id=run_id,
            integration=INTEGRATION_NAME,
            kind=d.kind,
            discrepancy=d.discrepancy_type,
            severity=d.severity,
            identity_key=d.identity_key,
            label=d.label,
            message=d.message,
            source_observation_id=source_observation_id,
        )

    # Phase 21 (additive, and the one genuinely NEW behavior in this
    # stage): a native/osquery MATCH still produces no integration_alerts
    # row (untouched — see crosscheck.py's own founding docstring), but
    # now additionally gets a formal, queryable same_event_confirmation
    # evidence_links row instead of leaving zero trace anywhere. Only
    # runs against queries that succeeded this pass, same guard as the
    # discrepancy crosschecks above. A failure to record a link is
    # swallowed defensively — this is enrichment, never allowed to turn
    # a successful scan into a failed one.
    #
    # logical_key (Stage 3c correction): osquery has no ingestion cursor
    # (see this file's own module docstring / scan_osquery()'s
    # docstring) — every scan re-runs live queries and inserts a
    # genuinely NEW integration_observations row for the same unchanged
    # real-world fact. Passing this observation's own row id as the
    # evidence_links idempotence key would therefore record a fresh link
    # on every single pass for one ongoing match. `m.identity_key` is
    # osquery's own STABLE identity for "this port"/"this persistence
    # entry" (matches ExternalObservation.identity_key — see
    # crosscheck.py's Match), independent of which scan produced it, so
    # using it as logical_key means record_link() recognizes "still the
    # same relationship" across scans and touches (last_seen/times_seen)
    # the existing evidence_links row instead of duplicating it — while
    # integration_observations itself keeps logging every single scan,
    # untouched, per the user's explicit "do not suppress osquery
    # observation history" instruction.
    evidence_links_recorded = 0
    matches = []
    if LISTENING_PORTS not in failed_queries:
        matches.extend(find_listening_port_matches(conn, observations))
    if LAUNCHD not in failed_queries:
        matches.extend(find_persistence_matches(conn, observations))
    query_kind_by_match_kind = {"listening_port": LISTENING_PORTS, "persistence": LAUNCHD}
    for m in matches:
        query_kind = query_kind_by_match_kind.get(m.kind)
        observation_id = observation_id_by_key.get((query_kind, m.identity_key))
        if observation_id is None:
            continue
        try:
            _, created = record_link(
                conn,
                EvidenceLink(
                    from_ref=ObservationRef(
                        source_table="integration_observations",
                        source_id=observation_id,
                        logical_key=f"osquery:{m.kind}:{m.identity_key}",
                    ),
                    to_ref=ObservationRef(source_table=m.native_source_table, source_id=m.native_source_id),
                    relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION,
                    match_basis="structural_agreement",
                    detail=m.detail,
                    created_by="osquery_crosscheck",
                ),
            )
            if created:
                evidence_links_recorded += 1
        except Exception:  # noqa: BLE001 - defensive: enrichment must never fail the scan
            pass

    add_integration_run(
        conn,
        run_id=run_id,
        integration=INTEGRATION_NAME,
        started_at=now,
        completed_at=datetime.now(timezone.utc).isoformat(),
        status=overall_status,
        detail=detail,
        tool_version=health.tool_version,
        observations_collected=len(observations),
        alerts_generated=len(discrepancies),
    )

    return OsqueryScanResult(
        scanned_at=now,
        run_id=run_id,
        health=effective_health,
        observations=observations,
        discrepancies=discrepancies,
        failed_queries=failed_queries,
        evidence_links_recorded=evidence_links_recorded,
    )
