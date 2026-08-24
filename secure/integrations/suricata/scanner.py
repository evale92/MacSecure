"""
integrations/suricata/scanner.py — orchestrates one Suricata ingestion
pass: check availability/packet-visibility health, read new EVE alert
records since the last ingested alert, correlate each against Secure's
own native connection_events (best-effort, honest about absence), and
persist everything. The only file in this integration that touches the
database.

Every genuine alert record becomes both an `integration_observations`
row (kind="eve_alert", full normalized fields, including whatever
process-correlation outcome was found) AND an `integration_alerts` row
— unlike Sigma's "always persist status, alert only on match" split,
there is no "rule checked, nothing matched" concept here: Suricata's
own engine already did that filtering before writing anything to
eve.json at all, so every alert record IS already a genuine finding
(same "already filtered by the source" reasoning YARA-X's own "zero
matches = zero observations" convention relies on, just applied one
step earlier in the pipeline). One additional `capture_stats`
observation (no accompanying alert — it's health telemetry, not a
finding) is persisted once per scan pass so packet-visibility history
is inspectable via `secure integrations suricata observations`.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from secure.config import AppConfig
from secure.evidence import (
    EvidenceLink,
    ObservationRef,
    RELATIONSHIP_DERIVED_EVIDENCE,
    record_link,
)
from secure.integrations.base import ExternalObservation, IntegrationHealth
from secure.integrations.suricata._eve import DEFAULT_MAX_LINES, iter_by_event_type, read_eve_lines
from secure.integrations.suricata.analysis import classify_suricata_severity
from secure.integrations.suricata.availability import check_availability
from secure.integrations.suricata.correlate import (
    DEFAULT_CORRELATION_WINDOW_SECONDS,
    describe_correlation,
    find_process_correlation,
)
from secure.integrations.suricata.parser import (
    ALERT_KIND,
    CAPTURE_STATS_KIND,
    extract_latest_capture_stats,
    parse_alert_record,
)
from secure.storage.models import (
    add_integration_alert,
    add_integration_observations,
    add_integration_run,
    list_integration_observations,
)

INTEGRATION_NAME = "suricata"
NETWORK_ALERT = "network_alert"


@dataclass(frozen=True)
class SuricataFinding:
    severity: str
    identity_key: str
    signature: str
    message: str


@dataclass
class SuricataScanResult:
    scanned_at: str
    run_id: str
    health: IntegrationHealth
    new_alert_observations: List[ExternalObservation] = field(default_factory=list)
    malformed_lines: int = 0
    skipped_records: int = 0
    findings: List[SuricataFinding] = field(default_factory=list)
    capture_stats: "Optional[dict]" = None
    evidence_links_recorded: int = 0

    @property
    def available(self) -> bool:
        return self.health.available


def _last_ingested_alert_timestamp(conn: sqlite3.Connection) -> "Optional[str]":
    """The latest Suricata-own `timestamp` string among already-ingested
    alert observations — used as the cursor for "only ingest newer
    alerts" filtering, so re-scanning the same eve.json tail doesn't
    re-persist alerts already recorded. Suricata's timestamp strings are
    fixed-width/zero-padded for a consistent offset, so a plain string
    max is a valid stand-in for a real timestamp comparison here.
    Sampled over the most recent 500 rows rather than just 1, defensive
    against any minor out-of-order arrival within one ingest batch.
    """
    observations = list_integration_observations(
        conn, integration=INTEGRATION_NAME, kind=ALERT_KIND, limit=500
    )
    timestamps = [o.fields.get("timestamp") for o in observations if o.fields.get("timestamp")]
    return max(timestamps) if timestamps else None


def _build_alert_message(fields: dict, severity: str, correlation_note: str) -> str:
    who = f"{fields.get('src_ip')}:{fields.get('src_port')}" if fields.get("src_ip") else "?"
    dest = f"{fields.get('dest_ip')}:{fields.get('dest_port')}" if fields.get("dest_ip") else "?"
    factual = (
        f"Suricata signature '{fields.get('signature')}' (category: "
        f"{fields.get('category') or 'uncategorized'}) fired on {fields.get('proto')} traffic "
        f"{who} -> {dest} at {fields.get('timestamp')}."
    )
    caveat = (
        "This is Suricata's own detection engine reporting a signature match — Secure did "
        "not independently evaluate this traffic and does not reproduce Suricata's own "
        "detection logic."
    )
    return f"{factual} {caveat} {correlation_note}"


def scan_suricata(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    *,
    max_lines: int = DEFAULT_MAX_LINES,
    correlation_window_seconds: float = DEFAULT_CORRELATION_WINDOW_SECONDS,
) -> SuricataScanResult:
    """Run one Suricata EVE ingestion pass. An unavailable/error health
    check (no log configured, log not found, or unreadable) short-
    circuits immediately — one integration_runs row is written and
    nothing else happens, the scan never looks like a clean success.

    A DEGRADED health (e.g. packet visibility not currently confirmed)
    does NOT short-circuit — genuinely logged alerts already in the
    tail are still real findings worth surfacing; DEGRADED only means
    the ABSENCE of new alerts can't be read as "nothing happened."
    """
    started_at = datetime.now(timezone.utc)
    now = started_at.isoformat()
    run_id = uuid.uuid4().hex[:12]

    health = check_availability(cfg, max_lines=max_lines)
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
        return SuricataScanResult(scanned_at=now, run_id=run_id, health=health)

    path = cfg.suricata_eve_log_path_resolved()
    records, malformed = read_eve_lines(path, max_lines=max_lines)

    cursor = _last_ingested_alert_timestamp(conn)
    all_alert_records = list(iter_by_event_type(records, "alert"))
    new_alert_records = [
        r for r in all_alert_records if cursor is None or (r.get("timestamp") or "") > cursor
    ]

    new_observations: List[ExternalObservation] = []
    skipped_records = 0
    for record in new_alert_records:
        obs = parse_alert_record(record, now, str(path))
        if obs is None:
            skipped_records += 1
            continue
        new_observations.append(obs)

    capture_stats = extract_latest_capture_stats(records)

    rows_to_persist: List[tuple] = [
        (o.kind, o.identity_key, o.fields, o.source_query, o.collected_at) for o in new_observations
    ]
    if capture_stats is not None:
        rows_to_persist.append(
            (
                CAPTURE_STATS_KIND,
                capture_stats.get("timestamp") or "unknown",
                capture_stats,
                f"eve.json stats record ({path})",
                now,
            )
        )

    observation_ids: List[int] = (
        add_integration_observations(conn, run_id=run_id, integration=INTEGRATION_NAME, rows=rows_to_persist)
        if rows_to_persist
        else []
    )
    # rows_to_persist and observation_ids share order by construction
    # (add_integration_observations() preserves input order — see its
    # own docstring); the first len(new_observations) ids belong to the
    # alert observations, in the same order as new_observations.
    alert_observation_ids = observation_ids[: len(new_observations)]

    findings: List[SuricataFinding] = []
    evidence_links_recorded = 0
    for obs, observation_id in zip(new_observations, alert_observation_ids):
        correlation = find_process_correlation(
            conn, obs.fields, window_seconds=correlation_window_seconds
        )
        correlation_note = describe_correlation(correlation)
        severity = classify_suricata_severity(obs.fields.get("severity"))
        message = _build_alert_message(obs.fields, severity, correlation_note)

        alert_id = add_integration_alert(
            conn,
            run_id=run_id,
            integration=INTEGRATION_NAME,
            kind=NETWORK_ALERT,
            discrepancy="match",  # no native comparison side — mirrors yarax/sigma's own constant
            severity=severity,
            identity_key=obs.identity_key,
            label=obs.fields.get("signature"),
            message=message,
            source_observation_id=observation_id,
        )
        findings.append(
            SuricataFinding(
                severity=severity,
                identity_key=obs.identity_key,
                signature=obs.fields.get("signature") or "",
                message=message,
            )
        )

        # Phase 21 (additive): when find_process_correlation() above
        # found a genuine match, additionally record a formal, queryable
        # derived_evidence evidence_links row — the alert's own process
        # context (already embedded in `message` via correlation_note,
        # unchanged) is DERIVED FROM the matched connection_events row,
        # not a duplicate of it and not a second engine independently
        # confirming the same event. Nothing about the alert's own
        # message/severity/fields changes because of this; a failure to
        # record the link is swallowed defensively, same discipline as
        # Zeek's own Stage 3 wiring.
        if correlation is not None:
            try:
                _, created = record_link(
                    conn,
                    EvidenceLink(
                        from_ref=ObservationRef(source_table="integration_alerts", source_id=alert_id),
                        to_ref=ObservationRef(
                            source_table="connection_events", source_id=correlation.connection_event_id,
                        ),
                        relationship=RELATIONSHIP_DERIVED_EVIDENCE,
                        match_basis="identity+timing",
                        detail=correlation_note,
                        created_by="suricata_correlate",
                        time_delta_seconds=correlation.time_delta_seconds,
                    ),
                )
                if created:
                    evidence_links_recorded += 1
            except Exception:  # noqa: BLE001 - defensive: enrichment must never fail the scan
                pass

    detail_parts = [
        health.detail,
        f"new_alerts={len(new_observations)}",
    ]
    if skipped_records:
        detail_parts.append(f"skipped_malformed_alert_records={skipped_records}")
    if malformed:
        detail_parts.append(f"unparseable_log_lines={malformed}")
    detail = "; ".join(detail_parts)

    add_integration_run(
        conn,
        run_id=run_id,
        integration=INTEGRATION_NAME,
        started_at=now,
        completed_at=datetime.now(timezone.utc).isoformat(),
        status=health.status,
        detail=detail,
        tool_version=health.tool_version,
        observations_collected=len(observation_ids),
        alerts_generated=len(findings),
    )

    return SuricataScanResult(
        scanned_at=now,
        run_id=run_id,
        health=health,
        new_alert_observations=new_observations,
        malformed_lines=malformed,
        skipped_records=skipped_records,
        findings=findings,
        capture_stats=capture_stats,
        evidence_links_recorded=evidence_links_recorded,
    )
