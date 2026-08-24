"""
integrations/zeek/scanner.py — orchestrates one Zeek ingestion pass:
check availability, read new records since each log type's own cursor,
normalize them, classify conn.log records for dedup-awareness against
Secure's own native connection_events and Suricata's ingested EVE
alerts, feed the two baseline-eligible observation kinds (DNS query
domains, TLS SNI hostnames) into Secure's behavioral-baseline layer,
and persist everything. The only file in this integration that touches
the database.

Phase 19's own instruction: "Distinguish: Suricata = detection/
signature evidence, Zeek = behavioral/protocol telemetry." This is
enforced structurally, not just by convention — this scanner NEVER
calls add_integration_alert() and this package has no severity/
detection-classification module at all (contrast with Suricata's
analysis.py). Every Zeek record that gets persisted becomes exactly one
`integration_observations` row (kind="conn"/"dns"/"ssl"/"http") and
nothing else; `secure integrations zeek alerts` does not exist as a
command (see cli/integrations.py) for the same reason Suricata has no
`rules` command — there is structurally nothing for it to list.
Because Zeek never writes integration_alerts, it also never becomes a
correlation Signal (secure/correlate/signals.py's _collect_integrations()
deliberately only reads integration_alerts — see that module's own
docstring) — Zeek evidence reaches the user through
`secure integrations zeek observations`, through the baseline/anomaly
layer for the two entity_types below, and through direct inspection,
never through an inflated "this is a detection" claim.

Baseline dampening ("without allowing bulk network noise to immediately
create mature baselines" — the phase's own explicit requirement): only
DNS query domains (dns.log) and TLS SNI hostnames (ssl.log) are fed
into the baseline layer, as the two new gap-filling entity_types
`dns_query`/`tls_sni` (secure/baseline/entities.py). conn.log and
http.log are intentionally NOT baselined — conn.log's real-world
"connection" identity is already covered by the existing
`process_destination` baseline dimension whenever a process can be
attributed (via Secure's native lsof-based connections scan); adding a
second, process-less baseline dimension for the exact same underlying
connections would duplicate history Phase 14's own design review
explicitly ruled out ("do not duplicate raw feature history that
already exists elsewhere" — extension approval item 3). http.log's own
Host header is largely the same identity dns.log's `query` domain
already captures, one layer up the stack, at higher cardinality and
lower interpretability (full URI/user-agent baselining) — so it is
normalized and persisted for visibility/correlation, but deliberately
not baselined this phase; see identity.py/parser.py's own docstrings.

For the two entity_types that ARE baselined, volume is bounded the
SAME way connections/scanner.py already bounds `process_destination`
volume: every distinct entity is folded into the baseline layer AT
MOST ONCE PER SCAN PASS, regardless of how many raw dns.log/ssl.log
records this pass ingested for it (a domain queried 500 times in one
pass still contributes exactly one observation to
baseline_entities.eligible_weight_total). Combined with Phase 14's own
maturity rule — an entity can only reach ESTABLISHED once it has been
seen on at least MIN_ELIGIBLE_DISTINCT_DAYS separate CALENDAR DAYS,
never merely enough raw volume (secure/baseline/constants.py) — this
means the rate a domain/hostname's baseline can mature is bounded by
how often `secure integrations zeek scan` itself runs, never by how
much traffic Zeek observed in one pass. No additional weight-capping
mechanism is invented beyond reusing this existing, already-approved
design.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Dict, List, Optional

from secure.baseline.engine import BaselineRunCounters, finalize_baseline_run
from secure.baseline.entities import DNS_QUERY, TLS_SNI, dns_query_key, tls_sni_key
from secure.baseline.history import record_gap_observation
from secure.config import AppConfig
from secure.evidence import (
    EvidenceLink,
    ObservationRef,
    RELATIONSHIP_SAME_EVENT_CONFIRMATION,
    record_link,
)
from secure.integrations.base import ExternalObservation, IntegrationHealth
from secure.integrations.zeek._logs import (
    CONN_LOG,
    DEFAULT_MAX_LINES,
    DNS_LOG,
    HTTP_LOG,
    SSL_LOG,
    read_zeek_log_lines,
)
from secure.integrations.zeek._timeutil import parse_zeek_timestamp
from secure.integrations.zeek.availability import check_availability
from secure.integrations.zeek.dedup import DEFAULT_DEDUP_WINDOW_SECONDS, classify_conn_dedup
from secure.integrations.zeek.identity import dns_query_domain, tls_sni_hostname
from secure.integrations.zeek.parser import (
    CONN_KIND,
    DNS_KIND,
    HTTP_KIND,
    SSL_KIND,
    parse_conn_record,
    parse_dns_record,
    parse_http_record,
    parse_ssl_record,
)
from secure.storage.models import add_integration_observations, add_integration_run, list_integration_observations

INTEGRATION_NAME = "zeek"


@dataclass
class ZeekScanResult:
    scanned_at: str
    run_id: str
    health: IntegrationHealth
    observations: List[ExternalObservation] = field(default_factory=list)
    malformed_lines_by_log: Dict[str, int] = field(default_factory=dict)
    dedup_counts: Dict[str, int] = field(default_factory=dict)
    baseline_entities_updated: int = 0
    baseline_anomalies_generated: int = 0
    evidence_links_recorded: int = 0

    @property
    def available(self) -> bool:
        return self.health.available

    @property
    def counts_by_kind(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for obs in self.observations:
            counts[obs.kind] = counts.get(obs.kind, 0) + 1
        return counts


_PARSERS = {
    CONN_LOG: (CONN_KIND, parse_conn_record),
    DNS_LOG: (DNS_KIND, parse_dns_record),
    SSL_LOG: (SSL_KIND, parse_ssl_record),
    HTTP_LOG: (HTTP_KIND, parse_http_record),
}


def _last_ingested_ts(conn: sqlite3.Connection, kind: str) -> "Optional[float]":
    """The latest numeric `ts` already ingested for one observation kind
    — the cursor for "only ingest newer records" filtering. Unlike
    Suricata's own string-timestamp cursor (safe because Suricata's EVE
    timestamps are fixed-width/zero-padded), Zeek's `ts` is a genuine
    JSON number, so the max must be computed numerically, not
    lexicographically — a plain string comparison of e.g. "9.5" vs
    "10.2" would be wrong. Sampled over the most recent 500 rows of this
    kind, same defensive-against-minor-reordering reasoning as
    Suricata's own cursor function.
    """
    observations = list_integration_observations(conn, integration=INTEGRATION_NAME, kind=kind, limit=500)
    values = []
    for o in observations:
        raw = o.fields.get("ts")
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            values.append(float(raw))
    return max(values) if values else None


def scan_zeek(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    *,
    max_lines: int = DEFAULT_MAX_LINES,
    dedup_window_seconds: float = DEFAULT_DEDUP_WINDOW_SECONDS,
) -> ZeekScanResult:
    """Run one Zeek log ingestion pass. An unavailable/error health
    check (no log directory configured, directory not found, or
    unreadable) short-circuits immediately — one integration_runs row
    is written and nothing else happens, the scan never looks like a
    clean success.

    A DEGRADED health (e.g. some but not all target logs present, or
    stale) does NOT short-circuit — whichever logs ARE present and
    readable are still ingested; DEGRADED only means overall coverage
    is incomplete right now, the same "do not treat a partial result as
    silently equivalent to a full clean pass" discipline every other
    integration in this codebase already applies.
    """
    started_at = datetime.now(timezone.utc)
    now = started_at.isoformat()
    run_id = uuid.uuid4().hex[:12]

    health = check_availability(cfg)
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
        return ZeekScanResult(scanned_at=now, run_id=run_id, health=health)

    log_dir = cfg.zeek_log_dir_resolved()

    all_observations: List[ExternalObservation] = []
    malformed_by_log: Dict[str, int] = {}
    dedup_counts: Dict[str, int] = {}

    for log_name, (kind, parse_fn) in _PARSERS.items():
        path = log_dir / log_name
        records, malformed = read_zeek_log_lines(path, max_lines=max_lines)
        if malformed:
            malformed_by_log[log_name] = malformed
        if not records:
            continue

        cursor = _last_ingested_ts(conn, kind)
        new_records = [
            r for r in records
            if cursor is None
            or (isinstance(r.get("ts"), (int, float)) and not isinstance(r.get("ts"), bool) and r["ts"] > cursor)
        ]

        for record in new_records:
            obs = parse_fn(record, now, str(path))
            if obs is None:
                continue
            if kind == CONN_KIND:
                dedup = classify_conn_dedup(conn, obs.fields, window_seconds=dedup_window_seconds)
                dedup_counts[dedup.status] = dedup_counts.get(dedup.status, 0) + 1
                augmented_fields = {
                    **obs.fields,
                    "dedup_status": dedup.status,
                    "dedup_detail": dedup.detail,
                    "dedup_matched_source_table": dedup.matched_source_table,
                    "dedup_matched_source_id": dedup.matched_source_id,
                }
                obs = replace(obs, fields=augmented_fields)
            all_observations.append(obs)

    rows_to_persist = [
        (o.kind, o.identity_key, o.fields, o.source_query, o.collected_at) for o in all_observations
    ]
    evidence_links_recorded = 0
    if rows_to_persist:
        new_ids = add_integration_observations(conn, run_id=run_id, integration=INTEGRATION_NAME, rows=rows_to_persist)
        # Phase 21 (additive): a conn.log record classify_conn_dedup()
        # already matched against native/Suricata evidence (see the
        # loop above — dedup_status/dedup_detail/dedup_matched_* are
        # already embedded in obs.fields, unchanged) additionally gets
        # a formal, queryable same_event_confirmation evidence_links
        # row now that its own real integration_observations.id exists
        # (only available AFTER persistence, hence this separate pass).
        # This is purely additive: dedup_status/dedup_detail and every
        # other observation field stay exactly as they already were;
        # nothing here changes what gets persisted to
        # integration_observations itself. A failure to record a link
        # is swallowed defensively — this is enrichment, never allowed
        # to turn a successful ingestion pass into a failed one.
        for obs, new_id in zip(all_observations, new_ids):
            if obs.kind != CONN_KIND:
                continue
            matched_table = obs.fields.get("dedup_matched_source_table")
            matched_id = obs.fields.get("dedup_matched_source_id")
            if matched_table is None or matched_id is None:
                continue
            try:
                _, created = record_link(
                    conn,
                    EvidenceLink(
                        from_ref=ObservationRef(source_table="integration_observations", source_id=new_id),
                        to_ref=ObservationRef(source_table=matched_table, source_id=matched_id),
                        relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION,
                        match_basis="identity+timing",
                        detail=obs.fields.get("dedup_detail") or "Matched via identity+timing.",
                        created_by="zeek_dedup",
                    ),
                )
                if created:
                    evidence_links_recorded += 1
            except Exception:  # noqa: BLE001 - defensive: enrichment must never fail the scan
                pass

    # ---- Baseline layer: dns_query / tls_sni only, deduped to at most
    # one entity per distinct domain/hostname THIS SCAN PASS — mirrors
    # connections/scanner.py's own process_destination dedup-within-a-
    # scan discipline exactly (see this module's own docstring).
    baseline_counters = BaselineRunCounters()
    seen_domains: Dict[str, str] = {}  # domain -> latest observed_at ISO string this pass
    seen_hostnames: Dict[str, str] = {}
    for obs in all_observations:
        if obs.kind == DNS_KIND:
            domain = dns_query_domain(obs.fields)
            if domain is None:
                continue
            ts = parse_zeek_timestamp(obs.fields.get("ts"))
            if ts is None:
                continue
            observed_at = ts.isoformat()
            if domain not in seen_domains or observed_at > seen_domains[domain]:
                seen_domains[domain] = observed_at
        elif obs.kind == SSL_KIND:
            hostname = tls_sni_hostname(obs.fields)
            if hostname is None:
                continue
            ts = parse_zeek_timestamp(obs.fields.get("ts"))
            if ts is None:
                continue
            observed_at = ts.isoformat()
            if hostname not in seen_hostnames or observed_at > seen_hostnames[hostname]:
                seen_hostnames[hostname] = observed_at

    for domain, observed_at in seen_domains.items():
        try:
            record_gap_observation(
                conn, run_id, DNS_QUERY, dns_query_key(domain), observed_at, counters=baseline_counters,
            )
        except Exception as exc:  # noqa: BLE001 - defensive, see baseline_runs.errors_count
            baseline_counters.record_error(f"dns_query baseline evaluation failed for {domain!r}: {exc}")

    for hostname, observed_at in seen_hostnames.items():
        try:
            record_gap_observation(
                conn, run_id, TLS_SNI, tls_sni_key(hostname), observed_at, counters=baseline_counters,
            )
        except Exception as exc:  # noqa: BLE001
            baseline_counters.record_error(f"tls_sni baseline evaluation failed for {hostname!r}: {exc}")

    finalize_baseline_run(conn, run_id, started_at, baseline_counters)

    detail_parts = [health.detail, f"observations={len(all_observations)}"]
    if dedup_counts:
        detail_parts.append(
            "conn dedup: " + ", ".join(f"{k}={v}" for k, v in sorted(dedup_counts.items()))
        )
    if malformed_by_log:
        detail_parts.append(
            "malformed lines: " + ", ".join(f"{k}={v}" for k, v in sorted(malformed_by_log.items()))
        )
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
        observations_collected=len(all_observations),
        alerts_generated=0,  # Zeek never produces integration_alerts — see module docstring
    )

    return ZeekScanResult(
        scanned_at=now,
        run_id=run_id,
        health=health,
        observations=all_observations,
        malformed_lines_by_log=malformed_by_log,
        dedup_counts=dedup_counts,
        baseline_entities_updated=baseline_counters.entities_updated,
        baseline_anomalies_generated=baseline_counters.anomalies_generated,
        evidence_links_recorded=evidence_links_recorded,
    )
