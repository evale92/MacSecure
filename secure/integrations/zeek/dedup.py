"""
integrations/zeek/dedup.py — Phase 19's own explicit requirement:
"Implement dedup awareness for network events already seen by Secure or
Suricata." Classifies one Zeek conn.log observation against two other
evidence sources for the exact same kind of fact (a network
connection/flow):

    1. Secure's own native connection_events (from lsof-based active
       connection scans — secure/connections/).
    2. Suricata's own ingested EVE alert observations (Phase 18 —
       integration_observations where integration="suricata",
       kind="eve_alert").

Only conn.log records get this classification — dns.log/ssl.log/
http.log records describe protocol-level facts ABOUT a connection Zeek
already assigned a `uid` to (and that connection's own conn.log entry,
when present in the same ingestion batch, already carries the dedup
verdict for "is this connection itself already known elsewhere") rather
than being separate network events in their own right. Re-running the
same identity+timing match for three more log types would not surface
any additional dedup information conn.log's own classification doesn't
already capture.

This module does NOT decide anything is "wrong," "malicious," or
"unauthorized" — it only classifies awareness: was this connection
ALREADY visible to Secure through another source. `dedup.py` never
writes an alert (see scanner.py/__init__.py's module docstrings on why
Zeek never produces integration_alerts rows). The classification is
stored directly inside the persisted conn observation's own fields, so
"was this connection novel to Zeek alone, or corroborated elsewhere" is
inspectable per-observation without a second query.

Same conservative dual-constraint (IDENTITY AND TIMING) matching
discipline as Suricata's own correlate.py — a match requires both an
exact (remote_addr, remote_port, proto) identity match AND a timestamp
within a bounded window, tried against both the conn.log record's
"orig" and "resp" sides (Zeek's own record doesn't indicate which side
is "this Mac" any more than Suricata's does).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from secure.integrations.zeek._timeutil import parse_zeek_timestamp
from secure.storage.models import list_integration_observations, list_recent_connection_events

DEFAULT_DEDUP_WINDOW_SECONDS = 300.0

NOVEL = "novel"
MATCHES_NATIVE_CONNECTION = "matches_native_connection"
MATCHES_SURICATA_ALERT = "matches_suricata_alert"


@dataclass(frozen=True)
class DedupResult:
    status: str  # NOVEL / MATCHES_NATIVE_CONNECTION / MATCHES_SURICATA_ALERT
    detail: str
    matched_source_table: "Optional[str]" = None
    matched_source_id: "Optional[int]" = None


def _parse_native_timestamp(value: str) -> "Optional[datetime]":
    """connection_events.created_at is Secure's own ISO-8601
    datetime.now(timezone.utc).isoformat() output — datetime.fromisoformat()
    handles it natively, same as Suricata's correlate.py's own helper.
    """
    try:
        dt = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_suricata_alert_timestamp(value) -> "Optional[datetime]":
    """Lazily imports Suricata's own EVE timestamp parser — avoids a
    module-load-time cross-integration dependency (each integration
    package is otherwise self-contained); only needed at the moment a
    conn.log record's timing is actually being checked against Suricata
    evidence.
    """
    from secure.integrations.suricata._timeutil import parse_suricata_timestamp

    return parse_suricata_timestamp(value)


def _candidate_sides(fields: dict) -> "list[tuple[str, object, object]]":
    sides = []
    orig_h, orig_p = fields.get("orig_h"), fields.get("orig_p")
    resp_h, resp_p = fields.get("resp_h"), fields.get("resp_p")
    if orig_h and orig_p is not None:
        sides.append(("orig", orig_h, orig_p))
    if resp_h and resp_p is not None:
        sides.append(("resp", resp_h, resp_p))
    return sides


def classify_conn_dedup(
    conn: sqlite3.Connection,
    conn_fields: dict,
    *,
    window_seconds: float = DEFAULT_DEDUP_WINDOW_SECONDS,
) -> DedupResult:
    """Classify one conn.log observation's own `fields` dict (as built
    by parser.parse_conn_record) against native connection_events and
    Suricata's ingested EVE alerts. Checked in that order — a native
    match is reported even when a Suricata match also exists, since
    Secure's own native visibility is the more directly relevant "did
    Secure already know about this" fact; a caller wanting the full
    picture can still inspect Suricata's own observations separately.

    Returns NOVEL (never raises) whenever the record's own timestamp
    can't be parsed, or no candidate row matches both identity and
    timing in either source — "novel to Zeek" is itself a genuine,
    useful classification (Zeek may see connections lsof-based polling
    misses between scans, and connections Suricata has no signature
    reason to alert on), not a fallback/error state.
    """
    ts = parse_zeek_timestamp(conn_fields.get("ts"))
    if ts is None:
        return DedupResult(status=NOVEL, detail="Connection record has no usable timestamp to correlate.")

    proto = (conn_fields.get("proto") or "").upper()
    sides = _candidate_sides(conn_fields)
    if not sides:
        return DedupResult(status=NOVEL, detail="Connection record has no usable endpoint identity to correlate.")

    if proto in ("TCP", "UDP"):
        since = (ts - timedelta(seconds=window_seconds)).isoformat()
        native_events = list_recent_connection_events(conn, since=since, limit=2000)
        for side_label, ip, port in sides:
            for ev in native_events:
                if ev.proto != proto or ev.remote_addr != ip or ev.remote_port != port:
                    continue
                ev_ts = _parse_native_timestamp(ev.created_at)
                if ev_ts is None or abs((ev_ts - ts).total_seconds()) > window_seconds:
                    continue
                return DedupResult(
                    status=MATCHES_NATIVE_CONNECTION,
                    detail=(
                        f"Matches Secure's own native connection observation "
                        f"(#{ev.id}, {side_label} side, {abs((ev_ts - ts).total_seconds()):.0f}s "
                        "from this record's timestamp)."
                    ),
                    matched_source_table="connection_events",
                    matched_source_id=ev.id,
                )

    # Suricata evidence: check regardless of protocol, since Suricata's
    # own `proto` string vocabulary isn't guaranteed to line up exactly
    # (e.g. ICMP), and Suricata alerts on non-TCP/UDP traffic are still
    # legitimate corroboration to surface.
    lookback_since = (ts - timedelta(seconds=window_seconds)).isoformat()
    suricata_observations = list_integration_observations(
        conn, integration="suricata", kind="eve_alert", since=lookback_since, limit=1000
    )
    for obs in suricata_observations:
        alert_fields = obs.fields
        alert_ts = _parse_suricata_alert_timestamp(alert_fields.get("timestamp"))
        if alert_ts is None or abs((alert_ts - ts).total_seconds()) > window_seconds:
            continue
        alert_proto = (alert_fields.get("proto") or "").upper()
        if proto and alert_proto and alert_proto != proto:
            continue
        for side_label, ip, port in sides:
            src_match = alert_fields.get("src_ip") == ip and alert_fields.get("src_port") == port
            dest_match = alert_fields.get("dest_ip") == ip and alert_fields.get("dest_port") == port
            if src_match or dest_match:
                return DedupResult(
                    status=MATCHES_SURICATA_ALERT,
                    detail=(
                        f"Matches a Suricata EVE alert already ingested by Secure "
                        f"(observation #{obs.id}, {side_label} side, "
                        f"{abs((alert_ts - ts).total_seconds()):.0f}s from this record's timestamp): "
                        f"signature {alert_fields.get('signature')!r}."
                    ),
                    matched_source_table="integration_observations",
                    matched_source_id=obs.id,
                )

    return DedupResult(
        status=NOVEL,
        detail="No matching native connection observation or ingested Suricata alert found near this record's timestamp.",
    )
