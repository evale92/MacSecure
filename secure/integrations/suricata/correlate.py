"""
integrations/suricata/correlate.py — attaches Secure's own native
process/connection context to a Suricata alert WHEN, AND ONLY WHEN, a
genuine identity+timing match against connection_events is found.

Phase 18's explicit instruction: "Correlate Suricata evidence with
Secure's process/connection context when identity and timing support
it, but do not claim process attribution unless it is actually
established." This module is the one place that decision gets made,
and it is deliberately conservative in both directions this instruction
implies:

    - IDENTITY: matched by exact (remote_addr, remote_port, proto)
      against connection_events — tried against BOTH the alert's src
      and dest ip/port (Suricata's EVE record doesn't itself tell you
      which side is "this Mac"; connection_events' own `remote_addr` is
      always the non-local side regardless of direction, so trying both
      sides and taking whichever matches is the correct, honest check
      rather than guessing directionality).
    - TIMING: the connection_events row must fall within a bounded
      window of the alert's own timestamp (default +/-300s) — native
      connection scans run periodically, not continuously, so an exact
      timestamp match is not realistic; a window is, but it is still a
      REAL bound, not "any connection ever recorded for this
      destination" (that would routinely misattribute one process's
      alert to a different, unrelated process that happened to talk to
      the same remote endpoint at a different time).

No match within both constraints returns None. Callers (scanner.py,
integration_explainer.py) are required to say so explicitly ("no
process attribution established") rather than silently omitting the
field — the same "absence is a fact, not a gap to paper over" discipline
this codebase already applies to e.g. Sigma's NOT_EVALUABLE status.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from secure.integrations.suricata._timeutil import parse_suricata_timestamp
from secure.storage.models import list_recent_connection_events

DEFAULT_CORRELATION_WINDOW_SECONDS = 300.0


@dataclass(frozen=True)
class ProcessCorrelation:
    connection_event_id: int
    pid: "Optional[int]"
    process_name: "Optional[str]"
    matched_side: str  # "src" or "dest" — which alert endpoint matched connection_events.remote_*
    time_delta_seconds: float


def _parse_native_timestamp(value: str) -> "Optional[datetime]":
    """connection_events.created_at is Secure's own
    datetime.now(timezone.utc).isoformat() output (colon-delimited UTC
    offset), which datetime.fromisoformat() handles natively on every
    Python version this project targets — unlike Suricata's own
    timestamp format, which needs _timeutil.parse_suricata_timestamp().
    """
    try:
        dt = datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def find_process_correlation(
    conn: sqlite3.Connection,
    alert_fields: dict,
    window_seconds: float = DEFAULT_CORRELATION_WINDOW_SECONDS,
) -> "Optional[ProcessCorrelation]":
    """Look for one native connection_events row matching this alert's
    network identity within `window_seconds` of its own timestamp.
    Returns None whenever timing can't be established at all (an
    unparseable alert timestamp), the protocol isn't one
    connection_events tracks (TCP/UDP only), or no candidate row
    matches both identity and timing — never a best-effort guess.
    """
    alert_ts = parse_suricata_timestamp(alert_fields.get("timestamp"))
    if alert_ts is None:
        return None

    proto = (alert_fields.get("proto") or "").upper()
    if proto not in ("TCP", "UDP"):
        return None

    candidate_sides = []
    src_ip, src_port = alert_fields.get("src_ip"), alert_fields.get("src_port")
    dest_ip, dest_port = alert_fields.get("dest_ip"), alert_fields.get("dest_port")
    if src_ip and src_port:
        candidate_sides.append(("src", src_ip, src_port))
    if dest_ip and dest_port:
        candidate_sides.append(("dest", dest_ip, dest_port))
    if not candidate_sides:
        return None

    since = (alert_ts - timedelta(seconds=window_seconds)).isoformat()
    events = list_recent_connection_events(conn, since=since, limit=2000)

    best: "Optional[ProcessCorrelation]" = None
    best_delta = None

    for side_label, ip, port in candidate_sides:
        for ev in events:
            if ev.proto != proto:
                continue
            if ev.remote_addr != ip or ev.remote_port != port:
                continue
            ev_ts = _parse_native_timestamp(ev.created_at)
            if ev_ts is None:
                continue
            delta = abs((ev_ts - alert_ts).total_seconds())
            if delta > window_seconds:
                continue
            if best is None or delta < best_delta:
                best = ProcessCorrelation(
                    connection_event_id=ev.id,
                    pid=ev.pid,
                    process_name=ev.process_name,
                    matched_side=side_label,
                    time_delta_seconds=delta,
                )
                best_delta = delta

    return best


def describe_correlation(correlation: "Optional[ProcessCorrelation]") -> str:
    """One-sentence, honest description of the correlation outcome —
    used directly in the alert's message so the "not established" case
    is as visible as a genuine match, never silently dropped.
    """
    if correlation is None:
        return (
            "No matching native connection observation was found near this alert's "
            "timestamp — process attribution is not established for this alert."
        )
    who = correlation.process_name or (
        f"pid {correlation.pid}" if correlation.pid is not None else "an unidentified process"
    )
    return (
        f"Correlated with Secure's own native connection observation "
        f"(#{correlation.connection_event_id}, {correlation.time_delta_seconds:.0f}s from this "
        f"alert's timestamp), attributed to {who}."
    )
