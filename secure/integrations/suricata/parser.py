"""
integrations/suricata/parser.py — turns raw EVE JSON records (already
parsed from text by _eve.py) into this integration's normalized
ExternalObservation shape, and extracts the latest packet-capture stats
snapshot used by availability.py to judge packet visibility honestly.

Pure functions only: dict in, dict/ExternalObservation out — no file
I/O, no database access, directly testable with hand-built EVE records.

Deliberately narrow field selection (Phase 18: normalize "timestamp,
signature/rule, category/severity, source/destination, protocol/flow
identity, ... exact source provenance" — nothing more). An `alert`
record can carry much more (full HTTP/TLS/file metadata, and — if
Suricata's own `payload`/`packet` output options are enabled — raw
packet bytes); none of that is ingested here, both to keep this
integration's scope exactly what the phase asked for and to avoid
pulling potentially large/sensitive packet contents into Secure's own
database by accident.
"""

from __future__ import annotations

from typing import Optional

from secure.integrations.base import ExternalObservation

ALERT_KIND = "eve_alert"
CAPTURE_STATS_KIND = "capture_stats"


def _identity_key(record: dict, alert: dict) -> str:
    """As unique as Suricata's own EVE output gets for one alert
    occurrence — there is no true per-alert UUID in the format. flow_id
    scopes it to one network flow, (gid, signature_id, rev) scopes it to
    one exact rule revision, and the record's own timestamp
    distinguishes repeat firings of the same rule on the same flow.
    """
    flow_id = record.get("flow_id", "noflow")
    gid = alert.get("gid", "?")
    signature_id = alert.get("signature_id", "?")
    rev = alert.get("rev", "?")
    timestamp = record.get("timestamp", "?")
    return f"{flow_id}:{gid}:{signature_id}:{rev}:{timestamp}"


def parse_alert_record(
    record: dict, collected_at: str, source_path: str
) -> "Optional[ExternalObservation]":
    """Normalize one EVE `event_type: "alert"` record. Returns None
    (never raises) if the record is missing fields this integration
    treats as required (timestamp, an `alert` object with a
    signature) — callers count that as a malformed/skipped record, the
    same "one bad item doesn't abort the batch" discipline
    _eve.read_eve_lines() already applies to unparseable lines.
    """
    if record.get("event_type") != "alert":
        return None

    timestamp = record.get("timestamp")
    alert = record.get("alert")
    if not timestamp or not isinstance(alert, dict) or not alert.get("signature"):
        return None

    fields = {
        "timestamp": timestamp,
        "flow_id": record.get("flow_id"),
        "in_iface": record.get("in_iface"),
        "src_ip": record.get("src_ip"),
        "src_port": record.get("src_port"),
        "dest_ip": record.get("dest_ip"),
        "dest_port": record.get("dest_port"),
        "proto": record.get("proto"),
        "signature": alert.get("signature"),
        "signature_id": alert.get("signature_id"),
        "gid": alert.get("gid"),
        "rev": alert.get("rev"),
        "category": alert.get("category"),
        "severity": alert.get("severity"),
        "action": alert.get("action"),
    }

    return ExternalObservation(
        kind=ALERT_KIND,
        identity_key=_identity_key(record, alert),
        fields=fields,
        source_query=f"eve.json alert record ({source_path})",
        collected_at=collected_at,
    )


def extract_latest_capture_stats(records: "list[dict]") -> "Optional[dict]":
    """The most recent `event_type: "stats"` record's own capture
    counters, or None if no stats event was found at all in this read —
    itself a meaningful, honest signal (see availability.py) rather
    than something to silently default to zero.

    `kernel_packets`/`kernel_drops` come from `stats.capture` — present
    for AF_PACKET and most other capture methods; `decoder_pkts` from
    `stats.decoder.pkts`, Suricata's own total-decoded-packet counter,
    used as a fallback signal when a capture method doesn't expose
    kernel_packets. Any field genuinely absent from the record is
    reported as None, never coerced to 0 — a missing field and a
    confirmed zero mean different things here.
    """
    latest = None
    for record in records:
        if record.get("event_type") == "stats":
            latest = record

    if latest is None:
        return None

    stats = latest.get("stats") or {}
    capture = stats.get("capture") or {}
    decoder = stats.get("decoder") or {}

    return {
        "timestamp": latest.get("timestamp"),
        "kernel_packets": capture.get("kernel_packets"),
        "kernel_drops": capture.get("kernel_drops"),
        "decoder_pkts": decoder.get("pkts"),
    }
