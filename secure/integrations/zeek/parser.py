"""
integrations/zeek/parser.py — turns raw Zeek JSON log records (already
parsed from text by _logs.py) into this integration's normalized
ExternalObservation shape. Pure functions only: dict in,
ExternalObservation out — no file I/O, no database access, directly
testable with hand-built Zeek records.

Deliberately narrow field selection, matching Phase 19's own
instruction to normalize "with exact source and event provenance" —
one function per log type, each selecting only the fields with genuine
behavioral/telemetry value, not a 1:1 dump of everything Zeek can log
(some Zeek deployments add many optional fields via extra scripts;
none of that is ingested here).

Every record's `uid` — Zeek's own stable per-connection identifier — is
the identity this integration keys observations on: it's what ties a
dns.log/ssl.log/http.log record back to the conn.log entry for the
same underlying connection, and it's the natural, honest identity_key
for an ExternalObservation (a real Zeek-native identifier, not a
Secure-invented composite).
"""

from __future__ import annotations

from typing import Optional

from secure.integrations.base import ExternalObservation

CONN_KIND = "conn"
DNS_KIND = "dns"
SSL_KIND = "ssl"
HTTP_KIND = "http"


def _endpoint_fields(record: dict) -> dict:
    """Zeek's JSON log writer nests connection-identity fields under an
    `id` object (`id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`) —
    "orig" is the connection originator, "resp" the responder; which
    side is "this Mac" is not indicated by the record itself, the same
    ambiguity Suricata's own src/dest fields have (see
    dedup.py/scanner.py, which check both sides against Secure's native
    connection_events, same as Suricata's correlate.py does). Falls
    back to flattened `id.orig_h`-style keys defensively, in case a
    non-default Zeek log-writer configuration flattens instead of
    nesting.
    """
    identity = record.get("id")
    if isinstance(identity, dict):
        return {
            "orig_h": identity.get("orig_h"),
            "orig_p": identity.get("orig_p"),
            "resp_h": identity.get("resp_h"),
            "resp_p": identity.get("resp_p"),
        }
    return {
        "orig_h": record.get("id.orig_h"),
        "orig_p": record.get("id.orig_p"),
        "resp_h": record.get("id.resp_h"),
        "resp_p": record.get("id.resp_p"),
    }


def parse_conn_record(record: dict, collected_at: str, source_path: str) -> "Optional[ExternalObservation]":
    """Normalize one conn.log record. Returns None (never raises) if
    the record is missing `ts` or `uid` — both required for identity,
    dedup-awareness, and any later baseline/correlation use.
    """
    ts = record.get("ts")
    uid = record.get("uid")
    if ts is None or not uid:
        return None

    fields = {
        "ts": ts,
        "uid": uid,
        **_endpoint_fields(record),
        "proto": record.get("proto"),
        "service": record.get("service"),
        "duration": record.get("duration"),
        "orig_bytes": record.get("orig_bytes"),
        "resp_bytes": record.get("resp_bytes"),
        "conn_state": record.get("conn_state"),
        "missed_bytes": record.get("missed_bytes"),
        "history": record.get("history"),
        "orig_pkts": record.get("orig_pkts"),
        "resp_pkts": record.get("resp_pkts"),
    }
    return ExternalObservation(
        kind=CONN_KIND,
        identity_key=uid,
        fields=fields,
        source_query=f"conn.log record uid={uid} ({source_path})",
        collected_at=collected_at,
    )


def parse_dns_record(record: dict, collected_at: str, source_path: str) -> "Optional[ExternalObservation]":
    """Normalize one dns.log record. Returns None if missing `ts`,
    `uid`, or a query domain — a DNS log line with no `query` field
    (e.g. a malformed/truncated packet Zeek still logged something
    about) has nothing meaningful to baseline or report.
    """
    ts = record.get("ts")
    uid = record.get("uid")
    query = record.get("query")
    if ts is None or not uid or not query:
        return None

    fields = {
        "ts": ts,
        "uid": uid,
        **_endpoint_fields(record),
        "proto": record.get("proto"),
        "query": query,
        "qtype_name": record.get("qtype_name"),
        "rcode_name": record.get("rcode_name"),
        "answers": record.get("answers"),
        "rejected": record.get("rejected"),
    }
    return ExternalObservation(
        kind=DNS_KIND,
        identity_key=uid,
        fields=fields,
        source_query=f"dns.log record uid={uid} ({source_path})",
        collected_at=collected_at,
    )


def parse_ssl_record(record: dict, collected_at: str, source_path: str) -> "Optional[ExternalObservation]":
    """Normalize one ssl.log (TLS) record. Returns None if missing `ts`
    or `uid`. `server_name` (the TLS SNI hostname) is frequently absent
    (older TLS, session resumption, non-SNI clients) — that's a normal,
    honest gap, not a parse failure, so it's carried through as
    possibly-None rather than excluding the record.
    """
    ts = record.get("ts")
    uid = record.get("uid")
    if ts is None or not uid:
        return None

    fields = {
        "ts": ts,
        "uid": uid,
        **_endpoint_fields(record),
        "version": record.get("version"),
        "cipher": record.get("cipher"),
        "server_name": record.get("server_name"),
        "established": record.get("established"),
        "validation_status": record.get("validation_status"),
    }
    return ExternalObservation(
        kind=SSL_KIND,
        identity_key=uid,
        fields=fields,
        source_query=f"ssl.log record uid={uid} ({source_path})",
        collected_at=collected_at,
    )


def parse_http_record(record: dict, collected_at: str, source_path: str) -> "Optional[ExternalObservation]":
    """Normalize one http.log record. Returns None if missing `ts` or
    `uid`. Observation-only (see scanner.py/__init__.py's module
    docstrings for why HTTP is not fed into the baseline layer this
    phase) — still normalized and persisted with full provenance so it
    remains available for manual review and future correlation.
    """
    ts = record.get("ts")
    uid = record.get("uid")
    if ts is None or not uid:
        return None

    fields = {
        "ts": ts,
        "uid": uid,
        **_endpoint_fields(record),
        "method": record.get("method"),
        "host": record.get("host"),
        "uri": record.get("uri"),
        "status_code": record.get("status_code"),
        "user_agent": record.get("user_agent"),
    }
    return ExternalObservation(
        kind=HTTP_KIND,
        identity_key=uid,
        fields=fields,
        source_query=f"http.log record uid={uid} ({source_path})",
        collected_at=collected_at,
    )
