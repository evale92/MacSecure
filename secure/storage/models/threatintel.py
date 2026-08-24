"""
threatintel.py — Phase 20 Threat-Intelligence Enrichment: the single
`threat_intel_lookups` table — see secure/threatintel/.

Added as a new domain file directly inside the already-split
secure/storage/models/ package (Phase 14.5 Stage C), following that
split's own convention: one file per domain, re-exported from
secure/storage/models/__init__.py.

This module has no idea what a "provider" is, what VirusTotal's API
looks like, or what "private IP" means — it only knows how to store
and retrieve the already-normalized ProviderLookupResult rows
secure/threatintel/enrich.py hands it, the same "this module doesn't
interpret, it only persists" separation every other domain file in
this package keeps.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class ThreatIntelLookupRecord:
    id: int
    created_at: str
    indicator_type: str
    indicator_value: str
    provider: str
    queried_at: str
    status: str
    verdict: "str | None"
    score: "float | None"
    score_meaning: "str | None"
    categories_json: "str | None"
    raw_response_json: "str | None"
    source_query: str
    expires_at: "str | None"
    detail: "str | None"

    @property
    def categories(self) -> "tuple[str, ...]":
        return tuple(json.loads(self.categories_json)) if self.categories_json else ()

    @property
    def raw_response(self) -> "dict | None":
        return json.loads(self.raw_response_json) if self.raw_response_json else None


def _row_to_lookup(row: sqlite3.Row) -> ThreatIntelLookupRecord:
    return ThreatIntelLookupRecord(**dict(row))


def add_threat_intel_lookup(
    conn: sqlite3.Connection,
    indicator_type: str,
    indicator_value: str,
    provider: str,
    queried_at: str,
    status: str,
    verdict: "str | None",
    score: "float | None",
    score_meaning: "str | None",
    categories: "tuple[str, ...]",
    raw_response: "dict | None",
    source_query: str,
    expires_at: "str | None",
    detail: "str | None",
) -> int:
    """Insert one threat_intel_lookups row (a real lookup ATTEMPT — see
    the schema comment in database.py) and return its new id. Always an
    INSERT, never an UPDATE/upsert: the cache-freshness decision
    ("is there already a non-expired row for this indicator+provider")
    is made by the CALLER (enrich.py's find_fresh_lookup() read,
    below) BEFORE deciding to query at all — this function only ever
    records a lookup that genuinely happened, preserving full lookup
    history rather than overwriting it, the same append-only-history
    discipline every other *_observations table in this app already
    uses.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO threat_intel_lookups "
        "(created_at, indicator_type, indicator_value, provider, queried_at, status, "
        "verdict, score, score_meaning, categories_json, raw_response_json, source_query, "
        "expires_at, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            created_at, indicator_type, indicator_value, provider, queried_at, status,
            verdict, score, score_meaning,
            json.dumps(list(categories)) if categories else None,
            json.dumps(raw_response) if raw_response is not None else None,
            source_query, expires_at, detail,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def find_fresh_lookup(
    conn: sqlite3.Connection, indicator_type: str, indicator_value: str, provider: str, now: "str | None" = None,
) -> "ThreatIntelLookupRecord | None":
    """The cache read: the most recent lookup for this exact
    (indicator_type, indicator_value, provider) whose `expires_at` is
    either NULL (never cacheable — always treated as already expired,
    so this returns None and a fresh lookup is always made) or still in
    the future relative to `now` (defaults to the real current time).
    Returns None when nothing fresh exists — the caller (enrich.py)
    then performs a real lookup rather than assuming anything.
    """
    now = now or datetime.now(timezone.utc).isoformat()
    row = conn.execute(
        "SELECT * FROM threat_intel_lookups WHERE indicator_type = ? AND indicator_value = ? "
        "AND provider = ? AND expires_at IS NOT NULL AND expires_at > ? "
        "ORDER BY id DESC LIMIT 1",
        (indicator_type, indicator_value, provider, now),
    ).fetchone()
    return _row_to_lookup(row) if row else None


def list_threat_intel_lookups(
    conn: sqlite3.Connection,
    indicator_type: "str | None" = None,
    indicator_value: "str | None" = None,
    provider: "str | None" = None,
    limit: int = 100,
) -> "list[ThreatIntelLookupRecord]":
    """Most recent lookups first, optionally filtered — the read behind
    `secure threatintel history`.
    """
    clauses = []
    params: list = []
    if indicator_type is not None:
        clauses.append("indicator_type = ?")
        params.append(indicator_type)
    if indicator_value is not None:
        clauses.append("indicator_value = ?")
        params.append(indicator_value)
    if provider is not None:
        clauses.append("provider = ?")
        params.append(provider)
    where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
    params.append(limit)
    rows = conn.execute(
        f"SELECT * FROM threat_intel_lookups {where}ORDER BY id DESC LIMIT ?", params
    ).fetchall()
    return [_row_to_lookup(row) for row in rows]


def find_latest_lookups_for_indicator(
    conn: sqlite3.Connection, indicator_type: str, indicator_value: str
) -> "list[ThreatIntelLookupRecord]":
    """The latest lookup row for EACH distinct provider that has ever
    looked up this one indicator — what explain wiring's cache-only
    read (secure/threatintel/enrich.py's attach_cached_threat_intel())
    uses to show "what's already known" about an indicator without
    making any new provider call. A plain GROUP-BY-max-id done in
    Python rather than a correlated SQL subquery — this table is small
    enough (one row per lookup ATTEMPT, not per raw network event) that
    the simpler, more readable approach is the right tradeoff, matching
    this project's general "clarity over cleverness" style.
    """
    rows = conn.execute(
        "SELECT * FROM threat_intel_lookups WHERE indicator_type = ? AND indicator_value = ? "
        "ORDER BY id DESC",
        (indicator_type, indicator_value),
    ).fetchall()
    latest_by_provider: "dict[str, ThreatIntelLookupRecord]" = {}
    for row in rows:
        record = _row_to_lookup(row)
        if record.provider not in latest_by_provider:
            latest_by_provider[record.provider] = record
    return list(latest_by_provider.values())


def find_latest_lookup(
    conn: sqlite3.Connection, indicator_type: str, indicator_value: str, provider: str
) -> "ThreatIntelLookupRecord | None":
    """The single most recent lookup for one (indicator, provider) pair
    REGARDLESS of freshness — used by explain wiring's cache-only read
    (secure/threatintel/enrich.py's attach_cached_threat_intel()), which
    must still show a stale/expired result rather than nothing (an
    honestly-labeled stale result is more useful in an explanation than
    silence), distinct from find_fresh_lookup()'s cache-for-querying
    purpose above.
    """
    row = conn.execute(
        "SELECT * FROM threat_intel_lookups WHERE indicator_type = ? AND indicator_value = ? "
        "AND provider = ? ORDER BY id DESC LIMIT 1",
        (indicator_type, indicator_value, provider),
    ).fetchone()
    return _row_to_lookup(row) if row else None
