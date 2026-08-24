"""
integrations.py — Phase 15 External Telemetry Foundation: integration_runs,
integration_observations, integration_alerts — see secure/integrations/.

Added as a new domain file directly inside the already-split
secure/storage/models/ package (Phase 14.5 Stage C), following that
split's own convention: one file per domain, re-exported from
secure/storage/models/__init__.py so `from secure.storage.models import X`
keeps working for every name here too.

This module has no idea what osquery is, or what any other future
integration is — it only knows how to store and retrieve the
already-normalized rows secure/integrations/osquery/scanner.py hands it
(a run's lifecycle, a batch of ExternalObservations, and any crosscheck
Discrepancy rows), the same "this module doesn't interpret, it only
persists" separation every other domain file in this package keeps.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone


# ---------- integration_runs ----------


@dataclass
class IntegrationRunRecord:
    id: int
    run_id: str
    integration: str
    started_at: str
    completed_at: "str | None"
    status: str
    detail: "str | None"
    tool_version: "str | None"
    observations_collected: int
    alerts_generated: int


def _row_to_integration_run(row: sqlite3.Row) -> IntegrationRunRecord:
    return IntegrationRunRecord(**dict(row))


def add_integration_run(
    conn: sqlite3.Connection,
    run_id: str,
    integration: str,
    started_at: str,
    completed_at: "str | None",
    status: str,
    detail: "str | None",
    tool_version: "str | None" = None,
    observations_collected: int = 0,
    alerts_generated: int = 0,
) -> int:
    """Insert one integration_runs row and return its new id. Unlike
    baseline_runs (started, then finalized in place later), this is
    written once at the end of one collection pass — scanner.py already
    knows the full outcome (status, counts) by the time it's ready to
    persist anything, so there's no separate "start" call to make.
    """
    cursor = conn.execute(
        "INSERT INTO integration_runs "
        "(run_id, integration, started_at, completed_at, status, detail, "
        "tool_version, observations_collected, alerts_generated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id,
            integration,
            started_at,
            completed_at,
            status,
            detail,
            tool_version,
            observations_collected,
            alerts_generated,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def list_integration_runs(
    conn: sqlite3.Connection, integration: "str | None" = None, limit: int = 50
) -> "list[IntegrationRunRecord]":
    """Return the most recent integration runs, newest first, optionally
    filtered to one integration name.
    """
    if integration is not None:
        rows = conn.execute(
            "SELECT * FROM integration_runs WHERE integration = ? "
            "ORDER BY id DESC LIMIT ?",
            (integration, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM integration_runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_integration_run(row) for row in rows]


def find_latest_integration_run(
    conn: sqlite3.Connection, integration: str
) -> "IntegrationRunRecord | None":
    """The single most recent run for one integration — what `secure
    integrations osquery status` shows.
    """
    row = conn.execute(
        "SELECT * FROM integration_runs WHERE integration = ? "
        "ORDER BY id DESC LIMIT 1",
        (integration,),
    ).fetchone()
    return _row_to_integration_run(row) if row else None


# ---------- integration_observations ----------


@dataclass
class IntegrationObservationRecord:
    id: int
    created_at: str
    run_id: str
    integration: str
    kind: str
    identity_key: str
    fields_json: str
    source_query: str
    collected_at: str

    @property
    def fields(self) -> dict:
        return json.loads(self.fields_json)


def _row_to_integration_observation(row: sqlite3.Row) -> IntegrationObservationRecord:
    return IntegrationObservationRecord(**dict(row))


def add_integration_observations(
    conn: sqlite3.Connection,
    run_id: str,
    integration: str,
    rows: "list[tuple[str, str, dict, str, str]]",
) -> "list[int]":
    """Insert one row per ExternalObservation collected in a single
    integration run, in one commit, and return the real
    `integration_observations.id` assigned to each inserted row, in the
    same order as `rows`.

    Each row: (kind, identity_key, fields, source_query, collected_at) —
    `fields` is a plain dict, JSON-encoded here.

    Inserts one row at a time with individual conn.execute() calls
    (each returns a trustworthy cursor.lastrowid), committed once at the
    end — the same id-surfacing discipline Phase 14.5 Stage B established
    for add_connection_events()/add_listening_events()/
    add_persistence_observations(), applied here from the start rather
    than needing a later fix, since Phase 15's own instruction
    ("exact source provenance") makes per-row ids a day-one requirement,
    not an afterthought.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    ids: "list[int]" = []
    for kind, identity_key, fields, source_query, collected_at in rows:
        cursor = conn.execute(
            "INSERT INTO integration_observations "
            "(created_at, run_id, integration, kind, identity_key, fields_json, "
            "source_query, collected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                created_at,
                run_id,
                integration,
                kind,
                identity_key,
                json.dumps(fields),
                source_query,
                collected_at,
            ),
        )
        ids.append(cursor.lastrowid)
    conn.commit()
    return ids


def list_integration_observations(
    conn: sqlite3.Connection,
    integration: "str | None" = None,
    kind: "str | None" = None,
    since: "str | None" = None,
    limit: int = 200,
) -> "list[IntegrationObservationRecord]":
    """Return the most recent integration observations, newest first,
    optionally filtered by integration name, kind, and/or a minimum
    `created_at` (ISO 8601 string, inclusive) — `since` added in Phase
    17 for secure/integrations/sigma/scanner.py's own lookback-window
    telemetry queries, the same `created_at >= cutoff_iso` convention
    secure/correlate/signals.py's `_collect_*()` functions already use
    throughout. Optional and additive — every existing caller that
    doesn't pass `since` is unaffected.
    """
    clauses = []
    params: list = []
    if integration is not None:
        clauses.append("integration = ?")
        params.append(integration)
    if kind is not None:
        clauses.append("kind = ?")
        params.append(kind)
    if since is not None:
        clauses.append("created_at >= ?")
        params.append(since)
    where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
    params.append(limit)
    rows = conn.execute(
        f"SELECT * FROM integration_observations {where}ORDER BY id DESC LIMIT ?",
        params,
    ).fetchall()
    return [_row_to_integration_observation(row) for row in rows]


# ---------- integration_alerts ----------


@dataclass
class IntegrationAlertRecord:
    id: int
    created_at: str
    run_id: str
    integration: str
    kind: str
    discrepancy: str
    severity: str
    identity_key: str
    label: "str | None"
    message: str
    source_observation_id: "int | None"
    known: bool


def _row_to_integration_alert(row: sqlite3.Row) -> IntegrationAlertRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    return IntegrationAlertRecord(**data)


def add_integration_alert(
    conn: sqlite3.Connection,
    run_id: str,
    integration: str,
    kind: str,
    discrepancy: str,
    severity: str,
    identity_key: str,
    label: "str | None",
    message: str,
    source_observation_id: "int | None" = None,
) -> int:
    """Insert one integration_alerts row and return its new id. Only a
    genuine native/integration DISCREPANCY reaches this table — see
    secure/integrations/osquery/crosscheck.py's module docstring for why
    a match between Secure's own native collectors and an integration is
    never written here (or anywhere), which is what keeps a single
    real-world fact both sources agree on from ever being treated as two
    pieces of independent corroborating evidence. `source_observation_id`
    should reference the exact integration_observations.id this alert was
    derived from for an 'osquery_only' discrepancy (None for
    'native_only', which has no corresponding osquery observation).
    `known` defaults to 0 (unreviewed), same convention as every other
    *_alerts table.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO integration_alerts "
        "(created_at, run_id, integration, kind, discrepancy, severity, "
        "identity_key, label, message, source_observation_id, known) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        (
            created_at, run_id, integration, kind, discrepancy, severity,
            identity_key, label, message, source_observation_id,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def list_integration_alerts(
    conn: sqlite3.Connection, integration: "str | None" = None, limit: int = 100
) -> "list[IntegrationAlertRecord]":
    """Return the most recent integration alerts, newest first,
    optionally filtered to one integration name.
    """
    if integration is not None:
        rows = conn.execute(
            "SELECT * FROM integration_alerts WHERE integration = ? "
            "ORDER BY id DESC LIMIT ?",
            (integration, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM integration_alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_integration_alert(row) for row in rows]


def find_integration_alert_by_id(
    conn: sqlite3.Connection, alert_id: int
) -> "IntegrationAlertRecord | None":
    row = conn.execute(
        "SELECT * FROM integration_alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    return _row_to_integration_alert(row) if row else None


def set_integration_alert_known(conn: sqlite3.Connection, alert_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE integration_alerts SET known = ? WHERE id = ?",
        (1 if known else 0, alert_id),
    )
    conn.commit()
