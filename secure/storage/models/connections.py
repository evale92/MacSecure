"""
connections.py — Active connections: connection_events, remote_endpoints, process_destinations — see secure/connections/.

Split out of the original secure/storage/models.py (Phase 14.5 Stage C)
purely mechanically — behavior, SQL, and function signatures are
unchanged; only the file this code lives in changed. See
secure/storage/models/__init__.py for the full original module
docstring and the re-export surface that preserves
`from secure.storage.models import X` for every name.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

@dataclass
class ConnectionEventRecord:
    id: int
    created_at: str
    run_id: str
    proto: str
    local_addr: str | None
    local_port: int | None
    remote_addr: str | None
    remote_port: int | None
    state: str | None
    pid: int | None
    process_name: str | None


def add_connection_events(
    conn: sqlite3.Connection,
    run_id: str,
    rows: "list[tuple[str, str | None, int | None, str | None, int | None, str | None, int | None, str | None]]",
) -> "list[int]":
    """Insert one row per connection observed in a single scan, in one
    commit, and return the real `connection_events.id` assigned to each
    inserted row, in the same order as `rows`.

    Each row: (proto, local_addr, local_port, remote_addr, remote_port,
    state, pid, process_name).

    Phase 14 Stage 4C originally inserted this batch with a single
    `executemany()` call — cheap, but `cursor.lastrowid` after an
    `executemany()` is not a reliable per-row id in Python's sqlite3
    module (it reflects at most the final statement executed, not each
    one), so no caller could ever learn which row got which id. That
    became a real problem once `process_destination` anomaly
    provenance needed to point at the *exact* connection observation
    that produced it (see `secure/connections/scanner.py`) — without a
    genuine per-row id, the only options were an unstable substitute
    (row count, `MAX(id)`, insertion order without verification) or an
    approximation (`remote_endpoints.id`, which identifies a
    destination alone, not a process+destination pair). Both were
    explicitly rejected in favor of fixing this storage boundary
    properly: insert one row at a time (still ONE commit for the whole
    batch, so this remains no slower in the way that matters — number
    of fsyncs, not number of statements) and collect each real
    `cursor.lastrowid` as it's assigned. A scan producing 50-200+ rows
    is still fast; SQLite's per-statement overhead here is negligible
    next to the syscall a commit already costs.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    ids: "list[int]" = []
    for row in rows:
        cursor = conn.execute(
            "INSERT INTO connection_events "
            "(created_at, run_id, proto, local_addr, local_port, remote_addr, remote_port, state, pid, process_name) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (created_at, run_id, *row),
        )
        ids.append(cursor.lastrowid)
    conn.commit()
    return ids


def list_recent_connection_events(
    conn: sqlite3.Connection, limit: int = 200, since: "str | None" = None
) -> list[ConnectionEventRecord]:
    """Return the most recent connection-event rows, newest first (not
    runs — see run_id note above). `since` (an ISO 8601 string,
    inclusive `created_at >= since`) is optional and additive — added
    in Phase 18 for secure/integrations/suricata/correlate.py's own
    bounded time-window lookup of native connections near a Suricata
    alert's own timestamp, the same `since` convention Phase 17 already
    added to list_integration_observations(). Every existing caller
    that doesn't pass `since` is unaffected.
    """
    if since is not None:
        rows = conn.execute(
            "SELECT id, created_at, run_id, proto, local_addr, local_port, remote_addr, "
            "remote_port, state, pid, process_name "
            "FROM connection_events WHERE created_at >= ? ORDER BY id DESC LIMIT ?",
            (since, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, created_at, run_id, proto, local_addr, local_port, remote_addr, "
            "remote_port, state, pid, process_name "
            "FROM connection_events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [ConnectionEventRecord(**dict(row)) for row in rows]


def last_connection_run_id(conn: sqlite3.Connection) -> str | None:
    """Return the run_id of the most recent connections scan, or None if none yet."""
    row = conn.execute(
        "SELECT run_id FROM connection_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["run_id"] if row else None


@dataclass
class RemoteEndpointRecord:
    id: int
    remote_addr: str
    remote_port: int
    proto: str
    process_name: str | None
    known: bool
    first_seen: str
    last_seen: str


def _row_to_endpoint(row: sqlite3.Row) -> RemoteEndpointRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    return RemoteEndpointRecord(**data)


def upsert_remote_endpoint(
    conn: sqlite3.Connection,
    remote_addr: str,
    remote_port: int,
    proto: str,
    process_name: str | None,
) -> tuple[RemoteEndpointRecord, bool]:
    """Record a remote destination seen during a connections scan.

    Matched by (remote_addr, remote_port, proto) — the same
    destination showing up again updates `process_name` (only
    overwritten with a non-empty value — an existing value is never
    replaced with nothing) and `last_seen`; `first_seen` and `known`
    are left untouched. No match inserts a new row with `known=False`.

    Returns (record, was_new) — was_new is True only for a brand-new
    row, which is what "flag an unexpected outbound connection" keys
    off.
    """
    now = datetime.now(timezone.utc).isoformat()

    existing = conn.execute(
        "SELECT * FROM remote_endpoints WHERE remote_addr = ? AND remote_port = ? AND proto = ?",
        (remote_addr, remote_port, proto),
    ).fetchone()

    if existing is not None:
        endpoint_id = existing["id"]
        new_process_name = process_name or existing["process_name"]
        conn.execute(
            "UPDATE remote_endpoints SET process_name = ?, last_seen = ? WHERE id = ?",
            (new_process_name, now, endpoint_id),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM remote_endpoints WHERE id = ?", (endpoint_id,)
        ).fetchone()
        return _row_to_endpoint(row), False

    cursor = conn.execute(
        "INSERT INTO remote_endpoints "
        "(remote_addr, remote_port, proto, process_name, known, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?, 0, ?, ?)",
        (remote_addr, remote_port, proto, process_name, now, now),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM remote_endpoints WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return _row_to_endpoint(row), True


def list_remote_endpoints(conn: sqlite3.Connection) -> list[RemoteEndpointRecord]:
    """Return every remote destination ever recorded, most recently seen first."""
    rows = conn.execute(
        "SELECT * FROM remote_endpoints ORDER BY last_seen DESC"
    ).fetchall()
    return [_row_to_endpoint(row) for row in rows]


@dataclass
class ProcessDestinationRecord:
    id: int
    process_name: str  # literal "(unknown)" for unattributed connections — never NULL
    remote_addr: str
    remote_port: int
    proto: str
    observation_count: int
    first_seen: str
    last_seen: str


def _row_to_process_destination(row: sqlite3.Row) -> ProcessDestinationRecord:
    return ProcessDestinationRecord(**dict(row))


def upsert_process_destination(
    conn: sqlite3.Connection,
    process_name: "str | None",
    remote_addr: str,
    remote_port: int,
    proto: str,
) -> "tuple[ProcessDestinationRecord, bool]":
    """Record one (process, destination) pair seen during a connections
    scan — Phase 14 Stage 4C's stable identity for process_destination
    baseline entities (see database.py's schema comment on
    process_destinations for why this is separate from
    remote_endpoints). `process_name=None` is stored as the literal
    string "(unknown)", matching
    secure.baseline.entities.process_destination_key()'s own fallback.

    Unlike upsert_remote_endpoint() (which leaves an existing row's
    `known` alone but freely updates `process_name`), identity here
    already INCLUDES process_name, so there's nothing analogous to
    reconcile — only `observation_count`/`last_seen` advance on a
    repeat.  Returns (record, was_new).
    """
    name = process_name or "(unknown)"
    now = datetime.now(timezone.utc).isoformat()

    existing = conn.execute(
        "SELECT * FROM process_destinations "
        "WHERE process_name = ? AND remote_addr = ? AND remote_port = ? AND proto = ?",
        (name, remote_addr, remote_port, proto),
    ).fetchone()

    if existing is not None:
        pd_id = existing["id"]
        conn.execute(
            "UPDATE process_destinations SET observation_count = observation_count + 1, "
            "last_seen = ? WHERE id = ?",
            (now, pd_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM process_destinations WHERE id = ?", (pd_id,)).fetchone()
        return _row_to_process_destination(row), False

    cursor = conn.execute(
        "INSERT INTO process_destinations "
        "(process_name, remote_addr, remote_port, proto, observation_count, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?, 1, ?, ?)",
        (name, remote_addr, remote_port, proto, now, now),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM process_destinations WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return _row_to_process_destination(row), True


def find_process_destination_by_id(conn: sqlite3.Connection, pd_id: int) -> "ProcessDestinationRecord | None":
    row = conn.execute("SELECT * FROM process_destinations WHERE id = ?", (pd_id,)).fetchone()
    return _row_to_process_destination(row) if row else None


def list_process_destinations(conn: sqlite3.Connection, limit: int = 500) -> "list[ProcessDestinationRecord]":
    """Return every (process, destination) pair ever recorded, most
    recently seen first. Added for Phase 23 (secure/investigate/) — no
    existing caller needed the FULL set before (only find-by-id, since
    every prior use already had a specific row's id in hand); the
    investigation engine's PROCESS/DESTINATION entity resolution needs
    to search across all of them by process_name or by remote identity,
    which the two functions below build on directly.
    """
    rows = conn.execute(
        "SELECT * FROM process_destinations ORDER BY last_seen DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_process_destination(row) for row in rows]


def list_process_destinations_for_process(
    conn: sqlite3.Connection, process_name: str, limit: int = 200
) -> "list[ProcessDestinationRecord]":
    """Every destination pair recorded for one exact process_name —
    Phase 23's PROCESS entity resolution: "what has this executable
    talked to." Exact string match only, the same "identity+timing, no
    fuzzy guessing" discipline the integrations correlate.py modules
    already established — never a substring/heuristic match.
    """
    rows = conn.execute(
        "SELECT * FROM process_destinations WHERE process_name = ? ORDER BY last_seen DESC LIMIT ?",
        (process_name, limit),
    ).fetchall()
    return [_row_to_process_destination(row) for row in rows]


def list_process_destinations_for_remote(
    conn: sqlite3.Connection, remote_addr: str, remote_port: int, proto: str, limit: int = 200
) -> "list[ProcessDestinationRecord]":
    """Every (process, destination) pair recorded for one exact remote
    endpoint — Phase 23's DESTINATION entity resolution: "what has ever
    talked to this remote address/port," independent of which process.
    """
    rows = conn.execute(
        "SELECT * FROM process_destinations WHERE remote_addr = ? AND remote_port = ? AND proto = ? "
        "ORDER BY last_seen DESC LIMIT ?",
        (remote_addr, remote_port, proto, limit),
    ).fetchall()
    return [_row_to_process_destination(row) for row in rows]


def find_remote_endpoint_by_id(
    conn: sqlite3.Connection, endpoint_id: int
) -> RemoteEndpointRecord | None:
    row = conn.execute(
        "SELECT * FROM remote_endpoints WHERE id = ?", (endpoint_id,)
    ).fetchone()
    return _row_to_endpoint(row) if row else None


def find_remote_endpoint_by_identity(
    conn: sqlite3.Connection, remote_addr: str, remote_port: int, proto: str
) -> "RemoteEndpointRecord | None":
    """Look up a remote_endpoints row by its own (remote_addr,
    remote_port, proto) uniqueness — added for Phase 23's DESTINATION
    entity resolution, which addresses a destination by that same
    identity (see secure/investigate/entity.py's destination_key())
    rather than by row id.
    """
    row = conn.execute(
        "SELECT * FROM remote_endpoints WHERE remote_addr = ? AND remote_port = ? AND proto = ?",
        (remote_addr, remote_port, proto),
    ).fetchone()
    return _row_to_endpoint(row) if row else None


def set_remote_endpoint_known(conn: sqlite3.Connection, endpoint_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE remote_endpoints SET known = ? WHERE id = ?",
        (1 if known else 0, endpoint_id),
    )
    conn.commit()
