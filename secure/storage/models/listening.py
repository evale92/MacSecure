"""
listening.py — Listening port/service audit: listening_events, listening_services — see secure/listening/.

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
class ListeningEventRecord:
    id: int
    created_at: str
    run_id: str
    proto: str
    local_addr: str | None
    local_port: int | None
    bind_scope: str
    pid: int | None
    process_name: str | None


def add_listening_events(
    conn: sqlite3.Connection,
    run_id: str,
    rows: "list[tuple[str, str | None, int | None, str, int | None, str | None]]",
) -> "list[int]":
    """Insert one row per listening socket observed in a single scan, in
    one commit, and return the real `listening_events.id` assigned to
    each inserted row, in the same order as `rows`.

    Each row: (proto, local_addr, local_port, bind_scope, pid,
    process_name).

    Phase 14.5 Stage B: inserts one row at a time (still ONE commit for
    the whole batch) instead of a single `executemany()` call, exactly
    like `add_connection_events()` was corrected to do — `executemany()`'s
    `cursor.lastrowid` isn't a reliable per-row id in Python's sqlite3
    module, so no caller could ever learn which row got which id. That
    made it impossible for a `listening` feature-level anomaly to
    reference the exact scan observation that produced it; only
    `listening_services.id` (a deduped identity row updated in place
    across many scans) was available, which can't tell two different
    scans of the same service apart. See add_connection_events()'s
    docstring for the full reasoning — identical fix, applied here.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    ids: "list[int]" = []
    for row in rows:
        cursor = conn.execute(
            "INSERT INTO listening_events "
            "(created_at, run_id, proto, local_addr, local_port, bind_scope, pid, process_name) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (created_at, run_id, *row),
        )
        ids.append(cursor.lastrowid)
    conn.commit()
    return ids


def list_recent_listening_events(
    conn: sqlite3.Connection, limit: int = 200
) -> list[ListeningEventRecord]:
    rows = conn.execute(
        "SELECT id, created_at, run_id, proto, local_addr, local_port, bind_scope, pid, process_name "
        "FROM listening_events ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [ListeningEventRecord(**dict(row)) for row in rows]


def last_listening_run_id(conn: sqlite3.Connection) -> str | None:
    """Return the run_id of the most recent listening scan, or None if none yet.

    Used to find "what was listening as of the scan before this one" —
    see secure/listening/scanner.py's disappeared-service detection.
    """
    row = conn.execute(
        "SELECT run_id FROM listening_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["run_id"] if row else None


@dataclass
class ListeningServiceRecord:
    id: int
    proto: str
    bind_scope: str
    process_name: str
    identity_port: str
    local_addr: str | None
    local_port: int | None
    known: bool
    first_seen: str
    last_seen: str


def _row_to_listening_service(row: sqlite3.Row) -> ListeningServiceRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    return ListeningServiceRecord(**data)


def upsert_listening_service(
    conn: sqlite3.Connection,
    proto: str,
    bind_scope: str,
    process_name: str,
    identity_port: str,
    local_addr: str | None,
    local_port: int | None,
) -> tuple[ListeningServiceRecord, bool]:
    """Record a listening service seen during a scan.

    Matched by (proto, bind_scope, process_name, identity_port) — see
    the `listening_services` schema comment in database.py for why
    that tuple, not the raw port, is the identity. A match updates
    `local_addr`/`local_port` (the concrete address/port seen just
    now, purely informational) and `last_seen`; `first_seen` and
    `known` are left untouched. No match inserts a new row with
    `known=False`.

    Returns (record, was_new) — was_new is True only for a brand-new
    row, which is what "alert when a new service begins listening"
    keys off.
    """
    now = datetime.now(timezone.utc).isoformat()

    existing = conn.execute(
        "SELECT * FROM listening_services WHERE proto = ? AND bind_scope = ? "
        "AND process_name = ? AND identity_port = ?",
        (proto, bind_scope, process_name, identity_port),
    ).fetchone()

    if existing is not None:
        service_id = existing["id"]
        conn.execute(
            "UPDATE listening_services SET local_addr = ?, local_port = ?, last_seen = ? WHERE id = ?",
            (local_addr, local_port, now, service_id),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM listening_services WHERE id = ?", (service_id,)
        ).fetchone()
        return _row_to_listening_service(row), False

    cursor = conn.execute(
        "INSERT INTO listening_services "
        "(proto, bind_scope, process_name, identity_port, local_addr, local_port, known, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)",
        (proto, bind_scope, process_name, identity_port, local_addr, local_port, now, now),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM listening_services WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return _row_to_listening_service(row), True


def list_listening_services(conn: sqlite3.Connection) -> list[ListeningServiceRecord]:
    """Return every listening service ever recorded, most recently seen first."""
    rows = conn.execute(
        "SELECT * FROM listening_services ORDER BY last_seen DESC"
    ).fetchall()
    return [_row_to_listening_service(row) for row in rows]


def find_listening_service_by_id(
    conn: sqlite3.Connection, service_id: int
) -> ListeningServiceRecord | None:
    row = conn.execute(
        "SELECT * FROM listening_services WHERE id = ?", (service_id,)
    ).fetchone()
    return _row_to_listening_service(row) if row else None


def set_listening_service_known(conn: sqlite3.Connection, service_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE listening_services SET known = ? WHERE id = ?",
        (1 if known else 0, service_id),
    )
    conn.commit()
