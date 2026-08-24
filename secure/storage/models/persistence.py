"""
persistence.py — Process and Persistence Monitor: process_entries, persistence_observations/entries/alerts — see secure/persistence/.

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

# ---------- Phase 10: Process and Persistence Monitor ----------


@dataclass
class ProcessEntryRecord:
    id: int
    executable_path: str
    process_name: str | None
    run_as_user: str | None
    signing_status: str | None
    known: bool
    times_seen: int
    first_seen: str
    last_seen: str


def _row_to_process_entry(row: sqlite3.Row) -> ProcessEntryRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    return ProcessEntryRecord(**data)


def upsert_process_entry(
    conn: sqlite3.Connection,
    executable_path: str,
    process_name: "str | None",
    run_as_user: "str | None",
    signing_status: "str | None" = None,
) -> tuple[ProcessEntryRecord, bool]:
    """Record a running process seen during a scan; insert if new, update if not.

    Matched by `executable_path` — the stable identity (a PID is not;
    it's reused constantly and means nothing across scans). A match
    updates `process_name` (only overwritten with a non-empty value),
    `run_as_user` (always overwritten — which user is currently running
    this executable is current information, not sticky identity, same
    reasoning as bluetooth's last_rssi), `times_seen`, and `last_seen`;
    `first_seen`, `known`, and — deliberately — `signing_status` are
    left untouched on a match. Code-signing status is only computed
    once, at first-seen time (see secure/persistence/scanner.py for
    why re-checking it on every scan for every known process would be
    far too slow to be worth it); `signing_status` is only actually
    stored on a brand-new row's INSERT.

    Returns (record, was_new) — was_new is True only for a brand-new
    row, which is what "track newly appearing processes" and the
    unusual/unsigned-executable check key off.
    """
    now = datetime.now(timezone.utc).isoformat()

    existing = conn.execute(
        "SELECT * FROM process_entries WHERE executable_path = ?", (executable_path,)
    ).fetchone()

    if existing is not None:
        entry_id = existing["id"]
        new_name = process_name or existing["process_name"]
        conn.execute(
            "UPDATE process_entries SET process_name = ?, run_as_user = ?, "
            "times_seen = times_seen + 1, last_seen = ? WHERE id = ?",
            (new_name, run_as_user, now, entry_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM process_entries WHERE id = ?", (entry_id,)).fetchone()
        return _row_to_process_entry(row), False

    cursor = conn.execute(
        "INSERT INTO process_entries "
        "(executable_path, process_name, run_as_user, signing_status, known, times_seen, "
        "first_seen, last_seen) VALUES (?, ?, ?, ?, 0, 1, ?, ?)",
        (executable_path, process_name, run_as_user, signing_status, now, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM process_entries WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row_to_process_entry(row), True


def find_process_entry_by_path(
    conn: sqlite3.Connection, executable_path: str
) -> ProcessEntryRecord | None:
    """Look up a process entry by its executable path BEFORE calling
    upsert_process_entry() — lets the caller (scanner.py) know whether
    this is about to be a brand-new entry so it only bothers computing
    a code-signing classification when one is actually needed (see
    upsert_process_entry()'s docstring for why signing_status is only
    ever stored at creation time), rather than needing a second write
    to fill it in after the fact.
    """
    row = conn.execute(
        "SELECT * FROM process_entries WHERE executable_path = ?", (executable_path,)
    ).fetchone()
    return _row_to_process_entry(row) if row else None


def list_process_entries(conn: sqlite3.Connection) -> list[ProcessEntryRecord]:
    """Return every process executable ever recorded, most recently seen first."""
    rows = conn.execute("SELECT * FROM process_entries ORDER BY last_seen DESC").fetchall()
    return [_row_to_process_entry(row) for row in rows]


def find_process_entry_by_id(conn: sqlite3.Connection, entry_id: int) -> ProcessEntryRecord | None:
    row = conn.execute("SELECT * FROM process_entries WHERE id = ?", (entry_id,)).fetchone()
    return _row_to_process_entry(row) if row else None


def set_process_entry_known(conn: sqlite3.Connection, entry_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE process_entries SET known = ? WHERE id = ?",
        (1 if known else 0, entry_id),
    )
    conn.commit()


def add_persistence_observations(
    conn: sqlite3.Connection,
    run_id: str,
    rows: "list[tuple[str, str | None, str | None, str | None, bool | None, bool | None]]",
) -> "list[int]":
    """Insert one row per persistence entry observed in a single scan, in
    one commit, and return the real `persistence_observations.id`
    assigned to each inserted row, in the same order as `rows`.

    Each row: (kind, label, path, program_path, run_at_load, keep_alive).

    Phase 14.5 Stage B: previously used `conn.executemany()` and
    returned nothing, the same id-surfacing gap `add_connection_events()`
    and `add_listening_events()` had — `cursor.lastrowid` after an
    `executemany()` call is not a reliable per-row id in Python's
    sqlite3 module, so there was no way for a caller to know which
    exact observation row backed a given anomaly (see those two
    functions' docstrings for the full explanation). Fixed the same
    way: insert one row at a time with individual `conn.execute()`
    calls (each returns a trustworthy `cursor.lastrowid`), but still
    commit once at the end, preserving the original "one commit per
    scan" performance characteristic.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    ids: "list[int]" = []
    for kind, label, path, program_path, run_at_load, keep_alive in rows:
        cursor = conn.execute(
            "INSERT INTO persistence_observations "
            "(created_at, run_id, kind, label, path, program_path, run_at_load, keep_alive) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                created_at,
                run_id,
                kind,
                label,
                path,
                program_path,
                None if run_at_load is None else (1 if run_at_load else 0),
                None if keep_alive is None else (1 if keep_alive else 0),
            ),
        )
        ids.append(cursor.lastrowid)
    conn.commit()
    return ids


@dataclass
class PersistenceEntryRecord:
    id: int
    kind: str
    path: str | None
    label: str | None
    program_path: str | None
    signing_status: str | None
    known: bool
    first_seen: str
    last_seen: str


def _row_to_persistence_entry(row: sqlite3.Row) -> PersistenceEntryRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    return PersistenceEntryRecord(**data)


def upsert_persistence_entry(
    conn: sqlite3.Connection,
    kind: str,
    path: "str | None",
    label: "str | None",
    program_path: "str | None",
    signing_status: "str | None",
) -> tuple[PersistenceEntryRecord, bool, "str | None"]:
    """Record a persistence entry (LaunchAgent/LaunchDaemon/login item)
    seen during a scan; insert if new, update if not.

    Matched by (kind, path) when a path is available — falls back to
    matching by (kind, label) when it isn't (some login items have no
    resolvable path), the same nullable-unique-column fallback pattern
    upsert_wifi_network() uses for BSSID-less networks. A match updates
    `label` (only overwritten with a non-empty value), `program_path`
    and `signing_status` (ALWAYS overwritten — unlike process_entries,
    persistence entries ARE re-checked every scan, since there are few
    enough of them that this stays cheap, and a persistence mechanism's
    backing executable silently changing is exactly the kind of thing
    worth catching), and `last_seen`; `first_seen` and `known` are left
    untouched. No match inserts a new row with `known=False`.

    Returns (record, was_new, previous_signing_status) — was_new is
    True only for a brand-new row, what "detect newly created
    persistence entries" keys off. previous_signing_status is the
    value BEFORE this call overwrote it (None for a brand-new entry) —
    what signing-status-changed detection keys off, since by the time
    the returned `record` comes back its signing_status already
    reflects *this* scan.
    """
    now = datetime.now(timezone.utc).isoformat()

    if path:
        existing = conn.execute(
            "SELECT * FROM persistence_entries WHERE kind = ? AND path = ?", (kind, path)
        ).fetchone()
    else:
        existing = conn.execute(
            "SELECT * FROM persistence_entries WHERE kind = ? AND path IS NULL AND label = ?",
            (kind, label),
        ).fetchone()

    if existing is not None:
        entry_id = existing["id"]
        new_label = label or existing["label"]
        previous_signing_status = existing["signing_status"]
        conn.execute(
            "UPDATE persistence_entries SET label = ?, program_path = ?, signing_status = ?, "
            "last_seen = ? WHERE id = ?",
            (new_label, program_path, signing_status, now, entry_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM persistence_entries WHERE id = ?", (entry_id,)).fetchone()
        return _row_to_persistence_entry(row), False, previous_signing_status

    cursor = conn.execute(
        "INSERT INTO persistence_entries "
        "(kind, path, label, program_path, signing_status, known, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?, ?, 0, ?, ?)",
        (kind, path, label, program_path, signing_status, now, now),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM persistence_entries WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return _row_to_persistence_entry(row), True, None


def list_persistence_entries(conn: sqlite3.Connection) -> list[PersistenceEntryRecord]:
    """Return every persistence entry ever recorded, most recently seen first."""
    rows = conn.execute("SELECT * FROM persistence_entries ORDER BY last_seen DESC").fetchall()
    return [_row_to_persistence_entry(row) for row in rows]


def find_persistence_entry_by_id(
    conn: sqlite3.Connection, entry_id: int
) -> PersistenceEntryRecord | None:
    row = conn.execute("SELECT * FROM persistence_entries WHERE id = ?", (entry_id,)).fetchone()
    return _row_to_persistence_entry(row) if row else None


def set_persistence_entry_known(conn: sqlite3.Connection, entry_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE persistence_entries SET known = ? WHERE id = ?",
        (1 if known else 0, entry_id),
    )
    conn.commit()


@dataclass
class PersistenceAlertRecord:
    id: int
    created_at: str
    run_id: str
    kind: str
    severity: str
    target_type: str
    identifier: str
    label: str | None
    message: str
    known: bool


def _row_to_persistence_alert(row: sqlite3.Row) -> PersistenceAlertRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    return PersistenceAlertRecord(**data)


def add_persistence_alert(
    conn: sqlite3.Connection,
    run_id: str,
    kind: str,
    severity: str,
    target_type: str,
    identifier: str,
    label: "str | None",
    message: str,
) -> int:
    """Insert one persistence alert row and return its new id. One row
    per call, same reasoning as add_arp_alert()/add_bluetooth_alert():
    a scan raises at most a handful of these, and the caller wants the
    id back right away to show "mark #N known|unknown" in scan output.
    `known` defaults to 0 (unreviewed).
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO persistence_alerts "
        "(created_at, run_id, kind, severity, target_type, identifier, label, message, known) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
        (created_at, run_id, kind, severity, target_type, identifier, label, message),
    )
    conn.commit()
    return cursor.lastrowid


def list_persistence_alerts(conn: sqlite3.Connection, limit: int = 100) -> list[PersistenceAlertRecord]:
    """Return the most recent persistence alerts, newest first."""
    rows = conn.execute(
        "SELECT id, created_at, run_id, kind, severity, target_type, identifier, label, message, known "
        "FROM persistence_alerts ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_row_to_persistence_alert(row) for row in rows]


def find_persistence_alert_by_id(conn: sqlite3.Connection, alert_id: int) -> PersistenceAlertRecord | None:
    row = conn.execute("SELECT * FROM persistence_alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row_to_persistence_alert(row) if row else None


def set_persistence_alert_known(conn: sqlite3.Connection, alert_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE persistence_alerts SET known = ? WHERE id = ?",
        (1 if known else 0, alert_id),
    )
    conn.commit()
