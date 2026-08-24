"""
fileintegrity.py — File Integrity Monitoring: file_watch_paths, file_entries, file_change_events, file_integrity_alerts/scans — see secure/fileintegrity/.

Split out of the original secure/storage/models.py (Phase 14.5 Stage C)
purely mechanically — behavior, SQL, and function signatures are
unchanged; only the file this code lives in changed. See
secure/storage/models/__init__.py for the full original module
docstring and the re-export surface that preserves
`from secure.storage.models import X` for every name.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

# ---------- File Integrity Monitoring ----------


@dataclass
class FileWatchPathRecord:
    id: int
    path: str
    recursive: bool
    max_depth: "int | None"
    sensitivity: str
    enabled: bool
    added_at: str
    last_scan_at: "str | None"
    last_scan_status: "str | None"


def _row_to_watch_path(row: sqlite3.Row) -> FileWatchPathRecord:
    data = dict(row)
    data["recursive"] = bool(data["recursive"])
    data["enabled"] = bool(data["enabled"])
    return FileWatchPathRecord(**data)


def add_watch_path(
    conn: sqlite3.Connection,
    path: str,
    recursive: bool = True,
    max_depth: "int | None" = None,
    sensitivity: str = "normal",
) -> "tuple[FileWatchPathRecord, bool]":
    """Add a watch path; does nothing if this exact normalized path is
    already registered. `path` must already be normalized (see
    secure/fileintegrity/paths.py's normalize_path()) — this function
    doesn't normalize it itself, so every caller does that consistently
    at the same layer.

    Returns (record, was_new).
    """
    existing = conn.execute(
        "SELECT * FROM file_watch_paths WHERE path = ?", (path,)
    ).fetchone()
    if existing is not None:
        return _row_to_watch_path(existing), False

    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO file_watch_paths "
        "(path, recursive, max_depth, sensitivity, enabled, added_at) "
        "VALUES (?, ?, ?, ?, 1, ?)",
        (path, 1 if recursive else 0, max_depth, sensitivity, now),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM file_watch_paths WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return _row_to_watch_path(row), True


def list_watch_paths(
    conn: sqlite3.Connection, enabled_only: bool = False
) -> "list[FileWatchPathRecord]":
    query = "SELECT * FROM file_watch_paths"
    if enabled_only:
        query += " WHERE enabled = 1"
    query += " ORDER BY id ASC"
    rows = conn.execute(query).fetchall()
    return [_row_to_watch_path(row) for row in rows]


def find_watch_path_by_id(conn: sqlite3.Connection, watch_path_id: int) -> "FileWatchPathRecord | None":
    row = conn.execute("SELECT * FROM file_watch_paths WHERE id = ?", (watch_path_id,)).fetchone()
    return _row_to_watch_path(row) if row else None


def find_watch_path_by_path(conn: sqlite3.Connection, path: str) -> "FileWatchPathRecord | None":
    row = conn.execute("SELECT * FROM file_watch_paths WHERE path = ?", (path,)).fetchone()
    return _row_to_watch_path(row) if row else None


def set_watch_path_enabled(conn: sqlite3.Connection, watch_path_id: int, enabled: bool) -> None:
    conn.execute(
        "UPDATE file_watch_paths SET enabled = ? WHERE id = ?",
        (1 if enabled else 0, watch_path_id),
    )
    conn.commit()


def set_watch_path_scan_status(
    conn: sqlite3.Connection, watch_path_id: int, status: str, scanned_at: "str | None" = None
) -> None:
    """Record the outcome ("ok" or "incomplete") of the most recent
    scan attempt over this watch path — see scanner.py's walk logic.
    """
    scanned_at = scanned_at or datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE file_watch_paths SET last_scan_status = ?, last_scan_at = ? WHERE id = ?",
        (status, scanned_at, watch_path_id),
    )
    conn.commit()


@dataclass
class FileEntryRecord:
    id: int
    watch_path_id: int
    path: str
    hash: "str | None"
    size: "int | None"
    mtime: "str | None"
    uid: "int | None"
    owner: "str | None"
    gid: "int | None"
    group_name: "str | None"
    mode: "str | None"
    is_executable: bool
    is_symlink: bool
    symlink_target: "str | None"
    dev: "int | None"
    ino: "int | None"
    program_path: "str | None"
    program_signing_status: "str | None"
    program_exists: "bool | None"
    known: bool
    unreadable: bool
    unreadable_reason: "str | None"
    skipped_reason: "str | None"
    first_seen: str
    last_seen: str
    last_hashed_at: "str | None"


def _row_to_file_entry(row: sqlite3.Row) -> FileEntryRecord:
    data = dict(row)
    data["is_executable"] = bool(data["is_executable"])
    data["is_symlink"] = bool(data["is_symlink"])
    data["known"] = bool(data["known"])
    data["unreadable"] = bool(data["unreadable"])
    if data["program_exists"] is not None:
        data["program_exists"] = bool(data["program_exists"])
    return FileEntryRecord(**data)


_FILE_ENTRY_METADATA_COLUMNS = (
    "hash", "size", "mtime", "uid", "owner", "gid", "group_name", "mode",
    "is_executable", "is_symlink", "symlink_target", "dev", "ino",
    "program_path", "program_signing_status", "program_exists",
    "unreadable", "unreadable_reason", "skipped_reason",
)


def insert_file_entry(
    conn: sqlite3.Connection,
    watch_path_id: int,
    path: str,
    metadata: dict,
    known: bool,
) -> FileEntryRecord:
    """Insert a brand-new file_entries row — used for both a watch
    path's baseline scan (known=True — see module docstring) and a
    genuinely new file found on a later scan (known=False). `metadata`
    is a dict keyed by the column names in _FILE_ENTRY_METADATA_COLUMNS
    (missing keys default to None/0 via .get()); hashing/stat happens
    entirely in secure/fileintegrity/hashing.py, this function only
    stores whatever it's handed.
    """
    now = datetime.now(timezone.utc).isoformat()
    last_hashed_at = now if metadata.get("hash") else None
    values = [metadata.get(col) for col in _FILE_ENTRY_METADATA_COLUMNS]
    columns_sql = ", ".join(_FILE_ENTRY_METADATA_COLUMNS)
    placeholders = ", ".join("?" for _ in _FILE_ENTRY_METADATA_COLUMNS)
    cursor = conn.execute(
        f"INSERT INTO file_entries "
        f"(watch_path_id, path, {columns_sql}, known, first_seen, last_seen, last_hashed_at) "
        f"VALUES (?, ?, {placeholders}, ?, ?, ?, ?)",
        (watch_path_id, path, *values, 1 if known else 0, now, now, last_hashed_at),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM file_entries WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row_to_file_entry(row)


def update_file_entry(
    conn: sqlite3.Connection,
    entry_id: int,
    metadata: dict,
    rehashed: bool = False,
) -> FileEntryRecord:
    """Overwrite an existing file_entries row's metadata (a modified or
    metadata_only change) and bump last_seen. `rehashed` controls
    whether last_hashed_at is refreshed — see hashing.py's stat-first
    fast path: a metadata-only change may not have required a re-hash
    at all (same size+mtime as baseline means the fast path skips
    hashing entirely), so last_hashed_at should only move forward when
    a hash was actually computed this scan.
    """
    now = datetime.now(timezone.utc).isoformat()
    set_clause = ", ".join(f"{col} = ?" for col in _FILE_ENTRY_METADATA_COLUMNS)
    values = [metadata.get(col) for col in _FILE_ENTRY_METADATA_COLUMNS]
    if rehashed:
        conn.execute(
            f"UPDATE file_entries SET {set_clause}, last_seen = ?, last_hashed_at = ? WHERE id = ?",
            (*values, now, now, entry_id),
        )
    else:
        conn.execute(
            f"UPDATE file_entries SET {set_clause}, last_seen = ? WHERE id = ?",
            (*values, now, entry_id),
        )
    conn.commit()
    row = conn.execute("SELECT * FROM file_entries WHERE id = ?", (entry_id,)).fetchone()
    return _row_to_file_entry(row)


def touch_file_entry_last_seen(conn: sqlite3.Connection, entry_id: int) -> None:
    """Bump last_seen only — the unchanged-file fast path (refinement:
    don't re-hash or rewrite metadata that didn't change)."""
    conn.execute(
        "UPDATE file_entries SET last_seen = ? WHERE id = ?",
        (datetime.now(timezone.utc).isoformat(), entry_id),
    )
    conn.commit()


def rename_file_entry(conn: sqlite3.Connection, entry_id: int, new_path: str, new_watch_path_id: int) -> FileEntryRecord:
    """Move an existing file_entries row to a new path in place —
    preserving id/first_seen/known/history continuity, which is the
    correct semantic for a CONFIRMED rename (same filesystem identity,
    just a new path), as opposed to a delete+insert pair (see
    secure/fileintegrity/analysis.py's match_renames()).
    """
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE file_entries SET path = ?, watch_path_id = ?, last_seen = ? WHERE id = ?",
        (new_path, new_watch_path_id, now, entry_id),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM file_entries WHERE id = ?", (entry_id,)).fetchone()
    return _row_to_file_entry(row)


def delete_file_entry(conn: sqlite3.Connection, entry_id: int) -> None:
    """Remove a file_entries row — used only once a scan has confirmed
    (via a fully-enumerated parent directory) that the file is
    genuinely gone. file_change_events keeps the historical record;
    file_entries reflects current state only.
    """
    conn.execute("DELETE FROM file_entries WHERE id = ?", (entry_id,))
    conn.commit()


def find_file_entry_by_path(conn: sqlite3.Connection, path: str) -> "FileEntryRecord | None":
    row = conn.execute("SELECT * FROM file_entries WHERE path = ?", (path,)).fetchone()
    return _row_to_file_entry(row) if row else None


def find_file_entries_by_hash(conn: sqlite3.Connection, file_hash: str, limit: int = 50) -> "list[FileEntryRecord]":
    """Every currently-known file whose CURRENT hash matches — added for
    Phase 23's INDICATOR entity resolution (a hash pivot: "is this exact
    hash the current state of any monitored file"). Deliberately reads
    file_entries (current state only), not file_change_events — a hash
    that only ever appeared in a file's PAST state (a `previous_hash` on
    some file_change_events row) is a different, historical question,
    answerable separately via list_file_change_events() if needed; this
    function answers "is anything monitored equal to this hash RIGHT
    NOW."
    """
    rows = conn.execute(
        "SELECT * FROM file_entries WHERE hash = ? ORDER BY last_seen DESC LIMIT ?",
        (file_hash, limit),
    ).fetchall()
    return [_row_to_file_entry(row) for row in rows]


def find_file_entry_by_id(conn: sqlite3.Connection, entry_id: int) -> "FileEntryRecord | None":
    row = conn.execute("SELECT * FROM file_entries WHERE id = ?", (entry_id,)).fetchone()
    return _row_to_file_entry(row) if row else None


def list_file_entries_for_watch_path(
    conn: sqlite3.Connection, watch_path_id: int
) -> "list[FileEntryRecord]":
    rows = conn.execute(
        "SELECT * FROM file_entries WHERE watch_path_id = ? ORDER BY path ASC", (watch_path_id,)
    ).fetchall()
    return [_row_to_file_entry(row) for row in rows]


def list_file_entries(conn: sqlite3.Connection, limit: int = 500) -> "list[FileEntryRecord]":
    rows = conn.execute(
        "SELECT * FROM file_entries ORDER BY last_seen DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_file_entry(row) for row in rows]


def set_file_entry_known(conn: sqlite3.Connection, entry_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE file_entries SET known = ? WHERE id = ?",
        (1 if known else 0, entry_id),
    )
    conn.commit()


@dataclass
class FileChangeEventRecord:
    id: int
    created_at: str
    run_id: str
    watch_path_id: int
    path: str
    old_path: "str | None"
    change_type: str
    previous_hash: "str | None"
    new_hash: "str | None"
    rename_confidence: "str | None"
    details: dict  # parsed from JSON


def _row_to_file_change_event(row: sqlite3.Row) -> FileChangeEventRecord:
    data = dict(row)
    data["details"] = json.loads(data["details"])
    return FileChangeEventRecord(**data)


def add_file_change_event(
    conn: sqlite3.Connection,
    run_id: str,
    watch_path_id: int,
    path: str,
    change_type: str,
    details: dict,
    old_path: "str | None" = None,
    previous_hash: "str | None" = None,
    new_hash: "str | None" = None,
    rename_confidence: "str | None" = None,
) -> int:
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO file_change_events "
        "(created_at, run_id, watch_path_id, path, old_path, change_type, "
        "previous_hash, new_hash, rename_confidence, details) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            created_at, run_id, watch_path_id, path, old_path, change_type,
            previous_hash, new_hash, rename_confidence, json.dumps(details),
        ),
    )
    conn.commit()
    return cursor.lastrowid


def list_file_change_events(
    conn: sqlite3.Connection, path: "str | None" = None, limit: int = 200
) -> "list[FileChangeEventRecord]":
    if path is not None:
        rows = conn.execute(
            "SELECT * FROM file_change_events WHERE path = ? OR old_path = ? "
            "ORDER BY id DESC LIMIT ?",
            (path, path, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM file_change_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_file_change_event(row) for row in rows]


@dataclass
class FileIntegrityAlertRecord:
    id: int
    created_at: str
    run_id: str
    kind: str
    severity: str
    path: str
    message: str
    context_notes: "str | None"
    known: bool


def _row_to_file_integrity_alert(row: sqlite3.Row) -> FileIntegrityAlertRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    return FileIntegrityAlertRecord(**data)


def add_file_integrity_alert(
    conn: sqlite3.Connection,
    run_id: str,
    kind: str,
    severity: str,
    path: str,
    message: str,
    context_notes: "str | None" = None,
) -> int:
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO file_integrity_alerts "
        "(created_at, run_id, kind, severity, path, message, context_notes, known) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
        (created_at, run_id, kind, severity, path, message, context_notes),
    )
    conn.commit()
    return cursor.lastrowid


def list_file_integrity_alerts(conn: sqlite3.Connection, limit: int = 100) -> "list[FileIntegrityAlertRecord]":
    rows = conn.execute(
        "SELECT * FROM file_integrity_alerts ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_file_integrity_alert(row) for row in rows]


def find_file_integrity_alert_by_id(conn: sqlite3.Connection, alert_id: int) -> "FileIntegrityAlertRecord | None":
    row = conn.execute("SELECT * FROM file_integrity_alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row_to_file_integrity_alert(row) if row else None


def set_file_integrity_alert_known(conn: sqlite3.Connection, alert_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE file_integrity_alerts SET known = ? WHERE id = ?",
        (1 if known else 0, alert_id),
    )
    conn.commit()


@dataclass
class FileIntegrityScanRecord:
    id: int
    run_id: str
    started_at: str
    completed_at: "str | None"
    duration_seconds: "float | None"
    watch_paths_attempted: list
    watch_paths_completed: list
    watch_paths_incomplete: list
    files_visited: int
    files_hashed: int
    files_skipped_unchanged: int
    files_skipped_too_large: int
    files_skipped_excluded: int
    files_unreadable: int
    alerts_generated: int


def _row_to_file_integrity_scan(row: sqlite3.Row) -> FileIntegrityScanRecord:
    data = dict(row)
    data["watch_paths_attempted"] = json.loads(data["watch_paths_attempted"])
    data["watch_paths_completed"] = json.loads(data["watch_paths_completed"])
    data["watch_paths_incomplete"] = json.loads(data["watch_paths_incomplete"])
    return FileIntegrityScanRecord(**data)


def add_file_integrity_scan(
    conn: sqlite3.Connection,
    run_id: str,
    started_at: str,
    completed_at: "str | None",
    duration_seconds: "float | None",
    watch_paths_attempted: list,
    watch_paths_completed: list,
    watch_paths_incomplete: list,
    files_visited: int = 0,
    files_hashed: int = 0,
    files_skipped_unchanged: int = 0,
    files_skipped_too_large: int = 0,
    files_skipped_excluded: int = 0,
    files_unreadable: int = 0,
    alerts_generated: int = 0,
) -> int:
    cursor = conn.execute(
        "INSERT INTO file_integrity_scans "
        "(run_id, started_at, completed_at, duration_seconds, watch_paths_attempted, "
        "watch_paths_completed, watch_paths_incomplete, files_visited, files_hashed, "
        "files_skipped_unchanged, files_skipped_too_large, files_skipped_excluded, "
        "files_unreadable, alerts_generated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id, started_at, completed_at, duration_seconds,
            json.dumps(watch_paths_attempted), json.dumps(watch_paths_completed),
            json.dumps(watch_paths_incomplete), files_visited, files_hashed,
            files_skipped_unchanged, files_skipped_too_large, files_skipped_excluded,
            files_unreadable, alerts_generated,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def list_file_integrity_scans(conn: sqlite3.Connection, limit: int = 20) -> "list[FileIntegrityScanRecord]":
    rows = conn.execute(
        "SELECT * FROM file_integrity_scans ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [_row_to_file_integrity_scan(row) for row in rows]


def find_latest_file_integrity_scan(conn: sqlite3.Connection) -> "FileIntegrityScanRecord | None":
    row = conn.execute(
        "SELECT * FROM file_integrity_scans ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return _row_to_file_integrity_scan(row) if row else None
