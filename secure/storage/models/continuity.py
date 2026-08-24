"""
continuity.py — `secure snapshot` history (snapshots table) — see secure/continuity.py.

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
class SnapshotRecord:
    id: int
    created_at: str
    window_minutes: int
    summary: str
    details: str  # JSON string; see secure/continuity.py for the shape


def add_snapshot(
    conn: sqlite3.Connection, window_minutes: int, summary: str, details_json: str
) -> int:
    """Insert one Continuity snapshot row and return its new id."""
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO snapshots (created_at, window_minutes, summary, details) "
        "VALUES (?, ?, ?, ?)",
        (created_at, window_minutes, summary, details_json),
    )
    conn.commit()
    return cursor.lastrowid


def list_recent_snapshots(conn: sqlite3.Connection, limit: int = 10) -> list[SnapshotRecord]:
    """Return the most recent snapshots, newest first."""
    rows = conn.execute(
        "SELECT id, created_at, window_minutes, summary, details "
        "FROM snapshots ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [SnapshotRecord(**dict(row)) for row in rows]
