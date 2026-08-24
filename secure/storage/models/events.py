"""
events.py — Generic app-event log (events table) — see Event/add_event/list_events.

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
class Event:
    id: int
    created_at: str
    category: str
    message: str


def add_event(conn: sqlite3.Connection, category: str, message: str) -> int:
    """Insert one event row and return its new id."""
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO events (created_at, category, message) VALUES (?, ?, ?)",
        (created_at, category, message),
    )
    conn.commit()
    return cursor.lastrowid


def list_events(conn: sqlite3.Connection, limit: int = 20) -> list[Event]:
    """Return the most recent events, newest first."""
    rows = conn.execute(
        "SELECT id, created_at, category, message "
        "FROM events ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [Event(**dict(row)) for row in rows]


def count_events(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
    return int(row["n"])


def has_recent_event(conn: sqlite3.Connection, category: str, since_iso: str) -> bool:
    """True if an event of this category was recorded at/after
    since_iso. Used by secure/self_update.py to answer "are we
    currently inside a known Secure Update/reload context" without
    fileintegrity (or anything else) needing its own SQL — see
    add_event()'s "self_update_context" category.
    """
    row = conn.execute(
        "SELECT 1 FROM events WHERE category = ? AND created_at >= ? LIMIT 1",
        (category, since_iso),
    ).fetchone()
    return row is not None
