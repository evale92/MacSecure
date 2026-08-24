"""
checks.py — Security posture check results (posture_checks table) — see secure/checks/.

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
class PostureCheckRecord:
    id: int
    created_at: str
    run_id: str
    check_name: str
    status: str
    message: str
    remediation: str


def add_posture_result(
    conn: sqlite3.Connection,
    run_id: str,
    check_name: str,
    status: str,
    message: str,
    remediation: str,
) -> int:
    """Insert one posture-check result row and return its new id.

    Takes plain strings rather than a secure.checks.CheckResult object
    on purpose — this module shouldn't need to import the checks
    package just to store its output.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO posture_checks "
        "(created_at, run_id, check_name, status, message, remediation) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (created_at, run_id, check_name, status, message, remediation),
    )
    conn.commit()
    return cursor.lastrowid


def list_recent_posture_results(
    conn: sqlite3.Connection, limit: int = 20
) -> list[PostureCheckRecord]:
    """Return the most recent posture-check rows, newest first.

    Note this is rows, not runs — pass a large-enough limit (or filter
    by run_id yourself) to see a whole run's worth of checks.
    """
    rows = conn.execute(
        "SELECT id, created_at, run_id, check_name, status, message, remediation "
        "FROM posture_checks ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [PostureCheckRecord(**dict(row)) for row in rows]


def last_posture_run_id(conn: sqlite3.Connection) -> str | None:
    """Return the run_id of the most recent posture check, or None if none yet."""
    row = conn.execute(
        "SELECT run_id FROM posture_checks ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["run_id"] if row else None
