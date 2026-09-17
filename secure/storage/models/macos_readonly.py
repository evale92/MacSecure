"""
macos_readonly.py — reads SQLite databases that belong to macOS, not to
Secure: the TCC permission store and the LaunchServices quarantine
event log.

ARCHITECTURE_RULES rule 4 keeps every SQL statement in this package, and
that includes queries against files Secure did not create. Nothing here
touches Secure's own database or schema.

**Never writes, and never creates a file next to the one it reads.** A
plain `mode=ro` open can still create `-shm`/`-journal` files beside the
database, which would be a write outside the app directory (invariant
12). `immutable=1` tells SQLite the file cannot change, so it opens no
lock and creates nothing. Both databases use `journal_mode=delete`
(measured 2026-09-16), so there is no WAL whose rows `immutable` would
skip. A read that races an in-progress write can fail. That surfaces as
`MacDatabaseUnavailable` for the caller to report, and never as an empty
result.

An unreadable TCC.db is normal without Full Disk Access. That too is
`MacDatabaseUnavailable`, carrying the reason, never "no grants".
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote


class MacDatabaseUnavailable(Exception):
    """The database is missing, unreadable, or not the shape expected."""


@dataclass
class TccGrant:
    service: str        # e.g. kTCCServiceSystemPolicyAllFiles
    client: str         # bundle id, or an absolute path when client_type is 1
    client_type: int    # 0 bundle id, 1 absolute path
    auth_value: int     # 0 denied, 1 unknown, 2 allowed, 3 limited
    last_modified: "int | None"


@dataclass
class QuarantineEvent:
    identifier: str
    timestamp: "float | None"   # Unix seconds (converted from Cocoa epoch)
    agent_bundle_id: str
    agent_name: str
    data_url: str
    origin_url: str
    sender_name: str
    type_number: "int | None"


# Seconds between the Unix epoch and Cocoa's 2001-01-01 reference date.
_COCOA_EPOCH_OFFSET = 978307200


def _open_readonly(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise MacDatabaseUnavailable(f"{path}: not found")
    uri = f"file:{quote(str(path))}?mode=ro&immutable=1"
    try:
        return sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise MacDatabaseUnavailable(f"{path}: {type(exc).__name__}: {exc}") from exc


def read_tcc_grants(path: Path) -> "list[TccGrant]":
    """Every row of a TCC.db `access` table."""
    try:
        conn = _open_readonly(path)
    except MacDatabaseUnavailable:
        raise
    try:
        rows = conn.execute(
            "SELECT service, client, client_type, auth_value, last_modified "
            "FROM access ORDER BY service, client"
        ).fetchall()
    except sqlite3.Error as exc:
        # "unable to open database file" arrives here without Full Disk Access.
        raise MacDatabaseUnavailable(f"{path}: {type(exc).__name__}: {exc}") from exc
    finally:
        conn.close()
    return [
        TccGrant(str(s), str(c), int(ct or 0), int(av if av is not None else 1), lm)
        for s, c, ct, av, lm in rows
    ]


def read_quarantine_events(
    path: Path, since_unix: float, limit: int, require_url: bool = False
) -> "list[QuarantineEvent]":
    """Quarantine events at or after `since_unix`, newest first, at most `limit`.

    require_url drops events with neither a file nor an origin URL. Chrome
    writes hundreds of those a day, and they say nothing about provenance.
    """
    conn = _open_readonly(path)
    try:
        rows = conn.execute(
            "SELECT LSQuarantineEventIdentifier, LSQuarantineTimeStamp, "
            "LSQuarantineAgentBundleIdentifier, LSQuarantineAgentName, "
            "LSQuarantineDataURLString, LSQuarantineOriginURLString, "
            "LSQuarantineSenderName, LSQuarantineTypeNumber "
            "FROM LSQuarantineEvent WHERE LSQuarantineTimeStamp >= ? "
            + ("AND (COALESCE(LSQuarantineDataURLString, '') != '' "
               "OR COALESCE(LSQuarantineOriginURLString, '') != '') " if require_url else "")
            + "ORDER BY LSQuarantineTimeStamp DESC LIMIT ?",
            (since_unix - _COCOA_EPOCH_OFFSET, int(limit)),
        ).fetchall()
    except sqlite3.Error as exc:
        raise MacDatabaseUnavailable(f"{path}: {type(exc).__name__}: {exc}") from exc
    finally:
        conn.close()
    return [
        QuarantineEvent(
            identifier=str(ident),
            timestamp=None if ts is None else float(ts) + _COCOA_EPOCH_OFFSET,
            agent_bundle_id=bundle or "",
            agent_name=agent or "",
            data_url=data or "",
            origin_url=origin or "",
            sender_name=sender or "",
            type_number=type_number,
        )
        for ident, ts, bundle, agent, data, origin, sender, type_number in rows
    ]
