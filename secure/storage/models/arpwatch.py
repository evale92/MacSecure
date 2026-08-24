"""
arpwatch.py — ARP/neighbor table monitoring: arp_observations, arp_mappings, arp_alerts — see secure/arpwatch/.

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

def add_arp_observations(
    conn: sqlite3.Connection, run_id: str, rows: "list[tuple[str, str, str | None]]"
) -> None:
    """Insert one row per real ARP entry observed in a single scan, in one commit.

    Each row: (ip, mac, hostname).
    """
    created_at = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT INTO arp_observations (created_at, run_id, ip, mac, hostname) VALUES (?, ?, ?, ?, ?)",
        [(created_at, run_id, *row) for row in rows],
    )
    conn.commit()


@dataclass
class ArpMappingRecord:
    id: int
    ip: str
    mac: str
    is_gateway: bool
    first_seen: str
    last_seen: str


def _row_to_arp_mapping(row: sqlite3.Row) -> ArpMappingRecord:
    data = dict(row)
    data["is_gateway"] = bool(data["is_gateway"])
    return ArpMappingRecord(**data)


def upsert_arp_mapping(
    conn: sqlite3.Connection, ip: str, mac: str, is_gateway: bool
) -> tuple[ArpMappingRecord, bool]:
    """Record this Mac's current IP -> MAC mapping for one address.

    Matched by `ip` — the whole point of this table is "what MAC does
    this IP currently resolve to," so a match always updates `mac` (to
    whatever this scan just saw) and `is_gateway`, plus `last_seen`;
    `first_seen` is left untouched. No match inserts a new row.

    Returns (record, was_new). Note this function does NOT itself
    decide whether a MAC change is alert-worthy — the caller
    (secure/arpwatch/scanner.py) reads the previous mapping BEFORE
    calling this, and runs that comparison through
    secure/arpwatch/analysis.py first.
    """
    now = datetime.now(timezone.utc).isoformat()

    existing = conn.execute("SELECT * FROM arp_mappings WHERE ip = ?", (ip,)).fetchone()
    if existing is not None:
        mapping_id = existing["id"]
        conn.execute(
            "UPDATE arp_mappings SET mac = ?, is_gateway = ?, last_seen = ? WHERE id = ?",
            (mac, 1 if is_gateway else 0, now, mapping_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM arp_mappings WHERE id = ?", (mapping_id,)).fetchone()
        return _row_to_arp_mapping(row), False

    cursor = conn.execute(
        "INSERT INTO arp_mappings (ip, mac, is_gateway, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
        (ip, mac, 1 if is_gateway else 0, now, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM arp_mappings WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row_to_arp_mapping(row), True


def list_arp_mappings(conn: sqlite3.Connection) -> list[ArpMappingRecord]:
    """Return this Mac's current IP -> MAC mapping for every IP ever seen."""
    rows = conn.execute("SELECT * FROM arp_mappings ORDER BY ip").fetchall()
    return [_row_to_arp_mapping(row) for row in rows]


@dataclass
class ArpAlertRecord:
    id: int
    created_at: str
    run_id: str
    kind: str
    severity: str
    ip: str
    mac: str | None
    previous_mac: str | None
    message: str
    known: bool


def _row_to_arp_alert(row: sqlite3.Row) -> ArpAlertRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    return ArpAlertRecord(**data)


def add_arp_alert(
    conn: sqlite3.Connection,
    run_id: str,
    kind: str,
    severity: str,
    ip: str,
    mac: "str | None",
    previous_mac: "str | None",
    message: str,
) -> int:
    """Insert one arpwatch alert row and return its new id.

    One row per call (not bulk, unlike add_connection_events/
    add_listening_events) on purpose: a scan raises at most a handful
    of alerts, never the 50-200+ rows those history tables can see, and
    the CLI/GUI want each alert's id immediately (to show "mark #N
    known|unknown" right in the scan output) rather than a separate
    lookup after the fact. `known` defaults to 0 (unreviewed).
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO arp_alerts "
        "(created_at, run_id, kind, severity, ip, mac, previous_mac, message, known) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
        (created_at, run_id, kind, severity, ip, mac, previous_mac, message),
    )
    conn.commit()
    return cursor.lastrowid


def list_arp_alerts(conn: sqlite3.Connection, limit: int = 100) -> list[ArpAlertRecord]:
    """Return the most recent arpwatch alerts, newest first."""
    rows = conn.execute(
        "SELECT id, created_at, run_id, kind, severity, ip, mac, previous_mac, message, known "
        "FROM arp_alerts ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_row_to_arp_alert(row) for row in rows]


def find_arp_alert_by_id(conn: sqlite3.Connection, alert_id: int) -> ArpAlertRecord | None:
    row = conn.execute("SELECT * FROM arp_alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row_to_arp_alert(row) if row else None


def set_arp_alert_known(conn: sqlite3.Connection, alert_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE arp_alerts SET known = ? WHERE id = ?",
        (1 if known else 0, alert_id),
    )
    conn.commit()
