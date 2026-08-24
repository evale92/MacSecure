"""
inventory.py — Local network device inventory (devices table) — see secure/inventory/.

Split out of the original secure/storage/models.py (Phase 14.5 Stage C)
purely mechanically — behavior, SQL, and function signatures are
unchanged; only the file this code lives in changed. See
secure/storage/models/__init__.py for the full original module
docstring and the re-export surface that preserves
`from secure.storage.models import X` for every name.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

@dataclass
class DeviceRecord:
    id: int
    mac: str | None
    ip: str
    hostname: str | None
    vendor: str | None
    friendly_name: str | None
    known: bool
    first_seen: str
    last_seen: str


def _row_to_device(row: sqlite3.Row) -> DeviceRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    return DeviceRecord(**data)


def upsert_device(
    conn: sqlite3.Connection,
    ip: str,
    mac: str | None,
    hostname: str | None,
    vendor: str | None,
) -> tuple[DeviceRecord, bool]:
    """Record a device seen during a scan; insert if new, update if not.

    Matched by MAC address when one is available (the more stable
    identity across DHCP lease renewals) — falls back to matching by
    IP for devices whose MAC wasn't captured. A match updates `ip`
    (in case it changed), `hostname`/`vendor` (only if this scan found
    a non-empty value — an existing value is never overwritten with
    nothing), and `last_seen`; `first_seen`, `known`, and
    `friendly_name` are left untouched. No match inserts a new row
    with `known=False` and no friendly name.

    Returns (record, was_new) — was_new is True only for a brand-new
    row, which is what "alert on a newly appearing device" keys off.
    """
    now = datetime.now(timezone.utc).isoformat()

    existing = None
    if mac:
        existing = conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
    else:
        existing = conn.execute(
            "SELECT * FROM devices WHERE ip = ? AND mac IS NULL", (ip,)
        ).fetchone()

    if existing is not None:
        device_id = existing["id"]
        new_hostname = hostname or existing["hostname"]
        new_vendor = vendor or existing["vendor"]
        conn.execute(
            "UPDATE devices SET ip = ?, hostname = ?, vendor = ?, last_seen = ? WHERE id = ?",
            (ip, new_hostname, new_vendor, now, device_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        return _row_to_device(row), False

    cursor = conn.execute(
        "INSERT INTO devices "
        "(mac, ip, hostname, vendor, friendly_name, known, first_seen, last_seen) "
        "VALUES (?, ?, ?, ?, NULL, 0, ?, ?)",
        (mac, ip, hostname, vendor, now, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM devices WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row_to_device(row), True


def list_devices(conn: sqlite3.Connection) -> list[DeviceRecord]:
    """Return every device ever recorded (the full historical inventory), most recently seen first."""
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    return [_row_to_device(row) for row in rows]


def find_device_by_identifier(conn: sqlite3.Connection, identifier: str) -> DeviceRecord | None:
    """Look up one device by MAC or IP address, whichever the identifier matches."""
    row = conn.execute(
        "SELECT * FROM devices WHERE mac = ? OR ip = ? ORDER BY last_seen DESC LIMIT 1",
        (identifier.lower(), identifier),
    ).fetchone()
    return _row_to_device(row) if row else None


def set_device_friendly_name(conn: sqlite3.Connection, device_id: int, name: str) -> None:
    conn.execute("UPDATE devices SET friendly_name = ? WHERE id = ?", (name, device_id))
    conn.commit()


def set_device_known(conn: sqlite3.Connection, device_id: int, known: bool) -> None:
    conn.execute("UPDATE devices SET known = ? WHERE id = ?", (1 if known else 0, device_id))
    conn.commit()


_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def delete_junk_devices(conn: sqlite3.Connection) -> int:
    """Remove device rows that shouldn't have been recorded as devices.

    Covers rows written before secure/inventory/scanner.py started
    filtering these out at scan time (see PROJECT_NOTES.md's change
    log): no MAC captured (an ARP entry for an address nothing
    answered at — an empty IP, not a device), the broadcast MAC, or a
    multicast IP (mDNS/protocol traffic, not a physical device). Safe
    to run any time — a normal scan won't recreate these rows going
    forward. Returns how many rows were removed.
    """
    rows = conn.execute("SELECT id, mac, ip FROM devices").fetchall()
    junk_ids = []
    for row in rows:
        mac = row["mac"]
        is_junk = mac is None or mac == _BROADCAST_MAC
        if not is_junk:
            try:
                is_junk = ipaddress.ip_address(row["ip"]).is_multicast
            except ValueError:
                is_junk = False
        if is_junk:
            junk_ids.append(row["id"])

    if junk_ids:
        conn.executemany("DELETE FROM devices WHERE id = ?", [(i,) for i in junk_ids])
        conn.commit()
    return len(junk_ids)
