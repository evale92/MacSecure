"""
bluetooth.py — Classic Bluetooth visibility: bluetooth_observations, bluetooth_devices, bluetooth_alerts — see secure/bluetooth/.

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

def add_bluetooth_observations(
    conn: sqlite3.Connection,
    run_id: str,
    rows: "list[tuple[str, str | None, bool, bool, int | None]]",
) -> None:
    """Insert one row per Bluetooth device observed in a single scan, in one commit.

    Each row: (identifier, name, paired, connected, rssi). One commit
    for the whole batch, same reasoning as add_connection_events() —
    even though a Bluetooth scan typically sees far fewer devices than
    a connections/listening scan, there's no reason to commit per-row
    here either.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT INTO bluetooth_observations "
        "(created_at, run_id, identifier, name, paired, connected, rssi) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (created_at, run_id, identifier, name, 1 if paired else 0, 1 if connected else 0, rssi)
            for identifier, name, paired, connected, rssi in rows
        ],
    )
    conn.commit()


@dataclass
class BluetoothDeviceRecord:
    id: int
    identifier: str
    name: str | None
    trusted: bool
    times_seen: int
    last_rssi: int | None
    first_seen: str
    last_seen: str
    paired: bool
    connected: bool


def _row_to_bluetooth_device(row: sqlite3.Row) -> BluetoothDeviceRecord:
    data = dict(row)
    data["trusted"] = bool(data["trusted"])
    data["paired"] = bool(data["paired"])
    data["connected"] = bool(data["connected"])
    return BluetoothDeviceRecord(**data)


def upsert_bluetooth_device(
    conn: sqlite3.Connection,
    identifier: str,
    name: "str | None",
    rssi: "int | None",
    paired: bool = False,
    connected: bool = False,
) -> tuple[BluetoothDeviceRecord, bool, bool, bool]:
    """Record a Bluetooth device seen during a scan; insert if new, update if not.

    Matched by `identifier` (the device's normalized Bluetooth
    address). A match increments `times_seen`, updates `name` (only
    overwritten with a non-empty value — an existing name is never
    replaced with nothing), `last_rssi` (overwritten every time,
    including with None, since "no RSSI this scan" is itself current
    information — unlike name, an old RSSI reading isn't more correct
    than "we don't have one right now"), `paired`/`connected` (always
    overwritten with this scan's current values), and `last_seen`;
    `first_seen` and `trusted` are left untouched. No match inserts a
    new row with `trusted=False` and `times_seen=1`.

    Returns (record, was_new, was_paired_before, was_connected_before).
    was_new is True only for a brand-new row, which is what "alert on
    newly observed devices" keys off. was_paired_before/
    was_connected_before are the device's PRIOR paired/connected state
    — read BEFORE this call overwrites it — which is what
    new-pairing/first-connection transition detection keys off (see
    secure/bluetooth/scanner.py). Both are False for a brand-new device
    (there's no prior state to compare against). times_seen on the
    returned record is what persistent-unknown-device detection keys
    off instead.
    """
    now = datetime.now(timezone.utc).isoformat()

    existing = conn.execute(
        "SELECT * FROM bluetooth_devices WHERE identifier = ?", (identifier,)
    ).fetchone()

    if existing is not None:
        device_id = existing["id"]
        new_name = name or existing["name"]
        was_paired_before = bool(existing["paired"])
        was_connected_before = bool(existing["connected"])
        conn.execute(
            "UPDATE bluetooth_devices SET name = ?, last_rssi = ?, times_seen = times_seen + 1, "
            "paired = ?, connected = ?, last_seen = ? WHERE id = ?",
            (new_name, rssi, 1 if paired else 0, 1 if connected else 0, now, device_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM bluetooth_devices WHERE id = ?", (device_id,)).fetchone()
        return _row_to_bluetooth_device(row), False, was_paired_before, was_connected_before

    cursor = conn.execute(
        "INSERT INTO bluetooth_devices "
        "(identifier, name, trusted, times_seen, last_rssi, paired, connected, first_seen, last_seen) "
        "VALUES (?, ?, 0, 1, ?, ?, ?, ?, ?)",
        (identifier, name, rssi, 1 if paired else 0, 1 if connected else 0, now, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM bluetooth_devices WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row_to_bluetooth_device(row), True, False, False


def list_bluetooth_devices(conn: sqlite3.Connection) -> list[BluetoothDeviceRecord]:
    """Return every Bluetooth device ever recorded, most recently seen first."""
    rows = conn.execute("SELECT * FROM bluetooth_devices ORDER BY last_seen DESC").fetchall()
    return [_row_to_bluetooth_device(row) for row in rows]


def find_bluetooth_device_by_id(conn: sqlite3.Connection, device_id: int) -> BluetoothDeviceRecord | None:
    row = conn.execute("SELECT * FROM bluetooth_devices WHERE id = ?", (device_id,)).fetchone()
    return _row_to_bluetooth_device(row) if row else None


def set_bluetooth_device_trusted(conn: sqlite3.Connection, device_id: int, trusted: bool) -> None:
    conn.execute(
        "UPDATE bluetooth_devices SET trusted = ? WHERE id = ?",
        (1 if trusted else 0, device_id),
    )
    conn.commit()


@dataclass
class BluetoothAlertRecord:
    id: int
    created_at: str
    run_id: str
    kind: str
    severity: str
    identifier: str
    name: str | None
    message: str
    known: bool


def _row_to_bluetooth_alert(row: sqlite3.Row) -> BluetoothAlertRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    return BluetoothAlertRecord(**data)


def add_bluetooth_alert(
    conn: sqlite3.Connection,
    run_id: str,
    kind: str,
    severity: str,
    identifier: str,
    name: "str | None",
    message: str,
) -> int:
    """Insert one bluetooth alert row and return its new id.

    One row per call, same reasoning as add_arp_alert()/add_wifi_alert():
    a scan raises at most a couple of these, and the caller wants the
    id back right away to show "mark #N known|unknown" in scan output.
    `known` defaults to 0 (unreviewed).
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO bluetooth_alerts (created_at, run_id, kind, severity, identifier, name, message, known) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
        (created_at, run_id, kind, severity, identifier, name, message),
    )
    conn.commit()
    return cursor.lastrowid


def list_bluetooth_alerts(conn: sqlite3.Connection, limit: int = 100) -> list[BluetoothAlertRecord]:
    """Return the most recent bluetooth alerts, newest first."""
    rows = conn.execute(
        "SELECT id, created_at, run_id, kind, severity, identifier, name, message, known "
        "FROM bluetooth_alerts ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_row_to_bluetooth_alert(row) for row in rows]


def find_bluetooth_alert_by_id(conn: sqlite3.Connection, alert_id: int) -> BluetoothAlertRecord | None:
    row = conn.execute("SELECT * FROM bluetooth_alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row_to_bluetooth_alert(row) if row else None


def set_bluetooth_alert_known(conn: sqlite3.Connection, alert_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE bluetooth_alerts SET known = ? WHERE id = ?",
        (1 if known else 0, alert_id),
    )
    conn.commit()


def has_bluetooth_alert_of_kind(conn: sqlite3.Connection, identifier: str, kind: str) -> bool:
    """True if this device already has an alert of this kind on record.

    Used to raise a persistent-unknown-device alert only once per
    device rather than re-raising it on every subsequent scan while it
    remains untrusted — see secure/bluetooth/scanner.py.
    """
    row = conn.execute(
        "SELECT 1 FROM bluetooth_alerts WHERE identifier = ? AND kind = ? LIMIT 1",
        (identifier, kind),
    ).fetchone()
    return row is not None
