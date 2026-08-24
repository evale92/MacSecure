"""
ble.py — Live BLE visibility: ble_observations, ble_peripherals, ble_alerts — see secure/bluetooth/ble/.

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

def add_ble_observations(
    conn: sqlite3.Connection,
    run_id: str,
    rows: "list[tuple[str, str | None, int | None, str | None, str | None]]",
) -> None:
    """Insert one row per BLE peripheral advertisement observed in a
    single live scan, in one commit. Each row: (cb_uuid, name, rssi,
    service_uuids_json, manufacturer_data_json). Same bulk-insert-per-
    scan reasoning as add_bluetooth_observations() etc.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT INTO ble_observations "
        "(created_at, run_id, cb_uuid, name, rssi, service_uuids, manufacturer_data) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(created_at, run_id, *row) for row in rows],
    )
    conn.commit()


@dataclass
class BlePeripheralRecord:
    id: int
    cb_uuid: str
    name: str | None
    trusted: bool
    times_seen: int
    first_rssi: int | None
    last_rssi: int | None
    first_seen: str
    last_seen: str


def _row_to_ble_peripheral(row: sqlite3.Row) -> BlePeripheralRecord:
    data = dict(row)
    data["trusted"] = bool(data["trusted"])
    return BlePeripheralRecord(**data)


def upsert_ble_peripheral(
    conn: sqlite3.Connection, cb_uuid: str, name: "str | None", rssi: "int | None"
) -> tuple[BlePeripheralRecord, bool, "int | None"]:
    """Record a BLE peripheral seen during a live scan; insert if new, update if not.

    Matched by `cb_uuid` — see database.py's schema comment for why
    this is a separate identifier space from bluetooth_devices'
    Bluetooth-address identifiers, not merged with it. A match
    increments `times_seen`, updates `name` (only overwritten with a
    non-empty value, same as upsert_bluetooth_device()), `last_rssi`
    (always overwritten, including with None), and `last_seen`;
    `first_seen`, `first_rssi`, and `trusted` are left untouched. No
    match inserts a new row with `trusted=False`, `times_seen=1`, and
    `first_rssi` set to this scan's rssi (the baseline later RSSI
    changes are compared against — see secure/bluetooth/ble/analysis.py).

    Returns (record, was_new, previous_rssi) — was_new is True only for
    a brand-new row, which is what "new BLE peripheral" surfacing keys
    off. previous_rssi is the peripheral's last_rssi BEFORE this call
    overwrote it (None for a brand-new peripheral, or if no RSSI was
    ever recorded before) — what significant-RSSI-change detection
    keys off (see secure/bluetooth/ble/scanner.py), since by the time
    the returned `record` comes back, its last_rssi already reflects
    *this* scan.
    """
    now = datetime.now(timezone.utc).isoformat()

    existing = conn.execute(
        "SELECT * FROM ble_peripherals WHERE cb_uuid = ?", (cb_uuid,)
    ).fetchone()

    if existing is not None:
        peripheral_id = existing["id"]
        new_name = name or existing["name"]
        previous_rssi = existing["last_rssi"]
        conn.execute(
            "UPDATE ble_peripherals SET name = ?, last_rssi = ?, times_seen = times_seen + 1, "
            "last_seen = ? WHERE id = ?",
            (new_name, rssi, now, peripheral_id),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM ble_peripherals WHERE id = ?", (peripheral_id,)
        ).fetchone()
        return _row_to_ble_peripheral(row), False, previous_rssi

    cursor = conn.execute(
        "INSERT INTO ble_peripherals "
        "(cb_uuid, name, trusted, times_seen, first_rssi, last_rssi, first_seen, last_seen) "
        "VALUES (?, ?, 0, 1, ?, ?, ?, ?)",
        (cb_uuid, name, rssi, rssi, now, now),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM ble_peripherals WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return _row_to_ble_peripheral(row), True, None


def list_ble_peripherals(conn: sqlite3.Connection) -> list[BlePeripheralRecord]:
    """Return every BLE peripheral ever recorded, most recently seen first."""
    rows = conn.execute("SELECT * FROM ble_peripherals ORDER BY last_seen DESC").fetchall()
    return [_row_to_ble_peripheral(row) for row in rows]


def find_ble_peripheral_by_id(conn: sqlite3.Connection, peripheral_id: int) -> BlePeripheralRecord | None:
    row = conn.execute("SELECT * FROM ble_peripherals WHERE id = ?", (peripheral_id,)).fetchone()
    return _row_to_ble_peripheral(row) if row else None


def set_ble_peripheral_trusted(conn: sqlite3.Connection, peripheral_id: int, trusted: bool) -> None:
    conn.execute(
        "UPDATE ble_peripherals SET trusted = ? WHERE id = ?",
        (1 if trusted else 0, peripheral_id),
    )
    conn.commit()


@dataclass
class BleAlertRecord:
    id: int
    created_at: str
    run_id: str
    kind: str
    severity: str
    cb_uuid: str
    name: str | None
    message: str
    known: bool


def _row_to_ble_alert(row: sqlite3.Row) -> BleAlertRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    return BleAlertRecord(**data)


def add_ble_alert(
    conn: sqlite3.Connection,
    run_id: str,
    kind: str,
    severity: str,
    cb_uuid: str,
    name: "str | None",
    message: str,
) -> int:
    """Insert one BLE alert row and return its new id. One row per
    call, same reasoning as add_bluetooth_alert(). `known` defaults to
    0 (unreviewed).
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO ble_alerts (created_at, run_id, kind, severity, cb_uuid, name, message, known) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
        (created_at, run_id, kind, severity, cb_uuid, name, message),
    )
    conn.commit()
    return cursor.lastrowid


def list_ble_alerts(conn: sqlite3.Connection, limit: int = 100) -> list[BleAlertRecord]:
    """Return the most recent BLE alerts, newest first."""
    rows = conn.execute(
        "SELECT id, created_at, run_id, kind, severity, cb_uuid, name, message, known "
        "FROM ble_alerts ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_row_to_ble_alert(row) for row in rows]


def find_ble_alert_by_id(conn: sqlite3.Connection, alert_id: int) -> BleAlertRecord | None:
    row = conn.execute("SELECT * FROM ble_alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row_to_ble_alert(row) if row else None


def set_ble_alert_known(conn: sqlite3.Connection, alert_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE ble_alerts SET known = ? WHERE id = ?",
        (1 if known else 0, alert_id),
    )
    conn.commit()


def has_ble_alert_of_kind(conn: sqlite3.Connection, cb_uuid: str, kind: str) -> bool:
    """True if this peripheral already has an alert of this kind on record.

    Used to raise a persistent-unknown-peripheral alert only once per
    peripheral rather than every scan it remains untrusted — same
    pattern as has_bluetooth_alert_of_kind().
    """
    row = conn.execute(
        "SELECT 1 FROM ble_alerts WHERE cb_uuid = ? AND kind = ? LIMIT 1",
        (cb_uuid, kind),
    ).fetchone()
    return row is not None
