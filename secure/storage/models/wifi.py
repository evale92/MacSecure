"""
wifi.py — Wi-Fi security monitor: wifi_observations, wifi_networks, wifi_alerts — see secure/wifi/.

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

def add_wifi_observation(
    conn: sqlite3.Connection,
    run_id: str,
    ssid: str,
    bssid: "str | None",
    channel: "str | None",
    phy_mode: "str | None",
    security: "str | None",
    rssi: "int | None",
    noise: "int | None",
) -> int:
    """Insert one Wi-Fi status snapshot row and return its new id.

    One row per call (not bulk): a wifi scan produces exactly one
    observation (this Mac's current connection), never a batch, so
    there's nothing to group into a single executemany() the way
    add_connection_events()/add_arp_observations() do for their
    50-200+-row scans.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO wifi_observations "
        "(created_at, run_id, ssid, bssid, channel, phy_mode, security, rssi, noise) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (created_at, run_id, ssid, bssid, channel, phy_mode, security, rssi, noise),
    )
    conn.commit()
    return cursor.lastrowid


@dataclass
class WifiNetworkRecord:
    id: int
    ssid: str
    bssid: str | None
    known: bool
    first_seen: str
    last_seen: str


def _row_to_wifi_network(row: sqlite3.Row) -> WifiNetworkRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    return WifiNetworkRecord(**data)


def upsert_wifi_network(
    conn: sqlite3.Connection, ssid: str, bssid: "str | None"
) -> tuple[WifiNetworkRecord, bool]:
    """Record a Wi-Fi network seen during a scan; insert if new, update if not.

    Matched by (ssid, bssid) when a BSSID was captured — falls back to
    matching by ssid alone (WHERE bssid IS NULL) for scans where the
    BSSID isn't available, the same mac-or-ip fallback pattern
    upsert_device() uses. A match only updates `last_seen`; `first_seen`
    and `known` are left untouched. No match inserts a new row with
    `known=False`.

    Note: if a network's BSSID later becomes available after being
    recorded without one (e.g. Location Services permission is granted
    to this process after the fact), that BSSID-aware scan will insert
    a second, separate row rather than upgrading the existing one —
    a known, minor limitation, same spirit as the "some lsof rows are
    incomplete without sudo" honesty elsewhere in this app.

    Returns (record, was_new) — was_new is True only for a brand-new
    row, which is what "warn when joining an unknown network" and
    "flag a new BSSID for a known SSID" key off.
    """
    now = datetime.now(timezone.utc).isoformat()

    if bssid:
        existing = conn.execute(
            "SELECT * FROM wifi_networks WHERE ssid = ? AND bssid = ?", (ssid, bssid)
        ).fetchone()
    else:
        existing = conn.execute(
            "SELECT * FROM wifi_networks WHERE ssid = ? AND bssid IS NULL", (ssid,)
        ).fetchone()

    if existing is not None:
        network_id = existing["id"]
        conn.execute("UPDATE wifi_networks SET last_seen = ? WHERE id = ?", (now, network_id))
        conn.commit()
        row = conn.execute("SELECT * FROM wifi_networks WHERE id = ?", (network_id,)).fetchone()
        return _row_to_wifi_network(row), False

    cursor = conn.execute(
        "INSERT INTO wifi_networks (ssid, bssid, known, first_seen, last_seen) "
        "VALUES (?, ?, 0, ?, ?)",
        (ssid, bssid, now, now),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM wifi_networks WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row_to_wifi_network(row), True


def list_wifi_networks(conn: sqlite3.Connection) -> list[WifiNetworkRecord]:
    """Return every Wi-Fi network ever recorded, most recently seen first."""
    rows = conn.execute("SELECT * FROM wifi_networks ORDER BY last_seen DESC").fetchall()
    return [_row_to_wifi_network(row) for row in rows]


def find_wifi_network_by_id(conn: sqlite3.Connection, network_id: int) -> WifiNetworkRecord | None:
    row = conn.execute("SELECT * FROM wifi_networks WHERE id = ?", (network_id,)).fetchone()
    return _row_to_wifi_network(row) if row else None


def set_wifi_network_known(conn: sqlite3.Connection, network_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE wifi_networks SET known = ? WHERE id = ?",
        (1 if known else 0, network_id),
    )
    conn.commit()


def list_known_ssids(conn: sqlite3.Connection) -> list[str]:
    """Return the distinct SSIDs of every network marked known — what
    secure/wifi/scanner.py compares a newly-seen SSID against to spot a
    suspicious lookalike name.
    """
    rows = conn.execute("SELECT DISTINCT ssid FROM wifi_networks WHERE known = 1").fetchall()
    return [row["ssid"] for row in rows]


@dataclass
class WifiAlertRecord:
    id: int
    created_at: str
    run_id: str
    kind: str
    severity: str
    ssid: str
    bssid: str | None
    message: str
    known: bool


def _row_to_wifi_alert(row: sqlite3.Row) -> WifiAlertRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    return WifiAlertRecord(**data)


def add_wifi_alert(
    conn: sqlite3.Connection,
    run_id: str,
    kind: str,
    severity: str,
    ssid: str,
    bssid: "str | None",
    message: str,
) -> int:
    """Insert one wifi alert row and return its new id.

    One row per call, same reasoning as add_arp_alert(): a scan raises
    at most a couple of these, and the caller wants the id back right
    away to show "mark #N known|unknown" in the scan output. `known`
    defaults to 0 (unreviewed).
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO wifi_alerts (created_at, run_id, kind, severity, ssid, bssid, message, known) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
        (created_at, run_id, kind, severity, ssid, bssid, message),
    )
    conn.commit()
    return cursor.lastrowid


def list_wifi_alerts(conn: sqlite3.Connection, limit: int = 100) -> list[WifiAlertRecord]:
    """Return the most recent wifi alerts, newest first."""
    rows = conn.execute(
        "SELECT id, created_at, run_id, kind, severity, ssid, bssid, message, known "
        "FROM wifi_alerts ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    return [_row_to_wifi_alert(row) for row in rows]


def find_wifi_alert_by_id(conn: sqlite3.Connection, alert_id: int) -> WifiAlertRecord | None:
    row = conn.execute("SELECT * FROM wifi_alerts WHERE id = ?", (alert_id,)).fetchone()
    return _row_to_wifi_alert(row) if row else None


def set_wifi_alert_known(conn: sqlite3.Connection, alert_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE wifi_alerts SET known = ? WHERE id = ?",
        (1 if known else 0, alert_id),
    )
    conn.commit()
