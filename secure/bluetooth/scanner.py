"""
bluetooth/scanner.py — orchestrates one Bluetooth visibility scan:
read whatever `system_profiler SPBluetoothDataType` reports (see
parser.py for the important scope limitation — this is paired/
configured/connected devices, not a live nearby-BLE scan), compare
against everything this app already knows, and flag what's worth a
look.

Three things happen on every scan:

    1. New device tracking (upsert_bluetooth_device) — a first-time
       device is what "alert on newly observed devices" keys off. Same
       new-entity-defaults-to-untrusted pattern as
       devices/remote_endpoints/listening_services/wifi_networks,
       just using this domain's own "trusted" vocabulary instead of
       "known".
    2. Pairing/connection transition detection — upsert_bluetooth_device
       reports each device's PRIOR paired/connected state (read before
       this scan's values overwrite it). For an already-known,
       UNTRUSTED device: unpaired -> paired raises a HIGH severity
       "new pairing" alert; not-connected -> connected (first time)
       raises a MEDIUM severity "first connection" alert. Trusted
       devices never raise either — pairing/connecting is expected
       behavior for something you've already vouched for. Both
       messages explicitly say this does not prove an attack, while
       still saying the pairing/connection itself is worth a look
       since it's a real, deliberate state change, not just proximity.
    3. Persistent-unknown-device detection — once an untrusted device
       has shown up in several separate scans (_PERSISTENT_THRESHOLD),
       a single alert is raised (and never repeated for the same
       device — see has_bluetooth_alert_of_kind()) noting that it
       keeps appearing without being marked trusted. Per the Claude
       prompt this phase was built from ("avoid claiming that
       proximity alone means malicious activity"), the alert is
       deliberately low severity and its message says explicitly that
       this is usually innocent — nearby presence alone is a much
       weaker signal than an actual pairing/connection event, hence
       the lower severity than (2).

This module never attempts pairing, interception, exploitation, or any
other kind of unauthorized access — it only reads what macOS itself
already reports about devices it already knows about.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from secure.bluetooth._shell import run
from secure.bluetooth.parser import (
    normalize_bluetooth_address,
    parse_rssi,
    parse_system_profiler_bluetooth,
)
from secure.storage.models import (
    BluetoothDeviceRecord,
    add_bluetooth_alert,
    add_bluetooth_observations,
    has_bluetooth_alert_of_kind,
    upsert_bluetooth_device,
)

# How many separate scans an untrusted device must appear in before
# it's flagged as "persistently nearby" — conservative on purpose, so
# a single one-off sighting (a delivery driver's phone, a visitor's
# AirPods) never gets flagged; only a pattern across multiple scans
# does.
_PERSISTENT_THRESHOLD = 3


@dataclass
class BluetoothEntry:
    identifier: str
    name: Optional[str]
    paired: bool
    connected: bool
    rssi: Optional[int]


@dataclass
class BluetoothAlert:
    kind: str  # "persistent_unknown", "new_pairing", or "first_connection"
    severity: str
    identifier: str
    name: Optional[str]
    message: str
    id: Optional[int] = None


@dataclass
class BluetoothScanResult:
    scanned_at: str
    run_id: str
    bluetooth_available: bool = True
    entries: List[BluetoothEntry] = field(default_factory=list)
    new_devices: List[BluetoothDeviceRecord] = field(default_factory=list)
    alerts: List[BluetoothAlert] = field(default_factory=list)


def scan_bluetooth(conn: sqlite3.Connection) -> BluetoothScanResult:
    """Run one Bluetooth visibility scan and record the results.

    Returns bluetooth_available=False (nothing recorded) if
    `system_profiler SPBluetoothDataType` couldn't be run or didn't
    finish in time.
    """
    now = datetime.now(timezone.utc).isoformat()
    run_id = uuid.uuid4().hex[:12]

    result = run(["system_profiler", "SPBluetoothDataType"], timeout=10.0)
    if not result.ok:
        return BluetoothScanResult(scanned_at=now, run_id=run_id, bluetooth_available=False)

    parsed = parse_system_profiler_bluetooth(result.stdout)

    entries: List[BluetoothEntry] = []
    for item in parsed:
        identifier = normalize_bluetooth_address(item.get("address"))
        if not identifier:
            continue  # can't track a device without a stable identifier
        entries.append(
            BluetoothEntry(
                identifier=identifier,
                name=item.get("name"),
                paired=bool(item.get("paired")),
                connected=bool(item.get("connected")),
                rssi=parse_rssi(item.get("rssi_raw")),
            )
        )

    obs_rows = [(e.identifier, e.name, e.paired, e.connected, e.rssi) for e in entries]
    if obs_rows:
        add_bluetooth_observations(conn, run_id=run_id, rows=obs_rows)

    new_devices: List[BluetoothDeviceRecord] = []
    alerts: List[BluetoothAlert] = []
    for entry in entries:
        record, was_new, was_paired_before, was_connected_before = upsert_bluetooth_device(
            conn,
            identifier=entry.identifier,
            name=entry.name,
            rssi=entry.rssi,
            paired=entry.paired,
            connected=entry.connected,
        )
        if was_new:
            new_devices.append(record)
            continue

        # Pairing/connection transitions — only meaningful for a device
        # that isn't already trusted. A trusted device pairing or
        # connecting is exactly what you'd expect from something you've
        # already vouched for.
        if not record.trusted:
            if not was_paired_before and record.paired:
                label = entry.name or entry.identifier
                message = (
                    f"'{label}' just became paired with this Mac, and it is not marked "
                    "trusted. This does not prove an attack — you may have paired it "
                    "yourself just now, or approved a pairing prompt without recognizing "
                    "the name. But an unrecognized device becoming paired is a real, "
                    "deliberate state change (not just proximity), so it's worth "
                    "confirming you did this before dismissing it."
                )
                alert = BluetoothAlert(
                    kind="new_pairing",
                    severity="high",
                    identifier=entry.identifier,
                    name=entry.name,
                    message=message,
                )
                alert.id = add_bluetooth_alert(
                    conn,
                    run_id=run_id,
                    kind=alert.kind,
                    severity=alert.severity,
                    identifier=alert.identifier,
                    name=alert.name,
                    message=alert.message,
                )
                alerts.append(alert)

            if not was_connected_before and record.connected:
                label = entry.name or entry.identifier
                message = (
                    f"'{label}' just connected to this Mac for the first time, and it "
                    "is not marked trusted. This is often completely innocent — a device "
                    "you own but haven't marked trusted yet, or one that auto-connects "
                    "once paired. It does not prove an attack, but a first connection "
                    "from an unrecognized device is worth a quick look."
                )
                alert = BluetoothAlert(
                    kind="first_connection",
                    severity="medium",
                    identifier=entry.identifier,
                    name=entry.name,
                    message=message,
                )
                alert.id = add_bluetooth_alert(
                    conn,
                    run_id=run_id,
                    kind=alert.kind,
                    severity=alert.severity,
                    identifier=alert.identifier,
                    name=alert.name,
                    message=alert.message,
                )
                alerts.append(alert)

        if (
            not record.trusted
            and record.times_seen >= _PERSISTENT_THRESHOLD
            and not has_bluetooth_alert_of_kind(conn, entry.identifier, "persistent_unknown")
        ):
            label = entry.name or entry.identifier
            message = (
                f"'{label}' has now been seen nearby in {record.times_seen} separate scans "
                "without being marked trusted. This is often completely innocent — a "
                "neighbor's device, a smart-home accessory, a household member's device, or "
                "one of your own you just haven't marked trusted yet. Proximity alone is not "
                "evidence of anything malicious; this is only worth a closer look if you "
                "genuinely don't recognize it."
            )
            alert = BluetoothAlert(
                kind="persistent_unknown",
                severity="low",
                identifier=entry.identifier,
                name=entry.name,
                message=message,
            )
            alert.id = add_bluetooth_alert(
                conn,
                run_id=run_id,
                kind=alert.kind,
                severity=alert.severity,
                identifier=alert.identifier,
                name=alert.name,
                message=alert.message,
            )
            alerts.append(alert)

    return BluetoothScanResult(
        scanned_at=now,
        run_id=run_id,
        bluetooth_available=True,
        entries=entries,
        new_devices=new_devices,
        alerts=alerts,
    )
