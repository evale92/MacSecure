"""
bluetooth/ble/scanner.py — orchestrates one live BLE discovery scan via
Bleak: run a timed scan, compare what's found against everything this
app already knows, and flag what's worth a look.

Severity rationale (this is the live-BLE half of the full Bluetooth
severity table — see secure/bluetooth/scanner.py for the
system_profiler/pairing half):

    - A brand-new nearby peripheral is INFORMATIONAL — surfaced via a
      NEW tag in scan output (same pattern every *_devices/*_networks
      table in this app uses), not a stored alert. Nearby presence
      alone is the weakest possible signal; per the Claude prompt this
      whole feature was built from, it must never be treated as
      evidence of an attack.
    - A persistently-seen, still-untrusted peripheral (>=
      PERSISTENT_THRESHOLD separate scans) is LOW severity — a
      repeated pattern is a slightly stronger signal than one sighting,
      but still routinely innocent (a neighbor's phone, a household
      smart-home gadget), especially given real BLE devices legitimately
      rotate addresses for privacy (see the module docstring in
      secure/bluetooth/ble/__init__.py) — so even "persistent" here is
      a floor, not proof of anything.
    - A significant RSSI swing (>= RSSI_CHANGE_THRESHOLD dBm) is LOW
      severity — could mean the device moved, or just environmental
      interference; RSSI is a rough proxy, not a location system.

Both of these alert kinds are deliberately less severe than
secure/bluetooth/scanner.py's pairing-transition alerts: an unrecognized
device pairing or connecting is a real, deliberate state change; a
BLE peripheral merely being audible nearby is not.

This module never attempts pairing, connecting, interception,
exploitation, jamming, spoofing, deauthentication, or any other kind of
unauthorized access — it only listens to advertisements any nearby BLE
peripheral already broadcasts publicly, exactly like any phone's
Bluetooth settings screen would.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from secure.bluetooth.ble.analysis import (
    RSSI_CHANGE_THRESHOLD,
    is_persistent_and_unknown,
    rssi_significant_change,
)
from secure.bluetooth.ble.state import STATE_POWERED_ON, check_bluetooth_state
from secure.storage.models import (
    BlePeripheralRecord,
    add_ble_alert,
    add_ble_observations,
    has_ble_alert_of_kind,
    upsert_ble_peripheral,
)

_DEFAULT_SCAN_DURATION = 8.0


@dataclass
class BleEntry:
    cb_uuid: str
    name: Optional[str]
    rssi: Optional[int]
    service_uuids: List[str]
    manufacturer_data: Dict[str, str]  # company id (hex string) -> payload (hex string)


@dataclass
class BleAlert:
    kind: str  # "persistent_unknown" or "rssi_significant_change"
    severity: str
    cb_uuid: str
    name: Optional[str]
    message: str
    id: Optional[int] = None


@dataclass
class BleScanResult:
    scanned_at: str
    run_id: str
    ble_available: bool = True
    # Set only when ble_available is False: "poweredOff", "unauthorized",
    # "unsupported", "resetting", "unknown", or "error" — see
    # secure/bluetooth/ble/state.py's STATE_* constants. Never treated
    # as "zero nearby peripherals" — that's a genuinely different,
    # successful outcome (entries == [] with ble_available == True).
    unavailable_reason: Optional[str] = None
    unavailable_detail: Optional[str] = None
    entries: List[BleEntry] = field(default_factory=list)
    new_peripherals: List[BlePeripheralRecord] = field(default_factory=list)
    alerts: List[BleAlert] = field(default_factory=list)


def _discover(duration: float):
    """Thin seam around Bleak's async scan — the ONE place tests patch
    instead of touching asyncio/Bleak directly, same "pure function +
    thin wrapper" pattern every other package's _shell.py follows for
    subprocess calls. Returns exactly what
    `BleakScanner.discover(return_adv=True)` returns: a dict mapping
    address -> (BLEDevice, AdvertisementData).

    The `bleak` import happens here, not at module load time, so this
    module can still be imported (and its callers' logic exercised via
    monkeypatching this function) on a machine/sandbox without bleak
    installed.
    """
    from bleak import BleakScanner  # noqa: PLC0415 - deliberately lazy, see docstring

    async def _run():
        return await BleakScanner.discover(timeout=duration, return_adv=True)

    return asyncio.run(_run())


def scan_ble_peripherals(
    conn: sqlite3.Connection, duration: float = _DEFAULT_SCAN_DURATION
) -> BleScanResult:
    """Run one live BLE discovery scan and record the results.

    Checks Bluetooth's power/authorization state first (see
    secure/bluetooth/ble/state.py) — a scan is only attempted when
    state is confirmed poweredOn. Any other state (or any error talking
    to Bleak) comes back as ble_available=False with a specific
    unavailable_reason, never silently reported as "zero peripherals
    found."
    """
    now = datetime.now(timezone.utc).isoformat()
    run_id = uuid.uuid4().hex[:12]

    state = check_bluetooth_state()
    if state.state_name != STATE_POWERED_ON:
        return BleScanResult(
            scanned_at=now,
            run_id=run_id,
            ble_available=False,
            unavailable_reason=state.state_name,
            unavailable_detail=state.detail,
        )

    try:
        raw = _discover(duration)
    except Exception as e:
        return BleScanResult(
            scanned_at=now,
            run_id=run_id,
            ble_available=False,
            unavailable_reason="error",
            unavailable_detail=f"Bleak scan raised {type(e).__name__}: {e}",
        )

    entries: List[BleEntry] = []
    for address, pair in (raw or {}).items():
        device, adv = pair
        raw_manufacturer_data = getattr(adv, "manufacturer_data", None) or {}
        manufacturer_data = {
            (f"0x{company_id:04x}" if isinstance(company_id, int) else str(company_id)): (
                payload.hex() if isinstance(payload, (bytes, bytearray)) else str(payload)
            )
            for company_id, payload in raw_manufacturer_data.items()
        }
        name = getattr(adv, "local_name", None) or getattr(device, "name", None)
        entries.append(
            BleEntry(
                cb_uuid=address,
                name=name,
                rssi=getattr(adv, "rssi", None),
                service_uuids=list(getattr(adv, "service_uuids", None) or []),
                manufacturer_data=manufacturer_data,
            )
        )

    obs_rows = [
        (e.cb_uuid, e.name, e.rssi, json.dumps(e.service_uuids), json.dumps(e.manufacturer_data))
        for e in entries
    ]
    if obs_rows:
        add_ble_observations(conn, run_id=run_id, rows=obs_rows)

    new_peripherals: List[BlePeripheralRecord] = []
    alerts: List[BleAlert] = []
    for entry in entries:
        record, was_new, previous_rssi = upsert_ble_peripheral(
            conn, cb_uuid=entry.cb_uuid, name=entry.name, rssi=entry.rssi
        )
        if was_new:
            new_peripherals.append(record)
            continue

        if rssi_significant_change(previous_rssi, entry.rssi, RSSI_CHANGE_THRESHOLD):
            label = entry.name or entry.cb_uuid
            message = (
                f"'{label}'s signal strength changed by at least {RSSI_CHANGE_THRESHOLD} dBm "
                f"since last seen (was {previous_rssi}, now {entry.rssi}). This could mean "
                "the device moved closer or further away, or it could just be environmental "
                "interference — RSSI is a rough proxy, not a precise distance or location "
                "measurement, and this is not evidence of anything malicious on its own."
            )
            alert = BleAlert(
                kind="rssi_significant_change",
                severity="low",
                cb_uuid=entry.cb_uuid,
                name=entry.name,
                message=message,
            )
            alert.id = add_ble_alert(
                conn,
                run_id=run_id,
                kind=alert.kind,
                severity=alert.severity,
                cb_uuid=alert.cb_uuid,
                name=alert.name,
                message=alert.message,
            )
            alerts.append(alert)

        if is_persistent_and_unknown(record.times_seen, record.trusted) and not has_ble_alert_of_kind(
            conn, entry.cb_uuid, "persistent_unknown"
        ):
            label = entry.name or entry.cb_uuid
            message = (
                f"A BLE peripheral ('{label}') has now been seen advertising nearby in "
                f"{record.times_seen} separate scans without being marked trusted. This is "
                "often completely innocent — a neighbor's device, a smart-home accessory, "
                "or one of your own you haven't marked trusted yet. Remember that many "
                "modern devices rotate their advertised address every ~15 minutes for "
                "privacy, so this count is likely a floor, not an exact number of distinct "
                "physical devices. Proximity alone is not evidence of anything malicious."
            )
            alert = BleAlert(
                kind="persistent_unknown",
                severity="low",
                cb_uuid=entry.cb_uuid,
                name=entry.name,
                message=message,
            )
            alert.id = add_ble_alert(
                conn,
                run_id=run_id,
                kind=alert.kind,
                severity=alert.severity,
                cb_uuid=alert.cb_uuid,
                name=alert.name,
                message=alert.message,
            )
            alerts.append(alert)

    return BleScanResult(
        scanned_at=now,
        run_id=run_id,
        ble_available=True,
        entries=entries,
        new_peripherals=new_peripherals,
        alerts=alerts,
    )
