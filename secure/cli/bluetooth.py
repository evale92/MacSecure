from __future__ import annotations

import argparse
from secure.bluetooth import scan_bluetooth
from secure.bluetooth.ble import check_bluetooth_state
from secure.storage.database import Database
from secure.storage.models import (
    find_bluetooth_alert_by_id,
    find_bluetooth_device_by_id,
    list_bluetooth_alerts,
    list_bluetooth_devices,
    set_bluetooth_alert_known,
    set_bluetooth_device_trusted,
)
from secure.cli import _bootstrap, _record_alert_review_change, logger

def _format_bluetooth_device_line(record, tag: str) -> str:
    name = record.name or "(unnamed device)"
    rssi_display = f", {record.last_rssi} dBm" if record.last_rssi is not None else ""
    return f"[{tag:7}] #{record.id:<4} {record.identifier} {name} (seen {record.times_seen}x{rssi_display})"


def cmd_bluetooth_scan(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        result = scan_bluetooth(db.conn)

    if not result.bluetooth_available:
        print("Could not run `system_profiler SPBluetoothDataType` (not available, or it didn't finish in time).")
        print("No Bluetooth data was recorded this scan.")
        logger.warning(
            "Bluetooth scan could not run system_profiler",
            extra={"event": "bluetooth_scan_failed", "component": "cli"},
        )
        return 1

    print(f"Scan at {result.scanned_at} (run id: {result.run_id})")
    print(f"Devices seen: {len(result.entries)}")
    print(
        "(This is what macOS already knows — paired, configured, or connected devices — "
        "not a live scan of every nearby BLE device. See secure/bluetooth/'s docs.)"
    )
    print()

    for entry in sorted(result.entries, key=lambda e: e.identifier):
        state = "connected" if entry.connected else ("paired" if entry.paired else "not paired")
        signal = f", {entry.rssi} dBm" if entry.rssi is not None else ""
        print(f"  {entry.identifier} {entry.name or '(unnamed device)'} — {state}{signal}")

    new_devices = result.new_devices
    print()
    if new_devices:
        print(f"NEW DEVICES DETECTED ({len(new_devices)}):")
        for record in new_devices:
            print(f"  #{record.id} {record.identifier} — {record.name or '(unnamed device)'}")
        print("Review these, then: secure bluetooth mark <id> trusted|untrusted")
    else:
        print("No new devices detected.")

    if result.alerts:
        print()
        print(f"ALERTS ({len(result.alerts)}):")
        for alert in result.alerts:
            print(f"  #{alert.id} [{alert.severity.upper()}] {alert.kind} — {alert.name or alert.identifier}")
            print(f"           {alert.message}")
        print("Review these, then: secure bluetooth mark-alert <id> known|unknown")

    logger.info(
        "Ran a Bluetooth scan",
        extra={"event": "bluetooth_scan", "component": "cli"},
    )
    return 1 if new_devices or result.alerts else 0


def cmd_bluetooth_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        devices = list_bluetooth_devices(db.conn)

    if not devices:
        print("No Bluetooth devices recorded yet. Run `secure bluetooth scan` first.")
        return 0

    for record in devices:
        tag = "TRUSTED" if record.trusted else "UNKNOWN"
        print(_format_bluetooth_device_line(record, tag))
        print(f"          first seen {record.first_seen}, last seen {record.last_seen}")

    return 0


def cmd_bluetooth_mark(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    trusted = args.status == "trusted"

    with Database(cfg.database_path()) as db:
        device = find_bluetooth_device_by_id(db.conn, args.device_id)
        if device is None:
            print(
                f"No Bluetooth device found with id {args.device_id}. "
                "Run `secure bluetooth list` to see recorded devices."
            )
            return 1
        set_bluetooth_device_trusted(db.conn, device.id, trusted)

    print(f"Marked #{args.device_id} ({device.identifier}) as {args.status}.")
    logger.info(
        "Marked a Bluetooth device trusted/untrusted",
        extra={"event": "bluetooth_mark", "component": "cli"},
    )
    return 0


def cmd_bluetooth_alerts(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        alerts = list_bluetooth_alerts(db.conn)

    if not alerts:
        print("No bluetooth alerts recorded yet. Run `secure bluetooth scan` first.")
        return 0

    for record in alerts:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(
            f"[{tag:7}] #{record.id:<4} [{record.severity.upper():6}] "
            f"{record.kind} — {record.name or record.identifier} — {record.created_at}"
        )
        print(f"          {record.message}")

    return 0


def cmd_bluetooth_mark_alert(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        alert = find_bluetooth_alert_by_id(db.conn, args.alert_id)
        if alert is None:
            print(
                f"No bluetooth alert found with id {args.alert_id}. "
                "Run `secure bluetooth alerts` to see recorded alerts."
            )
            return 1
        if alert.known != known:
            _record_alert_review_change(
                db.conn, source_table="bluetooth_alerts", alert_id=alert.id,
                subject=alert.name or alert.identifier,
                severity=alert.severity, was_known=alert.known, now_known=known,
            )
        set_bluetooth_alert_known(db.conn, alert.id, known)

    print(f"Marked #{args.alert_id} ({alert.kind}, {alert.name or alert.identifier}) as {args.status}.")
    logger.info(
        "Marked a bluetooth alert known/unknown",
        extra={"event": "bluetooth_mark_alert", "component": "cli"},
    )
    return 0


def cmd_bluetooth_state(args: argparse.Namespace) -> int:
    """Check Bluetooth's current power/authorization state for this
    process — a quick diagnostic to run before `bluetooth ble scan` if
    a scan isn't finding anything and you want to know whether that's
    genuinely "nothing nearby" or a permission/power problem.
    """
    _bootstrap()
    result = check_bluetooth_state()
    print(f"State: {result.state_name}")
    print(result.detail)
    return 0 if result.available else 1
