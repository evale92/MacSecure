from __future__ import annotations

import argparse
from secure.bluetooth.ble import scan_ble_peripherals
from secure.storage.database import Database
from secure.storage.models import (
    find_ble_alert_by_id,
    find_ble_peripheral_by_id,
    list_ble_alerts,
    list_ble_peripherals,
    set_ble_alert_known,
    set_ble_peripheral_trusted,
)
from secure.cli import _bootstrap, _record_alert_review_change, logger

def _format_ble_peripheral_line(record, tag: str) -> str:
    name = record.name or "(unnamed peripheral)"
    rssi_display = f", {record.last_rssi} dBm" if record.last_rssi is not None else ""
    return f"[{tag:7}] #{record.id:<4} {record.cb_uuid} {name} (seen {record.times_seen}x{rssi_display})"


def cmd_bluetooth_ble_scan(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        result = scan_ble_peripherals(db.conn, duration=args.duration)

    if not result.ble_available:
        print(f"Live BLE scan not available: {result.unavailable_reason}")
        print(result.unavailable_detail or "")
        print(
            "(This is NOT the same as 'no nearby devices' — Secure could not "
            "determine that, and is not guessing.)"
        )
        logger.warning(
            "BLE scan unavailable",
            extra={
                "event": "ble_scan_failed",
                "component": "cli",
                "reason": result.unavailable_reason,
            },
        )
        return 1

    print(f"Scan at {result.scanned_at} (run id: {result.run_id})")
    print(f"Peripherals seen: {len(result.entries)}")
    print(
        "(Live BLE advertisements — real nearby peripherals, not just devices "
        "macOS already knows about. See secure/bluetooth/ble/'s docs for the "
        "CoreBluetooth-UUID-vs-MAC-address and address-rotation limitations.)"
    )
    print()

    for entry in sorted(result.entries, key=lambda e: e.cb_uuid):
        signal = f", {entry.rssi} dBm" if entry.rssi is not None else ""
        print(f"  {entry.cb_uuid} {entry.name or '(unnamed peripheral)'}{signal}")

    new_peripherals = result.new_peripherals
    print()
    if new_peripherals:
        print(f"NEW PERIPHERALS DETECTED ({len(new_peripherals)}):")
        for record in new_peripherals:
            print(f"  #{record.id} {record.cb_uuid} — {record.name or '(unnamed peripheral)'}")
        print("Review these, then: secure bluetooth ble mark <id> trusted|untrusted")
    else:
        print("No new peripherals detected.")

    if result.alerts:
        print()
        print(f"ALERTS ({len(result.alerts)}):")
        for alert in result.alerts:
            print(f"  #{alert.id} [{alert.severity.upper()}] {alert.kind} — {alert.name or alert.cb_uuid}")
            print(f"           {alert.message}")
        print("Review these, then: secure bluetooth ble mark-alert <id> known|unknown")

    logger.info(
        "Ran a live BLE scan",
        extra={"event": "ble_scan", "component": "cli"},
    )
    return 1 if new_peripherals or result.alerts else 0


def cmd_bluetooth_ble_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        peripherals = list_ble_peripherals(db.conn)

    if not peripherals:
        print("No BLE peripherals recorded yet. Run `secure bluetooth ble scan` first.")
        return 0

    for record in peripherals:
        tag = "TRUSTED" if record.trusted else "UNKNOWN"
        print(_format_ble_peripheral_line(record, tag))
        print(f"          first seen {record.first_seen}, last seen {record.last_seen}")

    return 0


def cmd_bluetooth_ble_mark(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    trusted = args.status == "trusted"

    with Database(cfg.database_path()) as db:
        peripheral = find_ble_peripheral_by_id(db.conn, args.peripheral_id)
        if peripheral is None:
            print(
                f"No BLE peripheral found with id {args.peripheral_id}. "
                "Run `secure bluetooth ble list` to see recorded peripherals."
            )
            return 1
        set_ble_peripheral_trusted(db.conn, peripheral.id, trusted)

    print(f"Marked #{args.peripheral_id} ({peripheral.cb_uuid}) as {args.status}.")
    logger.info(
        "Marked a BLE peripheral trusted/untrusted",
        extra={"event": "ble_mark", "component": "cli"},
    )
    return 0


def cmd_bluetooth_ble_alerts(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        alerts = list_ble_alerts(db.conn)

    if not alerts:
        print("No BLE alerts recorded yet. Run `secure bluetooth ble scan` first.")
        return 0

    for record in alerts:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(
            f"[{tag:7}] #{record.id:<4} [{record.severity.upper():6}] "
            f"{record.kind} — {record.name or record.cb_uuid} — {record.created_at}"
        )
        print(f"          {record.message}")

    return 0


def cmd_bluetooth_ble_mark_alert(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        alert = find_ble_alert_by_id(db.conn, args.alert_id)
        if alert is None:
            print(
                f"No BLE alert found with id {args.alert_id}. "
                "Run `secure bluetooth ble alerts` to see recorded alerts."
            )
            return 1
        if alert.known != known:
            _record_alert_review_change(
                db.conn, source_table="ble_alerts", alert_id=alert.id,
                subject=alert.name or alert.cb_uuid,
                severity=alert.severity, was_known=alert.known, now_known=known,
            )
        set_ble_alert_known(db.conn, alert.id, known)

    print(f"Marked #{args.alert_id} ({alert.kind}, {alert.name or alert.cb_uuid}) as {args.status}.")
    logger.info(
        "Marked a BLE alert known/unknown",
        extra={"event": "ble_mark_alert", "component": "cli"},
    )
    return 0
