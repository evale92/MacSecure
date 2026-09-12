from __future__ import annotations

import argparse
import re
from secure.inventory import scan_network
from secure.inventory.arp_table import normalize_mac
from secure.storage.database import Database
from secure.storage.models import (
    delete_junk_devices,
    find_device_by_identifier,
    list_devices,
    set_device_friendly_name,
    set_device_known,
)
from secure.cli import _bootstrap, logger

def _format_device_line(record, tag: str) -> str:
    name = record.friendly_name or record.hostname or "(no name)"
    mac = record.mac or "(no MAC)"
    vendor = f" [{record.vendor}]" if record.vendor else ""
    return f"[{tag:7}] {record.ip:15} {mac:17} {name}{vendor}"


_MAC_INPUT_RE = re.compile(r"^[0-9a-fA-F]{1,2}([:-][0-9a-fA-F]{1,2}){5}$")


def _lookup_identifier(identifier: str) -> str:
    """Put a MAC the operator typed into the form the scanner stored.

    Stored MACs are zero-padded by normalize_mac(), but `arp -a` prints
    them unpadded (ac:de:48:0:11:22), so a MAC copied from it would
    otherwise never match. Anything not shaped like a MAC (an IP) is
    passed through unchanged.
    """
    if _MAC_INPUT_RE.match(identifier.strip()):
        return normalize_mac(identifier)
    return identifier


def cmd_inventory_scan(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        result = scan_network(db.conn, do_ping_sweep=not args.no_ping_sweep)

    if not result.arp_available:
        print("Could not run `arp` (not installed, or it didn't finish in time).")
        print("No device inventory data was recorded this scan.")
        logger.warning(
            "Inventory scan could not run arp",
            extra={"event": "inventory_scan_failed", "component": "cli"},
        )
        return 1

    print(f"Scan at {result.scanned_at}")
    print(f"Subnet: {result.subnet or 'could not be determined'}")
    print(f"Ping sweep: {'performed' if result.ping_sweep_performed else 'skipped'}")
    print(f"Devices seen this scan: {len(result.devices)}")
    if result.filtered_out:
        print(
            f"  ({result.filtered_out} of {result.raw_arp_rows} ARP entries were empty "
            "addresses/broadcast/multicast, not devices — not counted above.)"
        )
    print()

    for record, was_new in sorted(result.devices, key=lambda pair: pair[0].ip):
        tag = "NEW" if was_new else ("KNOWN" if record.known else "UNKNOWN")
        print(_format_device_line(record, tag))

    new_devices = result.new_devices
    print()
    if new_devices:
        print(f"NEW DEVICES DETECTED ({len(new_devices)}):")
        for record in new_devices:
            print(f"  {record.ip} — {record.mac or '(no MAC)'} — {record.hostname or '(no hostname)'}")
        print("Review these, then: secure inventory name <ip-or-mac> \"Friendly Name\"")
        print("                and: secure inventory mark <ip-or-mac> known")
    else:
        print("No new devices detected.")

    logger.info(
        "Ran a local device inventory scan",
        extra={"event": "inventory_scan", "component": "cli"},
    )
    return 1 if new_devices else 0


def cmd_inventory_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        devices = list_devices(db.conn)

    if not devices:
        print("No devices recorded yet. Run `secure inventory scan` first.")
        return 0

    for record in devices:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(_format_device_line(record, tag))
        print(f"          first seen {record.first_seen}, last seen {record.last_seen}")

    return 0


def cmd_inventory_name(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        device = find_device_by_identifier(db.conn, _lookup_identifier(args.identifier))
        if device is None:
            print(
                f"No device found matching '{args.identifier}'. "
                "Run `secure inventory list` to see recorded devices."
            )
            return 1
        set_device_friendly_name(db.conn, device.id, args.name)

    print(f"Named {args.identifier} -> '{args.name}'")
    logger.info(
        "Set a device's friendly name",
        extra={"event": "inventory_name", "component": "cli"},
    )
    return 0


def cmd_inventory_mark(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        device = find_device_by_identifier(db.conn, _lookup_identifier(args.identifier))
        if device is None:
            print(
                f"No device found matching '{args.identifier}'. "
                "Run `secure inventory list` to see recorded devices."
            )
            return 1
        set_device_known(db.conn, device.id, known)

    print(f"Marked {args.identifier} as {args.status}.")
    logger.info(
        "Marked a device known/unknown",
        extra={"event": "inventory_mark", "component": "cli"},
    )
    return 0


def cmd_inventory_prune(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        removed = delete_junk_devices(db.conn)

    if removed:
        print(
            f"Removed {removed} device record(s) that shouldn't have been "
            "recorded as devices (empty addresses, broadcast, or multicast)."
        )
    else:
        print("Nothing to remove — no junk device records found.")

    logger.info(
        "Pruned junk device records",
        extra={"event": "inventory_prune", "component": "cli"},
    )
    return 0
