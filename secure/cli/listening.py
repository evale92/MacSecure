from __future__ import annotations

import argparse
from secure.listening import scan_listening_services
from secure.storage.database import Database
from secure.storage.models import (
    find_listening_service_by_id,
    list_listening_services,
    set_listening_service_known,
)
from secure.cli import _bootstrap, logger

def _format_listening_line(entry) -> str:
    local = f"{entry.local_addr or '*'}:{entry.local_port if entry.local_port is not None else '*'}"
    return f"[{entry.proto:3}] {local:23} {entry.bind_scope:9} pid={entry.pid:<7} {entry.process_name}"


def cmd_listening_scan(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        result = scan_listening_services(db.conn)

    if not result.lsof_available:
        print("Could not run `lsof` (not installed, or it didn't finish in time).")
        print("No listening services were recorded this scan.")
        logger.warning(
            "Listening scan could not run lsof",
            extra={"event": "listening_scan_failed", "component": "cli"},
        )
        return 1

    localhost_count = len(result.entries) - result.network_exposed_count
    print(f"Scan at {result.scanned_at} (run id: {result.run_id})")
    print(
        f"Listening services seen: {len(result.entries)} "
        f"({result.network_exposed_count} exposed to your network, {localhost_count} localhost-only)"
    )
    print()

    for entry in sorted(result.entries, key=lambda e: (e.proto, e.local_port or 0)):
        print(_format_listening_line(entry))
        print(f"          {entry.risk_note}")

    new_services = result.new_services
    print()
    if new_services:
        print(f"NEW LISTENING SERVICES DETECTED ({len(new_services)}):")
        for record in new_services:
            port_display = record.local_port if record.local_port is not None else record.identity_port
            print(
                f"  #{record.id} {record.process_name} ({record.proto}, {record.bind_scope}) "
                f"— port {port_display}"
            )
        print("Review these, then: secure listening mark <id> known|unknown")
        print("(the id is shown above, or run `secure listening list` any time)")
    else:
        print("No new listening services detected.")

    disappeared_services = result.disappeared_services
    print()
    if disappeared_services:
        print(f"SERVICES THAT STOPPED LISTENING SINCE THE LAST SCAN ({len(disappeared_services)}):")
        for record in disappeared_services:
            port_display = record.local_port if record.local_port is not None else record.identity_port
            print(
                f"  #{record.id} {record.process_name} ({record.proto}, {record.bind_scope}) "
                f"— port {port_display} — last seen {record.last_seen}"
            )
    elif result.has_previous_scan:
        print("No services stopped listening since the last scan.")

    logger.info(
        "Ran a listening-service audit",
        extra={"event": "listening_scan", "component": "cli"},
    )
    return 1 if new_services or disappeared_services else 0


def cmd_listening_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        services = list_listening_services(db.conn)

    if not services:
        print("No listening services recorded yet. Run `secure listening scan` first.")
        return 0

    for record in services:
        tag = "KNOWN" if record.known else "UNKNOWN"
        port_display = record.local_port if record.local_port is not None else record.identity_port
        print(
            f"[{tag:7}] #{record.id:<4} {record.process_name} ({record.proto}, {record.bind_scope}) "
            f"— port {port_display}"
        )
        print(f"          first seen {record.first_seen}, last seen {record.last_seen}")

    return 0


def cmd_listening_mark(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        service = find_listening_service_by_id(db.conn, args.service_id)
        if service is None:
            print(
                f"No listening service found with id {args.service_id}. "
                "Run `secure listening list` to see recorded services."
            )
            return 1
        set_listening_service_known(db.conn, service.id, known)

    print(f"Marked #{args.service_id} ({service.process_name}) as {args.status}.")
    logger.info(
        "Marked a listening service known/unknown",
        extra={"event": "listening_mark", "component": "cli"},
    )
    return 0
