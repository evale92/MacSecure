from __future__ import annotations

import argparse
from secure.connections import (
    is_loopback,
    scan_connections,
)
from secure.connections.port_info import describe_port
from secure.storage.database import Database
from secure.storage.models import (
    find_remote_endpoint_by_id,
    list_remote_endpoints,
    set_remote_endpoint_known,
)
from secure.cli import _bootstrap, logger

def _format_connection_line(entry) -> str:
    local = f"{entry.local_addr or '*'}:{entry.local_port if entry.local_port is not None else '*'}"
    remote = f"{entry.remote_addr}:{entry.remote_port}" if entry.remote_addr else "-"
    state = entry.state or "-"
    return f"[{entry.proto:3}] {local:23} -> {remote:23} {state:12} pid={entry.pid:<7} {entry.process_name}"


def cmd_connections_scan(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        result = scan_connections(db.conn)

    if not result.lsof_available:
        print("Could not run `lsof` (not installed, or it didn't finish in time).")
        print("No connections were recorded this scan.")
        logger.warning(
            "Connections scan could not run lsof",
            extra={"event": "connections_scan_failed", "component": "cli"},
        )
        return 1

    print(f"Scan at {result.scanned_at} (run id: {result.run_id})")
    print(
        f"Connections seen: {len(result.entries)} "
        f"({result.outbound_count} outbound, {result.listening_count} listening)"
    )
    if result.permission_warnings:
        print(
            f"  ({result.permission_warnings} permission warning(s) from lsof — some "
            "connections may be incomplete without elevated access, which this app "
            "never requests. See secure/connections/__init__.py.)"
        )
    print()

    for entry in sorted(result.entries, key=lambda e: (e.proto, e.local_port or 0)):
        print(_format_connection_line(entry))
        explanation = describe_port(entry.remote_port if entry.remote_addr else entry.local_port)
        if explanation:
            print(f"          {explanation}")

    new_endpoints = result.new_endpoints
    print()
    if new_endpoints:
        print(f"NEW REMOTE DESTINATIONS DETECTED ({len(new_endpoints)}):")
        for record in new_endpoints:
            note = " (loopback — this Mac talking to itself)" if is_loopback(record.remote_addr) else ""
            print(
                f"  #{record.id} {record.remote_addr}:{record.remote_port} ({record.proto}) — "
                f"{record.process_name or '(unknown process)'}{note}"
            )
        print("Review these, then: secure connections mark <id> known|unknown")
        print("(the id is shown above, or run `secure connections endpoints` any time)")
    else:
        print("No new remote destinations detected.")

    logger.info(
        "Ran an active connection scan",
        extra={"event": "connections_scan", "component": "cli"},
    )
    return 1 if new_endpoints else 0


def cmd_connections_endpoints(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        endpoints = list_remote_endpoints(db.conn)

    if not endpoints:
        print("No remote destinations recorded yet. Run `secure connections scan` first.")
        return 0

    for record in endpoints:
        tag = "KNOWN" if record.known else "UNKNOWN"
        note = " [loopback]" if is_loopback(record.remote_addr) else ""
        print(
            f"[{tag:7}] #{record.id:<4} {record.remote_addr}:{record.remote_port} "
            f"({record.proto}) — {record.process_name or '(unknown process)'}{note}"
        )
        explanation = describe_port(record.remote_port)
        if explanation:
            print(f"          {explanation}")
        print(f"          first seen {record.first_seen}, last seen {record.last_seen}")

    return 0


def cmd_connections_mark(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        endpoint = find_remote_endpoint_by_id(db.conn, args.endpoint_id)
        if endpoint is None:
            print(
                f"No remote destination found with id {args.endpoint_id}. "
                "Run `secure connections endpoints` to see recorded destinations."
            )
            return 1
        set_remote_endpoint_known(db.conn, endpoint.id, known)

    print(f"Marked #{args.endpoint_id} ({endpoint.remote_addr}:{endpoint.remote_port}) as {args.status}.")
    logger.info(
        "Marked a remote destination known/unknown",
        extra={"event": "connections_mark", "component": "cli"},
    )
    return 0
