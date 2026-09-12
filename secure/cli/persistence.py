from __future__ import annotations

import argparse
from secure.persistence import scan_persistence
from secure.storage.database import Database
from secure.storage.models import (
    find_persistence_alert_by_id,
    find_persistence_entry_by_id,
    find_process_entry_by_id,
    list_persistence_alerts,
    list_persistence_entries,
    list_process_entries,
    set_persistence_alert_known,
    set_persistence_entry_known,
    set_process_entry_known,
)
from secure.cli import _bootstrap, _record_alert_review_change, logger

def cmd_persistence_scan(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        result = scan_persistence(db.conn)

    if not result.processes_available:
        print("Could not run `ps` (not available, or it didn't finish in time).")
        print("No process data was recorded this scan.")
        logger.warning(
            "Persistence scan could not run ps",
            extra={"event": "persistence_scan_failed", "component": "cli"},
        )

    print(f"Scan at {result.scanned_at} (run id: {result.run_id})")
    if result.processes_available:
        print(f"Processes with a resolvable executable path: {result.process_count}")
    if not result.login_items_available:
        print(
            "Could not read classic login items (osascript unavailable or timed "
            "out) — LaunchAgents/LaunchDaemons were still scanned normally."
        )
    print()

    if result.new_processes:
        print(f"NEW PROCESSES DETECTED ({len(result.new_processes)}):")
        for record in result.new_processes:
            print(
                f"  #{record.id} {record.executable_path} "
                f"(user: {record.run_as_user}, signing: {record.signing_status})"
            )
        print("Review these, then: secure persistence mark-process <id> known|unknown")
    elif result.processes_available:
        # Only a scan that actually saw the processes may say none are new;
        # when `ps` failed, the lines above already say there is no data.
        print("No new processes detected.")

    if result.new_persistence_entries:
        print()
        print(f"NEW PERSISTENCE ENTRIES DETECTED ({len(result.new_persistence_entries)}):")
        for record in result.new_persistence_entries:
            label = record.label or record.path or "(unknown)"
            print(f"  #{record.id} [{record.kind}] {label} (signing: {record.signing_status})")
        print("Review these, then: secure persistence mark-item <id> known|unknown")
    else:
        print()
        print("No new persistence entries detected.")

    if result.alerts:
        print()
        print(f"ALERTS ({len(result.alerts)}):")
        for alert in result.alerts:
            print(
                f"  #{alert.id} [{alert.severity.upper()}] {alert.kind} "
                f"({alert.target_type}) — {alert.label or alert.identifier}"
            )
            print(f"           {alert.message}")
        print("Review these, then: secure persistence mark-alert <id> known|unknown")

    logger.info(
        "Ran a persistence scan",
        extra={"event": "persistence_scan", "component": "cli"},
    )
    if not result.processes_available:
        return 1
    return 1 if result.new_processes or result.new_persistence_entries or result.alerts else 0


def _format_process_entry_line(record, tag: str) -> str:
    signing = record.signing_status or "unknown"
    return (
        f"[{tag:7}] #{record.id:<4} {record.executable_path} "
        f"(user: {record.run_as_user}, signing: {signing}, seen {record.times_seen}x)"
    )


def cmd_persistence_processes(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        entries = list_process_entries(db.conn)

    if not entries:
        print("No process entries recorded yet. Run `secure persistence scan` first.")
        return 0

    for record in entries:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(_format_process_entry_line(record, tag))
        print(f"          first seen {record.first_seen}, last seen {record.last_seen}")

    return 0


def cmd_persistence_mark_process(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        entry = find_process_entry_by_id(db.conn, args.entry_id)
        if entry is None:
            print(
                f"No process entry found with id {args.entry_id}. "
                "Run `secure persistence processes` to see recorded entries."
            )
            return 1
        set_process_entry_known(db.conn, entry.id, known)

    print(f"Marked #{args.entry_id} ({entry.executable_path}) as {args.status}.")
    logger.info(
        "Marked a process entry known/unknown",
        extra={"event": "persistence_mark_process", "component": "cli"},
    )
    return 0


def _format_persistence_entry_line(record, tag: str) -> str:
    label = record.label or record.path or "(unknown)"
    signing = record.signing_status or "unknown"
    return f"[{tag:7}] #{record.id:<4} [{record.kind}] {label} (signing: {signing})"


def cmd_persistence_items(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        entries = list_persistence_entries(db.conn)

    if not entries:
        print("No persistence entries recorded yet. Run `secure persistence scan` first.")
        return 0

    for record in entries:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(_format_persistence_entry_line(record, tag))
        print(f"          path: {record.path or '(none)'}")
        print(f"          first seen {record.first_seen}, last seen {record.last_seen}")

    return 0


def cmd_persistence_mark_item(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        entry = find_persistence_entry_by_id(db.conn, args.entry_id)
        if entry is None:
            print(
                f"No persistence entry found with id {args.entry_id}. "
                "Run `secure persistence items` to see recorded entries."
            )
            return 1
        set_persistence_entry_known(db.conn, entry.id, known)

    label = entry.label or entry.path or "(unknown)"
    print(f"Marked #{args.entry_id} ({label}) as {args.status}.")
    logger.info(
        "Marked a persistence entry known/unknown",
        extra={"event": "persistence_mark_item", "component": "cli"},
    )
    return 0


def cmd_persistence_alerts(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        alerts = list_persistence_alerts(db.conn)

    if not alerts:
        print("No persistence alerts recorded yet. Run `secure persistence scan` first.")
        return 0

    for record in alerts:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(
            f"[{tag:7}] #{record.id:<4} [{record.severity.upper():6}] "
            f"{record.kind} ({record.target_type}) — "
            f"{record.label or record.identifier} — {record.created_at}"
        )
        print(f"          {record.message}")

    return 0


def cmd_persistence_mark_alert(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        alert = find_persistence_alert_by_id(db.conn, args.alert_id)
        if alert is None:
            print(
                f"No persistence alert found with id {args.alert_id}. "
                "Run `secure persistence alerts` to see recorded alerts."
            )
            return 1
        if alert.known != known:
            _record_alert_review_change(
                db.conn, source_table="persistence_alerts", alert_id=alert.id,
                subject=alert.label or alert.identifier,
                severity=alert.severity, was_known=alert.known, now_known=known,
            )
        set_persistence_alert_known(db.conn, alert.id, known)

    print(
        f"Marked #{args.alert_id} ({alert.kind}, {alert.label or alert.identifier}) "
        f"as {args.status}."
    )
    logger.info(
        "Marked a persistence alert known/unknown",
        extra={"event": "persistence_mark_alert", "component": "cli"},
    )
    return 0
