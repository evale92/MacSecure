from __future__ import annotations

import argparse
from secure.fileintegrity import scan_file_integrity
from secure.fileintegrity.paths import normalize_path
from secure.storage.database import Database
from secure.storage.models import (
    add_watch_path,
    find_file_entry_by_id,
    find_file_integrity_alert_by_id,
    find_watch_path_by_id,
    list_file_change_events,
    list_file_entries,
    list_file_integrity_alerts,
    list_watch_paths,
    set_file_entry_known,
    set_file_integrity_alert_known,
    set_watch_path_enabled,
)
from secure.cli import _bootstrap, _record_alert_review_change, logger

def cmd_fileintegrity_scan(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        result = scan_file_integrity(db.conn)

    print(f"File integrity scan at {result.scanned_at} (run id: {result.run_id})")
    print(f"Duration: {result.duration_seconds:.2f}s")
    print(
        f"Watch paths: {len(result.watch_paths_completed)} fully scanned, "
        f"{len(result.watch_paths_incomplete)} incomplete "
        f"(of {len(result.watch_paths_attempted)} attempted)"
    )
    for incomplete in result.watch_paths_incomplete:
        print(f"  INCOMPLETE: {incomplete['path']}")
        for path, reason in incomplete["reasons"].items():
            print(f"    {path}: {reason}")
    print(
        f"Files: {result.files_visited} visited, {result.files_hashed} hashed, "
        f"{result.files_skipped_unchanged} unchanged (skipped), "
        f"{result.files_skipped_too_large} too large, "
        f"{result.files_skipped_excluded} excluded, "
        f"{result.files_unreadable} unreadable"
    )
    print()

    persisted_alerts = [a for a in result.alerts if a.id is not None]
    if persisted_alerts:
        print(f"ALERTS ({len(persisted_alerts)}):")
        for alert in persisted_alerts:
            print(f"  #{alert.id} [{alert.severity.upper()}] {alert.kind} — {alert.path}")
            print(f"           {alert.message}")
            if alert.context_notes:
                print(f"           Context: {alert.context_notes}")
        print("Review these, then: secure fileintegrity mark-alert <id> known|unknown")
    else:
        print("No alert-worthy file integrity changes this scan.")
    if len(result.alerts) > len(persisted_alerts):
        print(
            f"({len(result.alerts) - len(persisted_alerts)} additional low-severity "
            "change(s) recorded in history — see `secure fileintegrity events`.)"
        )

    logger.info(
        "Ran a file integrity scan",
        extra={"event": "fileintegrity_scan", "component": "cli"},
    )
    return 1 if persisted_alerts else 0


def cmd_fileintegrity_watch_add(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    path = normalize_path(args.path)

    with Database(cfg.database_path()) as db:
        record, was_new = add_watch_path(
            db.conn, path=path, recursive=not args.no_recursive, sensitivity=args.sensitivity,
        )

    if was_new:
        print(f"Added watch path #{record.id}: {record.path} (sensitivity: {record.sensitivity})")
    else:
        print(f"Watch path already registered as #{record.id}: {record.path}")
    return 0


def cmd_fileintegrity_watch_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        watch_paths = list_watch_paths(db.conn)

    if not watch_paths:
        print("No watch paths registered yet. Run `secure fileintegrity scan` "
              "to seed the default list, or `secure fileintegrity watch-add`.")
        return 0

    for wp in watch_paths:
        state = "enabled" if wp.enabled else "disabled"
        status = wp.last_scan_status or "never scanned"
        print(f"#{wp.id:<4} [{wp.sensitivity:8}] [{state:8}] {wp.path}")
        print(f"          recursive: {wp.recursive}, last scan: {status} ({wp.last_scan_at or 'n/a'})")

    return 0


def cmd_fileintegrity_watch_remove(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        wp = find_watch_path_by_id(db.conn, args.watch_path_id)
        if wp is None:
            print(
                f"No watch path found with id {args.watch_path_id}. "
                "Run `secure fileintegrity watch-list` to see registered paths."
            )
            return 1
        set_watch_path_enabled(db.conn, wp.id, False)

    print(f"Disabled watch path #{wp.id} ({wp.path}). Its recorded history is kept.")
    return 0


def cmd_fileintegrity_files(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        entries = list_file_entries(db.conn, limit=args.limit)

    if not entries:
        print("No files recorded yet. Run `secure fileintegrity scan` first.")
        return 0

    for entry in entries:
        tag = "KNOWN" if entry.known else "UNKNOWN"
        print(f"[{tag:7}] #{entry.id:<4} {entry.path}")
        print(f"          hash: {entry.hash or '(none)'}, size: {entry.size}, mode: {entry.mode}")
        print(f"          first seen {entry.first_seen}, last seen {entry.last_seen}")

    return 0


def cmd_fileintegrity_mark_file(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        entry = find_file_entry_by_id(db.conn, args.entry_id)
        if entry is None:
            print(
                f"No file entry found with id {args.entry_id}. "
                "Run `secure fileintegrity files` to see recorded entries."
            )
            return 1
        set_file_entry_known(db.conn, entry.id, known)

    print(f"Marked #{args.entry_id} ({entry.path}) as {args.status}.")
    return 0


def cmd_fileintegrity_events(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        events = list_file_change_events(db.conn, path=args.path, limit=args.limit)

    if not events:
        print("No file change events recorded yet.")
        return 0

    for event in events:
        rename_note = f" (from {event.old_path})" if event.old_path else ""
        print(f"#{event.id:<5} [{event.change_type:16}] {event.path}{rename_note} — {event.created_at}")
        reasons = event.details.get("reasons")
        if reasons:
            print(f"          {'; '.join(reasons)}")

    return 0


def cmd_fileintegrity_alerts(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        alerts = list_file_integrity_alerts(db.conn)

    if not alerts:
        print("No file integrity alerts recorded yet. Run `secure fileintegrity scan` first.")
        return 0

    for record in alerts:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(
            f"[{tag:7}] #{record.id:<4} [{record.severity.upper():6}] "
            f"{record.kind} — {record.path} — {record.created_at}"
        )
        print(f"          {record.message}")
        if record.context_notes:
            print(f"          Context: {record.context_notes}")

    return 0


def cmd_fileintegrity_mark_alert(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        alert = find_file_integrity_alert_by_id(db.conn, args.alert_id)
        if alert is None:
            print(
                f"No file integrity alert found with id {args.alert_id}. "
                "Run `secure fileintegrity alerts` to see recorded alerts."
            )
            return 1
        if alert.known != known:
            _record_alert_review_change(
                db.conn, source_table="file_integrity_alerts", alert_id=alert.id, subject=alert.path,
                severity=alert.severity, was_known=alert.known, now_known=known,
            )
        set_file_integrity_alert_known(db.conn, alert.id, known)

    print(f"Marked #{args.alert_id} ({alert.kind}, {alert.path}) as {args.status}.")
    logger.info(
        "Marked a file integrity alert known/unknown",
        extra={"event": "fileintegrity_mark_alert", "component": "cli"},
    )
    return 0
