from __future__ import annotations

import argparse
import uuid
from secure.arpwatch import scan_arp_table
from secure.bluetooth import scan_bluetooth
from secure.bluetooth.ble import scan_ble_peripherals
from secure.checks import run_all_checks
from secure.config import (
    load_config,
    save_config,
)
from secure.connections import scan_connections
from secure.continuity import take_snapshot
from secure.correlate import correlate
from secure.diagnostics.instrument import instrument_module, best_effort_counts
from secure.explain.dispatch import explain
from secure.threatintel.enrich import attach_cached_threat_intel
from secure.fileintegrity import scan_file_integrity
from secure.inventory import scan_network
from secure.listening import scan_listening_services
from secure.logging_setup import setup_logging
from secure.persistence import scan_persistence
from secure.self_update import mark_update_context
from secure.storage.database import Database
from secure.storage.models import (
    add_event,
    add_posture_result,
    count_events,
    find_arp_alert_by_id,
    find_ble_alert_by_id,
    find_bluetooth_alert_by_id,
    find_correlation_alert_by_id,
    find_correlation_chain_alert_by_id,
    find_file_integrity_alert_by_id,
    find_integration_alert_by_id,
    find_persistence_alert_by_id,
    find_wifi_alert_by_id,
    list_events,
)
from secure.wifi import scan_wifi
from secure.cli import _bootstrap, logger

# A CorrelationChainAlertRecord's id is looked up the same way every
# other alert record's id is (find_fn(conn, alert_id) -> record | None)
# despite alert_id here being a plain int, not the str the type hint on
# some other find_* functions historically used — see
# secure/storage/models/correlate_chains.py's find_correlation_chain_alert_by_id().
_EXPLAIN_SOURCES = {
    "arpwatch": (find_arp_alert_by_id, "arp_alerts"),
    "wifi": (find_wifi_alert_by_id, "wifi_alerts"),
    "bluetooth": (find_bluetooth_alert_by_id, "bluetooth_alerts"),
    "ble": (find_ble_alert_by_id, "ble_alerts"),
    "persistence": (find_persistence_alert_by_id, "persistence_alerts"),
    "fileintegrity": (find_file_integrity_alert_by_id, "file_integrity_alerts"),
    "correlate": (find_correlation_alert_by_id, "correlation_alerts"),
    "integrations": (find_integration_alert_by_id, "integration_alerts"),
    "chains": (find_correlation_chain_alert_by_id, "correlation_chain_alerts"),
}


def cmd_init(args: argparse.Namespace) -> int:
    cfg = load_config()
    if args.role is not None:
        cfg.device_role = args.role
    save_config(cfg)  # make sure config.json exists and is up to date
    setup_logging(cfg.log_path(), level=cfg.log_level)

    with Database(cfg.database_path()):
        pass  # __enter__ already created the schema

    logger.info(
        "Initialized Secure app directory",
        extra={"event": "init", "component": "cli"},
    )
    print(f"Device name:   {cfg.device_name}")
    print(f"Device role:   {cfg.device_role}")
    print(f"App directory: {cfg.app_dir_path()}")
    print(f"Config file:   {cfg.app_dir_path() / 'config.json'}")
    print(f"Database:      {cfg.database_path()}")
    print(f"Log file:      {cfg.log_path()}")
    print("Initialization complete.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        total = count_events(db.conn)
        recent = list_events(db.conn, limit=5)

    print(f"Device name:   {cfg.device_name}")
    print(f"Device role:   {cfg.device_role}")
    print(f"App directory: {cfg.app_dir_path()}")
    print(f"Database:      {cfg.database_path()}")
    print(f"Log file:      {cfg.log_path()}")
    print(f"Log level:     {cfg.log_level}")
    print(f"Total events:  {total}")

    if recent:
        print("\nMost recent events:")
        for event in recent:
            print(f"  [{event.created_at}] ({event.category}) {event.message}")

    logger.info("Displayed status", extra={"event": "status", "component": "cli"})
    return 0


def cmd_add_note(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        new_id = add_event(db.conn, category="note", message=args.text)

    logger.info(
        "Added note",
        extra={"event": "add_note", "component": "cli"},
    )
    print(f"Added event #{new_id}: {args.text}")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    """Developer/debug command: print the full Product Phase 13
    explanation (confidence, evidence, uncertainty, correlated events,
    recommended action) for one existing alert. Read-only — this does
    not mark, rescan, or change anything, and reuses secure/explain/
    exactly as secure_gui/data_access.py does, so CLI and GUI can never
    show a different explanation for the same alert.
    """
    cfg = _bootstrap()

    finder = _EXPLAIN_SOURCES.get(args.source)
    if finder is None:
        print(f"Unknown source '{args.source}'. Choose one of: {', '.join(sorted(_EXPLAIN_SOURCES))}.")
        return 1
    find_fn, source_table = finder

    with Database(cfg.database_path()) as db:
        record = find_fn(db.conn, args.alert_id)

        if record is None:
            print(f"No {args.source} alert found with id {args.alert_id}.")
            return 1

        exp = explain(record, source_table)
        # Cache-only threat-intel enrichment (Phase 20) — read-only,
        # never makes a network request; see secure/threatintel/
        # enrich.py's module docstring for why this is a separate step
        # applied here rather than something dispatch.explain() itself
        # does. Scans the record's own rendered message for candidate
        # IPs/domains/hashes and shows whatever's already cached about
        # them (or an honest "not yet checked" prompt) — run
        # `secure threatintel lookup <type> <value>` to actually check
        # a new indicator.
        exp = attach_cached_threat_intel(db.conn, exp, getattr(record, "message", "") or exp.summary)

    print(f"Summary:      {exp.summary}")
    print(f"Severity:     {exp.severity}")
    print(f"Confidence:   {exp.confidence}  ({exp.confidence_reason})")
    print(f"Significance: {exp.significance}")
    if exp.degraded:
        print(f"NOTE: a richer explanation was unavailable — {exp.degraded_reason}")

    print("\nEvidence:")
    if exp.evidence:
        for item in exp.evidence:
            print(f"  [{item.provenance}] {item.text}")
    else:
        print("  (none recorded)")

    print(f"\nUncertainty ({exp.uncertainty_status}):")
    if exp.uncertainty:
        for note in exp.uncertainty:
            print(f"  - {note}")
    else:
        print("  (none recorded)")

    if exp.correlated_events:
        shown = exp.correlated_events[:20]
        print(f"\nCorrelated events ({len(exp.correlated_events)}):")
        for event in shown:
            print(f"  - {event}")
        if len(exp.correlated_events) > len(shown):
            print(f"  ... and {len(exp.correlated_events) - len(shown)} more.")

    print(f"\nRecommended action: {exp.recommended_action} — {exp.recommended_action_text}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    results = run_all_checks(include_pending_updates=not args.quick)
    run_id = uuid.uuid4().hex[:12]

    counts = {"PASS": 0, "WARNING": 0, "FAIL": 0}
    with Database(cfg.database_path()) as db:
        for result in results:
            counts[result.status.value] += 1
            add_posture_result(
                db.conn,
                run_id=run_id,
                check_name=result.name,
                status=result.status.value,
                message=result.message,
                remediation=result.remediation,
            )

    for result in results:
        print(f"[{result.status.value:7}] {result.name}: {result.message}")
        if result.remediation:
            print(f"          -> {result.remediation}")

    print()
    print(
        f"Summary: {counts['PASS']} PASS, {counts['WARNING']} WARNING, "
        f"{counts['FAIL']} FAIL  (run id: {run_id})"
    )

    logger.info(
        "Ran macOS security posture check",
        extra={"event": "posture_check", "component": "cli"},
    )
    return 1 if counts["FAIL"] else 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        snapshot = take_snapshot(
            db.conn, app_dir=cfg.app_dir_path(), window_minutes=args.minutes
        )

    print(f"Snapshot taken: {snapshot.taken_at} (window: last {snapshot.window_minutes} min)")
    print()

    print(
        f"Project files changed: {len(snapshot.project_file_changes)}"
        + (" (truncated — see saved file for the full list)" if snapshot.project_files_truncated else "")
    )
    for change in snapshot.project_file_changes[:20]:
        print(f"  {change.path} — {change.modified_at}")
    if len(snapshot.project_file_changes) > 20:
        print(f"  ... and {len(snapshot.project_file_changes) - 20} more.")

    print()
    print(f"App state (~/.secure) changes: {len(snapshot.app_state_changes)}")
    for change in snapshot.app_state_changes[:20]:
        print(f"  {change.path} — {change.modified_at}")

    print()
    print(f"Launch item changes (LaunchAgents/LaunchDaemons): {len(snapshot.launch_item_changes)}")
    for change in snapshot.launch_item_changes:
        print(f"  {change.path} — {change.modified_at}")

    print()
    if snapshot.posture_baseline_at:
        print(f"Security posture changes since last check ({snapshot.posture_baseline_at}):")
    else:
        print("Security posture: no earlier check found — this run is now the baseline.")
    if snapshot.posture_diffs:
        for diff in snapshot.posture_diffs:
            print(f"  {diff.check_name}: {diff.previous_status} -> {diff.current_status}")
    elif snapshot.posture_baseline_at:
        print("  No changes.")

    counts = {"PASS": 0, "WARNING": 0, "FAIL": 0}
    for result in snapshot.posture_results:
        counts[result.status.value] += 1
    print()
    print(f"Current posture: {counts['PASS']} PASS, {counts['WARNING']} WARNING, {counts['FAIL']} FAIL")
    print()
    print(f"Saved: database (snapshot id {snapshot.db_id}) and {snapshot.json_path}")

    logger.info(
        "Took a Continuity snapshot",
        extra={"event": "snapshot", "component": "cli"},
    )
    return 1 if snapshot.posture_diffs or counts["FAIL"] else 0


def cmd_self_mark_update_context(args: argparse.Namespace) -> int:
    """Record that an intentional Secure Update/reload is happening now
    — see secure/self_update.py. File integrity monitoring checks for a
    recent marker like this one before flagging a self-file change as
    "unexplained".
    """
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        event_id = mark_update_context(db.conn, note=args.note or "")

    print(f"Marked update context (event #{event_id}). Self-file changes in the "
          "next several minutes will be annotated as expected, not unexplained.")
    return 0


def cmd_run_all(args: argparse.Namespace) -> int:
    """Run every scan that feeds correlation signals, back-to-back in
    this one process, then correlate the result. Runs each scan_*()
    function directly in-process rather than shelling itself out —
    that keeps every signal's timestamp genuinely close together,
    which matters a lot for a --window default of 60 seconds (see
    PROJECT_NOTES.md's "Cross-Module Correlation" section). Skips
    `secure check`/`secure snapshot` on purpose — posture checks aren't
    a correlation signal source (see secure/correlate/signals.py), so
    running them here wouldn't help correlation, only slow this down.

    Each scan is wrapped in secure/diagnostics/instrument.py's
    instrument_module() (Phase 30), writing one perf_module_runs row
    per scan — timing/CPU/memory/counts only, a diagnostic record, not
    a security finding (see that module's own docstring for why this
    can't change any scan's own detection/scoring behavior).
    """
    cfg = _bootstrap()
    run_group_id = uuid.uuid4().hex[:12]

    with Database(cfg.database_path()) as db:
        conn = db.conn
        print("Running every scan...")

        for module, operation, scan_fn, label in (
            ("inventory", "scan", scan_network, "Device Inventory"),
            ("connections", "scan", scan_connections, "Active Connections"),
            ("listening", "scan", scan_listening_services, "Listening Services"),
            ("arpwatch", "scan", scan_arp_table, "ARP Watch"),
            ("wifi", "scan", scan_wifi, "Wi-Fi Security"),
            ("bluetooth", "scan", scan_bluetooth, "Bluetooth"),
            ("ble", "scan", scan_ble_peripherals, "Live BLE Discovery"),
            ("persistence", "scan", scan_persistence, "Process & Persistence"),
            ("fileintegrity", "scan", scan_file_integrity, "File Integrity"),
        ):
            with instrument_module(conn, run_group_id=run_group_id, module=module, operation=operation) as rec:
                scan_result = scan_fn(conn)
                rec.observations_processed, rec.findings_produced = best_effort_counts(scan_result)
            print(f"  {label}: done")

        print()
        print("Correlating...")
        result = correlate(conn, triggered_by="run_all")

    print(f"Signals considered: {result.signals_considered}")
    print(
        f"Time-clusters found: {result.clusters_considered} "
        f"({result.cross_module_clusters} spanning 2+ modules)"
    )
    print()

    if result.new_alerts:
        print(f"NEW CORRELATION ALERTS ({len(result.new_alerts)}):")
        for alert in sorted(result.new_alerts, key=lambda a: a.id, reverse=True):
            print(
                f"  #{alert.id} [{alert.severity.upper()}] score {alert.score} — "
                f"{alert.module_count} modules, {alert.signal_count} signals"
            )
        print()
        print("Details: secure correlate list")
        print("Review these, then: secure correlate mark-alert <id> known|unknown")
    else:
        print("No new cross-module correlation clusters this run.")

    logger.info(
        "Ran run-all (every scan, then correlate)",
        extra={"event": "run_all", "component": "cli"},
    )
    return 1 if result.new_alerts else 0
