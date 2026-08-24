from __future__ import annotations

import argparse
from secure.arpwatch import scan_arp_table
from secure.storage.database import Database
from secure.storage.models import (
    find_arp_alert_by_id,
    list_arp_alerts,
    set_arp_alert_known,
)
from secure.cli import _bootstrap, _record_alert_review_change, logger

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def cmd_arpwatch_scan(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        result = scan_arp_table(db.conn)

    if not result.arp_available:
        print("Could not run `arp` (not installed, or it didn't finish in time).")
        print("No ARP data was recorded this scan.")
        logger.warning(
            "ARP watch scan could not run arp",
            extra={"event": "arpwatch_scan_failed", "component": "cli"},
        )
        return 1

    print(f"Scan at {result.scanned_at} (run id: {result.run_id})")
    print(f"Default gateway: {result.gateway_ip or 'could not be determined'}")
    print(f"ARP entries seen: {len(result.entries)}")
    print()

    for entry in sorted(result.entries, key=lambda e: e.ip):
        tag = " (gateway)" if entry.ip == result.gateway_ip else ""
        hostname = entry.hostname or "(no hostname)"
        print(f"  {entry.ip:15} {entry.mac:17} {hostname}{tag}")

    print()
    if result.alerts:
        ordered = sorted(result.alerts, key=lambda a: _SEVERITY_RANK.get(a.severity, 9))
        print(f"ALERTS ({len(ordered)}):")
        for alert in ordered:
            print(f"  #{alert.id} [{alert.severity.upper():6}] {alert.kind} — {alert.ip}")
            print(f"           {alert.message}")
        print()
        print("Review these, then: secure arpwatch mark <id> known|unknown")
    else:
        print("No alerts — nothing changed unexpectedly since the last scan.")

    logger.info(
        "Ran an ARP/neighbor-table scan",
        extra={"event": "arpwatch_scan", "component": "cli"},
    )
    return 1 if result.alerts else 0


def cmd_arpwatch_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        alerts = list_arp_alerts(db.conn)

    if not alerts:
        print("No arpwatch alerts recorded yet. Run `secure arpwatch scan` first.")
        return 0

    for record in alerts:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(
            f"[{tag:7}] #{record.id:<4} [{record.severity.upper():6}] "
            f"{record.kind} — {record.ip} — {record.created_at}"
        )
        print(f"          {record.message}")

    return 0


def cmd_arpwatch_mark(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        alert = find_arp_alert_by_id(db.conn, args.alert_id)
        if alert is None:
            print(
                f"No arpwatch alert found with id {args.alert_id}. "
                "Run `secure arpwatch list` to see recorded alerts."
            )
            return 1
        if alert.known != known:
            _record_alert_review_change(
                db.conn, source_table="arp_alerts", alert_id=alert.id, subject=alert.ip,
                severity=alert.severity, was_known=alert.known, now_known=known,
            )
        set_arp_alert_known(db.conn, alert.id, known)

    print(f"Marked #{args.alert_id} ({alert.kind}, {alert.ip}) as {args.status}.")
    logger.info(
        "Marked an arpwatch alert known/unknown",
        extra={"event": "arpwatch_mark", "component": "cli"},
    )
    return 0
