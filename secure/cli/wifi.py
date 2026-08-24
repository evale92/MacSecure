from __future__ import annotations

import argparse
from secure.storage.database import Database
from secure.storage.models import (
    find_wifi_alert_by_id,
    find_wifi_network_by_id,
    list_wifi_alerts,
    list_wifi_networks,
    set_wifi_alert_known,
    set_wifi_network_known,
)
from secure.wifi import scan_wifi
from secure.cli import _bootstrap, _record_alert_review_change, logger

def _format_bssid(status) -> str:
    if status.bssid_available:
        return status.bssid
    if status.bssid_unavailable_reason == "permission":
        return "Unavailable — permission required (macOS Location Services not granted to this process)"
    return "Unavailable — could not be determined"


def cmd_wifi_scan(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        result = scan_wifi(db.conn)

    status = result.status

    # Three distinct outcomes, deliberately not collapsed into one
    # "not connected" message — see secure/wifi/status.py's
    # get_wifi_status() docstring for why "couldn't tell" must never
    # be reported as "confirmed not connected."
    if status.status_unknown:
        print(
            "Secure could not determine Wi-Fi status — every diagnostic command "
            "(ipconfig, networksetup, ...) failed or timed out. This is NOT the same as "
            "confirming you're disconnected; try again, or check Wi-Fi manually."
        )
        logger.warning(
            "Wi-Fi scan could not determine status",
            extra={"event": "wifi_scan_status_unknown", "component": "cli"},
        )
        return 1

    if not status.connected:
        print("Not currently connected to any Wi-Fi network.")
        logger.info(
            "Ran a Wi-Fi scan (not connected)",
            extra={"event": "wifi_scan_not_connected", "component": "cli"},
        )
        return 0

    if not status.ssid:
        print(
            "Connected to a Wi-Fi network (this Mac has an active IP on its Wi-Fi "
            "interface), but the network's name (SSID) could not be determined from any "
            "source this scan. Nothing was recorded — try again."
        )
        logger.warning(
            "Wi-Fi scan connected but SSID undetermined",
            extra={"event": "wifi_scan_ssid_unknown", "component": "cli"},
        )
        return 1

    print(f"Scan at {result.scanned_at} (run id: {result.run_id})")
    print(f"SSID:     {status.ssid}")
    print(f"BSSID:    {_format_bssid(status)}")
    print(f"Channel:  {status.channel or 'unknown'}")
    print(f"PHY mode: {status.phy_mode or 'unknown'}")
    print(f"Security: {status.security or 'unknown'}")
    if status.rssi is not None:
        noise_display = f", noise {status.noise} dBm" if status.noise is not None else ""
        print(f"Signal:   {status.rssi} dBm{noise_display}")
    print()

    if result.security_severity:
        print(f"[{result.security_severity.upper()}] {result.security_note}")
    else:
        print(result.security_note)
    print()

    tag = "NEW" if result.is_new_network else ("KNOWN" if result.network_record.known else "UNKNOWN")
    print(f"Network: [{tag}] {status.ssid} ({status.bssid or 'BSSID unknown'})")
    if result.is_new_network:
        if result.other_bssids_for_ssid:
            print(
                f"  This SSID has other access points on record: "
                f"{', '.join(result.other_bssids_for_ssid)}. Often harmless (a mesh node, a "
                "new router, an additional access point) but also what an impersonating "
                "access point using the same network name looks like."
            )
        print(f"Review this, then: secure wifi mark {result.network_record.id} known|unknown")

    if result.alerts:
        print()
        print(f"ALERTS ({len(result.alerts)}):")
        for alert in result.alerts:
            print(f"  #{alert.id} [{alert.severity.upper()}] {alert.kind} — {alert.ssid}")
            print(f"           {alert.message}")
        print("Review these, then: secure wifi mark-alert <id> known|unknown")

    logger.info(
        "Ran a Wi-Fi scan",
        extra={"event": "wifi_scan", "component": "cli"},
    )
    return 1 if result.is_new_network or result.security_severity or result.alerts else 0


def cmd_wifi_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        networks = list_wifi_networks(db.conn)

    if not networks:
        print("No Wi-Fi networks recorded yet. Run `secure wifi scan` first.")
        return 0

    for record in networks:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(f"[{tag:7}] #{record.id:<4} {record.ssid} ({record.bssid or 'BSSID unknown'})")
        print(f"          first seen {record.first_seen}, last seen {record.last_seen}")

    return 0


def cmd_wifi_mark(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        network = find_wifi_network_by_id(db.conn, args.network_id)
        if network is None:
            print(
                f"No Wi-Fi network found with id {args.network_id}. "
                "Run `secure wifi list` to see recorded networks."
            )
            return 1
        set_wifi_network_known(db.conn, network.id, known)

    print(f"Marked #{args.network_id} ({network.ssid}) as {args.status}.")
    logger.info(
        "Marked a Wi-Fi network known/unknown",
        extra={"event": "wifi_mark", "component": "cli"},
    )
    return 0


def cmd_wifi_alerts(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        alerts = list_wifi_alerts(db.conn)

    if not alerts:
        print("No wifi alerts recorded yet. Run `secure wifi scan` first.")
        return 0

    for record in alerts:
        tag = "KNOWN" if record.known else "UNKNOWN"
        print(
            f"[{tag:7}] #{record.id:<4} [{record.severity.upper():6}] "
            f"{record.kind} — {record.ssid} — {record.created_at}"
        )
        print(f"          {record.message}")

    return 0


def cmd_wifi_mark_alert(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        alert = find_wifi_alert_by_id(db.conn, args.alert_id)
        if alert is None:
            print(
                f"No wifi alert found with id {args.alert_id}. "
                "Run `secure wifi alerts` to see recorded alerts."
            )
            return 1
        if alert.known != known:
            _record_alert_review_change(
                db.conn, source_table="wifi_alerts", alert_id=alert.id, subject=alert.ssid,
                severity=alert.severity, was_known=alert.known, now_known=known,
            )
        set_wifi_alert_known(db.conn, alert.id, known)

    print(f"Marked #{args.alert_id} ({alert.kind}, {alert.ssid}) as {args.status}.")
    logger.info(
        "Marked a wifi alert known/unknown",
        extra={"event": "wifi_mark_alert", "component": "cli"},
    )
    return 0
