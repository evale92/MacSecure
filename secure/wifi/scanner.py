"""
wifi/scanner.py — orchestrates one Wi-Fi security scan: read this
Mac's current Wi-Fi connection, compare it against everything this app
already knows about known networks, and flag anything worth a second
look.

Three things happen on every scan, each independent of the others:

    1. Weak/open security check (security_level.py) — re-evaluated
       fresh every time, like a Phase 2 posture check, since "this
       network's security type" is a standing condition, not a
       one-time event. Not stored as a discrete alert row (see
       database.py's wifi_alerts comment) — just reported in the scan
       output and reflected in the exit code.
    2. Known/unknown network tracking (upsert_wifi_network) — a
       first-time SSID+BSSID pair (or SSID alone, when the BSSID isn't
       available) is what "warn when joining an unknown network" and
       "detect a new BSSID for a known SSID" key off. Same
       new-entity-defaults-to-unknown pattern as
       devices/remote_endpoints/listening_services.
    3. Lookalike-SSID check (similarity.py) — only run for a network
       that's new to us (step 2), compared against every SSID already
       marked known. A genuine, discrete alert (stored in wifi_alerts),
       since it's tied to a specific network's first appearance rather
       than a recurring condition.

This module never joins, disconnects from, or otherwise changes any
Wi-Fi connection, and never performs any kind of Wi-Fi attack,
deauthentication, cracking, or packet injection — see the package
docstring and the Claude prompt this phase was built from.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from secure.baseline.engine import BaselineRunCounters, evaluate_and_record_feature_observation, finalize_baseline_run
from secure.baseline.entities import WIFI, wifi_key
from secure.storage.models import (
    WifiNetworkRecord,
    add_wifi_alert,
    add_wifi_observation,
    list_known_ssids,
    list_wifi_networks,
    upsert_wifi_network,
)
from secure.wifi.security_level import classify_security
from secure.wifi.similarity import find_similar_known_ssids
from secure.wifi.status import WifiStatus, get_wifi_status


@dataclass
class WifiAlert:
    kind: str  # currently just "similar_ssid"
    severity: str
    ssid: str
    bssid: Optional[str]
    message: str
    id: Optional[int] = None


@dataclass
class WifiScanResult:
    scanned_at: str
    run_id: str
    connected: bool
    status: Optional[WifiStatus] = None
    network_record: Optional[WifiNetworkRecord] = None
    is_new_network: bool = False
    other_bssids_for_ssid: List[str] = field(default_factory=list)
    security_severity: Optional[str] = None
    security_note: Optional[str] = None
    alerts: List[WifiAlert] = field(default_factory=list)


def scan_wifi(conn: sqlite3.Connection) -> WifiScanResult:
    """Run one Wi-Fi status scan and record the results.

    Returns connected=False (nothing recorded) if this Mac isn't
    currently on any Wi-Fi network, OR if that couldn't be determined
    at all — check `result.status.status_unknown` to tell those two
    apart (see secure/wifi/status.py's get_wifi_status() docstring);
    this function doesn't collapse that distinction, it just doesn't
    have anything more to do in either case. Also returns
    connected=False (nothing recorded) if this Mac has an active Wi-Fi
    connection but no source could determine its SSID — nothing
    meaningful to track without a network name.
    """
    started_at = datetime.now(timezone.utc)
    now = started_at.isoformat()
    run_id = uuid.uuid4().hex[:12]

    status = get_wifi_status()
    if not status.connected or not status.ssid:
        # Stage 4 approval item 3/12: a CONFIRMED "not connected"
        # (status_unknown=False) is a normal state — nothing to
        # evaluate, still a clean pass. But status_unknown=True means
        # every status source failed/timed out — a genuine sensor
        # failure, not a routine "nothing to do," so it must not look
        # like a clean pass (see WifiStatus.status_unknown's docstring).
        wifi_counters = BaselineRunCounters()
        if status.status_unknown:
            wifi_counters.record_error("Wi-Fi status could not be determined this scan (all sources failed/timed out)")
        finalize_baseline_run(conn, run_id, started_at, wifi_counters)
        return WifiScanResult(scanned_at=now, run_id=run_id, connected=False, status=status)

    security_severity, security_note = classify_security(status.security)

    # Read existing knowledge BEFORE writing anything this scan, same
    # "compare against the old state, then write the new state"
    # ordering used throughout secure/arpwatch/scanner.py.
    known_ssids_before = list_known_ssids(conn)
    other_bssids_for_ssid = sorted(
        {
            n.bssid
            for n in list_wifi_networks(conn)
            if n.ssid == status.ssid and n.bssid and n.bssid != status.bssid
        }
    )

    alerts: List[WifiAlert] = []
    if status.ssid not in known_ssids_before:
        for match in find_similar_known_ssids(status.ssid, known_ssids_before):
            alerts.append(
                WifiAlert(
                    kind="similar_ssid",
                    severity="medium",
                    ssid=status.ssid,
                    bssid=status.bssid,
                    message=(
                        f"'{status.ssid}' closely resembles a network you already trust, "
                        f"'{match}'. This can be an innocent coincidence (two nearby "
                        "networks with similar names), but it's also how a rogue lookalike "
                        "access point (an 'evil twin') tries to trick you into connecting. "
                        "Double-check the name before treating this like your usual network."
                    ),
                )
            )

    network_record, is_new_network = upsert_wifi_network(
        conn, ssid=status.ssid, bssid=status.bssid if status.bssid_available else None
    )

    observation_id = add_wifi_observation(
        conn,
        run_id=run_id,
        ssid=status.ssid,
        bssid=status.bssid,
        channel=status.channel,
        phy_mode=status.phy_mode,
        security=status.security,
        rssi=status.rssi,
        noise=status.noise,
    )

    # Product Phase 14: wifi_observations already stores `security`,
    # but only as the raw current-scan value — there's no summarized
    # frequency/history view of it anywhere, which is what baselining
    # needs (see database.py's schema comment on
    # baseline_feature_activity for why this feature is included
    # despite wifi_observations technically existing). status.security
    # being falsy means the enrichment step itself couldn't determine
    # it (see wifi/status.py) — a sensor gap, not a real "no security"
    # observation, so it's marked partial_sensor_data rather than
    # trained on. is_weak_wifi_security reuses classify_security()'s
    # own verdict (security_severity is not None for WEP/WPA/open) —
    # never re-derived here.
    #
    # Phase 14.5 Stage B: source_id references the exact
    # wifi_observations row this scan just wrote (observation_id, a
    # real per-row id — add_wifi_observation() has always returned one,
    # since a Wi-Fi scan is a single-row insert, never bulk), not
    # wifi_networks.id — that table is a DEDUPED identity row updated
    # in place across every scan of this SSID/BSSID, so it can't
    # identify which specific scan produced a given anomaly (the same
    # class of imprecise reference process_destination's provenance fix
    # corrected earlier — see PROJECT_NOTES.md's change log).
    counters = BaselineRunCounters()
    try:
        evaluate_and_record_feature_observation(
            conn, run_id, WIFI, wifi_key(status.ssid), "security",
            status.security if status.security else None,
            now,
            partial_sensor_data=not status.security,
            is_weak_wifi_security=(security_severity is not None),
            source_table="wifi_observations", source_id=observation_id,
            counters=counters,
        )
    except Exception as exc:  # noqa: BLE001 - defensive, see baseline_runs.errors_count
        counters.record_error(f"wifi security baseline evaluation failed for {status.ssid!r}: {exc}")
    finalize_baseline_run(conn, run_id, started_at, counters)

    for alert in alerts:
        alert.id = add_wifi_alert(
            conn,
            run_id=run_id,
            kind=alert.kind,
            severity=alert.severity,
            ssid=alert.ssid,
            bssid=alert.bssid,
            message=alert.message,
        )

    return WifiScanResult(
        scanned_at=now,
        run_id=run_id,
        connected=True,
        status=status,
        network_record=network_record,
        is_new_network=is_new_network,
        other_bssids_for_ssid=other_bssids_for_ssid if is_new_network else [],
        security_severity=security_severity,
        security_note=security_note,
        alerts=alerts,
    )
