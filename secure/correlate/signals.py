"""
correlate/signals.py — reads every other module's tables and turns
their "new/flagged" rows into a common Signal shape. This is the only
file in secure/correlate/ that touches the database directly (mirrors
every other package's "one file does the I/O, everything else is
pure" split — just reading SQLite instead of shelling out, since
correlation has nothing new to observe about the outside world; it
only re-examines what other scans already recorded).

Two kinds of existing rows become signals:

    1. The alert tables that already carry a severity: arp_alerts,
       wifi_alerts, bluetooth_alerts, ble_alerts, persistence_alerts,
       and (Phase 15) integration_alerts.
    2. The "known/trusted = False" rows in devices, remote_endpoints,
       listening_services, wifi_networks, bluetooth_devices,
       ble_peripherals, process_entries — ordinary "this is new"
       findings that don't get their own alert row today, but still
       matter once they cluster with something else.

integration_alerts (Phase 15, extended Phase 16) is read the same way
persistence_alerts is — an alert-table source, never a raw "new
observation" source — see _collect_integrations()'s own docstring for
why this specific choice is what prevents a native/osquery match (or,
Phase 16, a YARA-X scan that found nothing) on the same underlying fact
from ever being counted as independent corroboration. The table is
shared across every integration (`integration` column distinguishes
osquery vs yarax rows); which of strength.py's two integration-specific
classifiers applies is dispatched per-row by that column, since
osquery's discrepancy-keyed rule and yarax's severity-keyed rule mean
two very different things by "strong evidence."

`persistence_entries`' bare-new rows are deliberately NOT read here —
every new persistence entry already produces a persistence_alerts row
at the same instant (persistence_entry_alert_severity() never returns
"no alert"), so including both would double-count the same event.
`process_entries`, by contrast, IS read directly (not via
persistence_alerts' target_type="process" rows) — persistence.py only
raises a process alert for unusual/unsigned processes, never for an
ordinary signed one, so reading process_entries directly is the only
way an ordinary "new signed process" WEAK signal exists at all (see
the user's explicit WEAK-tier bullet for it).

For wifi_networks/bluetooth_devices/ble_peripherals specifically, a
bare-new row is skipped if that same identifier already produced an
alert row in the same table family (a lookalike SSID, a new pairing,
etc.) — otherwise the same real-world event would show up twice: once
as a WEAK "just new" signal and again as its own STRONG/MEDIUM alert.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from secure.correlate.strength import (
    MEDIUM,
    STRONG,
    WEAK,
    classify_arp_alert_strength,
    classify_bluetooth_alert_strength,
    classify_file_integrity_strength,
    classify_integration_alert_strength,
    classify_listening_strength,
    classify_persistence_alert_strength,
    classify_process_strength,
    classify_sigma_finding_strength,
    classify_suricata_finding_strength,
    classify_yarax_finding_strength,
)


@dataclass
class Signal:
    timestamp: datetime
    module: str
    kind: str
    strength: str  # weak / medium / strong — see strength.py
    identifier: str
    label: Optional[str]
    source_table: str
    source_id: int

    def as_dict(self) -> dict:
        return {
            "module": self.module,
            "kind": self.kind,
            "strength": self.strength,
            "identifier": self.identifier,
            "label": self.label,
            "source_table": self.source_table,
            "source_id": self.source_id,
            "timestamp": self.timestamp.isoformat(),
        }


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _collect_inventory(conn: sqlite3.Connection, cutoff_iso: str) -> list[Signal]:
    rows = conn.execute(
        "SELECT id, ip, mac, first_seen FROM devices WHERE known = 0 AND first_seen >= ?",
        (cutoff_iso,),
    ).fetchall()
    return [
        Signal(
            timestamp=_parse_ts(row["first_seen"]),
            module="inventory",
            kind="new_device",
            strength=WEAK,
            identifier=row["mac"] or row["ip"],
            label=row["mac"] or row["ip"],
            source_table="devices",
            source_id=row["id"],
        )
        for row in rows
    ]


def _collect_connections(conn: sqlite3.Connection, cutoff_iso: str) -> list[Signal]:
    rows = conn.execute(
        "SELECT id, remote_addr, remote_port, proto, process_name, first_seen "
        "FROM remote_endpoints WHERE known = 0 AND first_seen >= ?",
        (cutoff_iso,),
    ).fetchall()
    signals = []
    for row in rows:
        identifier = f"{row['remote_addr']}:{row['remote_port']}/{row['proto']}"
        signals.append(
            Signal(
                timestamp=_parse_ts(row["first_seen"]),
                module="connections",
                kind="new_remote_endpoint",
                strength=WEAK,
                identifier=identifier,
                label=row["process_name"],
                source_table="remote_endpoints",
                source_id=row["id"],
            )
        )
    return signals


def _collect_listening(conn: sqlite3.Connection, cutoff_iso: str) -> list[Signal]:
    rows = conn.execute(
        "SELECT id, proto, bind_scope, process_name, identity_port, first_seen "
        "FROM listening_services WHERE known = 0 AND first_seen >= ?",
        (cutoff_iso,),
    ).fetchall()
    return [
        Signal(
            timestamp=_parse_ts(row["first_seen"]),
            module="listening",
            kind="new_listening_service",
            strength=classify_listening_strength(row["bind_scope"]),
            identifier=f"{row['process_name']}:{row['identity_port']}/{row['proto']}",
            label=row["process_name"],
            source_table="listening_services",
            source_id=row["id"],
        )
        for row in rows
    ]


def _collect_arpwatch(conn: sqlite3.Connection, cutoff_iso: str) -> list[Signal]:
    rows = conn.execute(
        "SELECT id, kind, ip, mac, created_at FROM arp_alerts WHERE created_at >= ?",
        (cutoff_iso,),
    ).fetchall()
    return [
        Signal(
            timestamp=_parse_ts(row["created_at"]),
            module="arpwatch",
            kind=row["kind"],
            strength=classify_arp_alert_strength(row["kind"]),
            identifier=row["ip"],
            label=row["mac"],
            source_table="arp_alerts",
            source_id=row["id"],
        )
        for row in rows
    ]


def _collect_wifi(conn: sqlite3.Connection, cutoff_iso: str) -> list[Signal]:
    alert_rows = conn.execute(
        "SELECT id, kind, ssid, bssid, created_at FROM wifi_alerts WHERE created_at >= ?",
        (cutoff_iso,),
    ).fetchall()
    signals = [
        Signal(
            timestamp=_parse_ts(row["created_at"]),
            module="wifi",
            kind=row["kind"],
            strength=STRONG,  # the only wifi_alerts kind today is lookalike_ssid
            identifier=row["ssid"],
            label=row["bssid"],
            source_table="wifi_alerts",
            source_id=row["id"],
        )
        for row in alert_rows
    ]
    alerted_ssids = {row["ssid"] for row in alert_rows}

    network_rows = conn.execute(
        "SELECT id, ssid, bssid, first_seen FROM wifi_networks WHERE known = 0 AND first_seen >= ?",
        (cutoff_iso,),
    ).fetchall()
    for row in network_rows:
        if row["ssid"] in alerted_ssids:
            continue
        signals.append(
            Signal(
                timestamp=_parse_ts(row["first_seen"]),
                module="wifi",
                kind="new_network",
                strength=WEAK,
                identifier=row["ssid"],
                label=row["bssid"],
                source_table="wifi_networks",
                source_id=row["id"],
            )
        )
    return signals


def _collect_bluetooth(conn: sqlite3.Connection, cutoff_iso: str) -> list[Signal]:
    alert_rows = conn.execute(
        "SELECT id, kind, identifier, name, created_at FROM bluetooth_alerts WHERE created_at >= ?",
        (cutoff_iso,),
    ).fetchall()
    signals = [
        Signal(
            timestamp=_parse_ts(row["created_at"]),
            module="bluetooth",
            kind=row["kind"],
            strength=classify_bluetooth_alert_strength(row["kind"]),
            identifier=row["identifier"],
            label=row["name"],
            source_table="bluetooth_alerts",
            source_id=row["id"],
        )
        for row in alert_rows
    ]
    alerted_identifiers = {row["identifier"] for row in alert_rows}

    device_rows = conn.execute(
        "SELECT id, identifier, name, first_seen FROM bluetooth_devices "
        "WHERE trusted = 0 AND first_seen >= ?",
        (cutoff_iso,),
    ).fetchall()
    for row in device_rows:
        if row["identifier"] in alerted_identifiers:
            continue
        signals.append(
            Signal(
                timestamp=_parse_ts(row["first_seen"]),
                module="bluetooth",
                kind="new_device",
                strength=WEAK,
                identifier=row["identifier"],
                label=row["name"],
                source_table="bluetooth_devices",
                source_id=row["id"],
            )
        )
    return signals


def _collect_ble(conn: sqlite3.Connection, cutoff_iso: str) -> list[Signal]:
    alert_rows = conn.execute(
        "SELECT id, kind, cb_uuid, name, created_at FROM ble_alerts WHERE created_at >= ?",
        (cutoff_iso,),
    ).fetchall()
    signals = [
        Signal(
            timestamp=_parse_ts(row["created_at"]),
            module="ble",
            kind=row["kind"],
            strength=WEAK,  # every ble_alerts kind (persistent_unknown, rssi change) is weak
            identifier=row["cb_uuid"],
            label=row["name"],
            source_table="ble_alerts",
            source_id=row["id"],
        )
        for row in alert_rows
    ]
    alerted_uuids = {row["cb_uuid"] for row in alert_rows}

    peripheral_rows = conn.execute(
        "SELECT id, cb_uuid, name, first_seen FROM ble_peripherals "
        "WHERE trusted = 0 AND first_seen >= ?",
        (cutoff_iso,),
    ).fetchall()
    for row in peripheral_rows:
        if row["cb_uuid"] in alerted_uuids:
            continue
        signals.append(
            Signal(
                timestamp=_parse_ts(row["first_seen"]),
                module="ble",
                kind="new_peripheral",
                strength=WEAK,
                identifier=row["cb_uuid"],
                label=row["name"],
                source_table="ble_peripherals",
                source_id=row["id"],
            )
        )
    return signals


def _collect_process(conn: sqlite3.Connection, cutoff_iso: str) -> list[Signal]:
    rows = conn.execute(
        "SELECT id, executable_path, process_name, signing_status, first_seen "
        "FROM process_entries WHERE known = 0 AND first_seen >= ?",
        (cutoff_iso,),
    ).fetchall()
    return [
        Signal(
            timestamp=_parse_ts(row["first_seen"]),
            module="process",
            kind="new_process",
            strength=classify_process_strength(row["signing_status"], row["executable_path"]),
            identifier=row["executable_path"],
            label=row["process_name"],
            source_table="process_entries",
            source_id=row["id"],
        )
        for row in rows
    ]


def _collect_persistence(conn: sqlite3.Connection, cutoff_iso: str) -> list[Signal]:
    rows = conn.execute(
        "SELECT id, kind, severity, target_type, identifier, label, created_at "
        "FROM persistence_alerts WHERE target_type != 'process' AND created_at >= ?",
        (cutoff_iso,),
    ).fetchall()
    return [
        Signal(
            timestamp=_parse_ts(row["created_at"]),
            module="persistence",
            kind=row["kind"],
            strength=classify_persistence_alert_strength(row["severity"]),
            identifier=row["identifier"],
            label=row["label"],
            source_table="persistence_alerts",
            source_id=row["id"],
        )
        for row in rows
    ]


def _collect_file_integrity(conn: sqlite3.Connection, cutoff_iso: str) -> list[Signal]:
    """file_integrity_alerts only — LOW-severity file-integrity
    findings (an ordinary mtime-only change, a documentation edit)
    never reach that table at all (see scanner.py), so there's no
    "bare new row" dimension to also read here the way process_entries
    or wifi_networks need, and no double-counting risk to guard
    against on that front.

    Deliberately NOT joined against persistence_alerts here or
    anywhere else in this module: a LaunchAgent/LaunchDaemon change
    can legitimately produce BOTH a persistence_alerts row (semantic
    interpretation) and a file_integrity_alerts row (byte-level proof)
    for the exact same real-world event, and both are preserved as
    independent evidence rather than one suppressing the other at scan
    time — see fileintegrity/scanner.py's module docstring. Instead,
    "avoid double-counting in correlation" is handled at the SCORING
    layer: {"file_integrity", "persistence"} is deliberately NOT in
    MEANINGFUL_MODULE_PAIRS (see analysis.py), so a cluster containing
    only those two modules reporting the same underlying change gets
    no artificial "independent corroboration" bonus for that pair —
    while a genuinely separate third module (e.g. a new connection or
    process) still contributes its own signal weight and its own
    meaningful-pair bonuses normally. This works regardless of whether
    persistence or file-integrity scanned first, or ran standalone —
    nothing here depends on scan order.
    """
    rows = conn.execute(
        "SELECT id, kind, severity, path, created_at FROM file_integrity_alerts WHERE created_at >= ?",
        (cutoff_iso,),
    ).fetchall()
    return [
        Signal(
            timestamp=_parse_ts(row["created_at"]),
            module="file_integrity",
            kind=row["kind"],
            strength=classify_file_integrity_strength(row["severity"]),
            identifier=row["path"],
            label=None,
            source_table="file_integrity_alerts",
            source_id=row["id"],
        )
        for row in rows
    ]


def _classify_integration_signal_strength(integration: str, discrepancy: str, severity: str) -> str:
    """Dispatches to the right integration-specific strength rule by the
    row's own `integration` column — osquery's discrepancy-keyed rule,
    yarax's severity-keyed rule (Phase 16), sigma's own severity-keyed
    rule (Phase 17), and suricata's own severity-keyed rule (Phase 18)
    each mean something different by "strong evidence" (see
    strength.py's own docstrings for each). Any future integration not
    yet recognized here falls back to the osquery-style rule as a
    conservative default rather than raising — an unrecognized
    integration name should degrade gracefully, not break correlation.
    """
    if integration == "yarax":
        return classify_yarax_finding_strength(severity)
    if integration == "sigma":
        return classify_sigma_finding_strength(severity)
    if integration == "suricata":
        return classify_suricata_finding_strength(severity)
    return classify_integration_alert_strength(discrepancy)


# Phase 19 note: Zeek ("integration"="zeek" rows in integration_
# observations) deliberately has NO branch here and contributes NO rows
# to integration_alerts at all — see secure/integrations/zeek/scanner.py's
# module docstring. Since _collect_integrations() below only ever reads
# integration_alerts (never integration_observations), Zeek structurally
# can never become a correlation Signal — a deliberate architectural
# choice enforcing "Zeek = behavioral telemetry, never detection
# evidence," not a gap in this file.


def _collect_integrations(conn: sqlite3.Connection, cutoff_iso: str) -> list[Signal]:
    """integration_alerts only (Phase 15, extended Phase 16) —
    deliberately NOT integration_observations, and this is the whole
    point, not an oversight. Every row in integration_observations is
    just this scan's raw normalized external-tool data; a fact BOTH an
    integration and Secure's native collectors agree on (osquery) or a
    scan that found nothing (yarax) never produces an integration_alerts
    row at all (see secure/integrations/osquery/crosscheck.py's module
    docstring, and secure/integrations/yarax/parser.py's "zero matches
    -> zero observations" note) — only a genuine finding does. So
    reading integration_alerts here, the same way _collect_persistence()
    reads persistence_alerts rather than raw persistence_observations,
    is what structurally guarantees an agreeing/empty result can never
    become a correlation signal for the same underlying real-world fact
    — there is nothing here to double-count in the first place, by
    construction, not by a scoring-layer workaround.
    """
    rows = conn.execute(
        "SELECT id, integration, kind, discrepancy, severity, identity_key, label, created_at "
        "FROM integration_alerts WHERE created_at >= ?",
        (cutoff_iso,),
    ).fetchall()
    signals = []
    for row in rows:
        integration = row["integration"]
        # osquery's kind carries the discrepancy type in its own string
        # (e.g. "listening_port_osquery_only") for display purposes —
        # yarax's kind is already a clean, standalone label ("yara_match"),
        # so it isn't suffixed with the always-constant discrepancy="match".
        kind = f"{row['kind']}_{row['discrepancy']}" if integration == "osquery" else row["kind"]
        signals.append(
            Signal(
                timestamp=_parse_ts(row["created_at"]),
                module="integrations",
                kind=kind,
                strength=_classify_integration_signal_strength(
                    integration, row["discrepancy"], row["severity"]
                ),
                identifier=row["identity_key"],
                label=row["label"],
                source_table="integration_alerts",
                source_id=row["id"],
            )
        )
    return signals


def _upgrade_connections_from_strong_processes(
    all_signals: list[Signal], process_signals: list[Signal]
) -> None:
    """Bump a "new remote endpoint" signal from WEAK to STRONG when its
    process name matches a STRONG (confirmed unsigned/ad-hoc-signed)
    new process — "a previously unseen remote endpoint from a new/
    untrusted process," one of the user's explicit STRONG bullets, made
    traceable via a real join on process name rather than mere time
    proximity. Matched by name only, since remote_endpoints never
    records a full executable path — a documented approximation; a
    coincidentally-shared process name between an unrelated legitimate
    and unsigned binary could in theory cause a false upgrade, accepted
    as a rare edge case in exchange for real traceability.
    """
    strong_names = {s.label for s in process_signals if s.strength == STRONG and s.label}
    if not strong_names:
        return
    for signal in all_signals:
        if signal.module == "connections" and signal.strength == WEAK and signal.label in strong_names:
            signal.strength = STRONG
            signal.kind = "new_remote_endpoint_from_untrusted_process"


def collect_signals(conn: sqlite3.Connection, lookback_hours: float = 24.0) -> list[Signal]:
    """Gather every correlation-eligible signal across every module,
    within the last `lookback_hours`, sorted oldest first.
    """
    cutoff_iso = (datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).isoformat()

    signals: list[Signal] = []
    signals.extend(_collect_inventory(conn, cutoff_iso))
    signals.extend(_collect_connections(conn, cutoff_iso))
    signals.extend(_collect_listening(conn, cutoff_iso))
    signals.extend(_collect_arpwatch(conn, cutoff_iso))
    signals.extend(_collect_wifi(conn, cutoff_iso))
    signals.extend(_collect_bluetooth(conn, cutoff_iso))
    signals.extend(_collect_ble(conn, cutoff_iso))

    process_signals = _collect_process(conn, cutoff_iso)
    signals.extend(process_signals)
    signals.extend(_collect_persistence(conn, cutoff_iso))
    signals.extend(_collect_file_integrity(conn, cutoff_iso))
    signals.extend(_collect_integrations(conn, cutoff_iso))

    _upgrade_connections_from_strong_processes(signals, process_signals)

    signals.sort(key=lambda s: s.timestamp)
    return signals
