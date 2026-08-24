"""
arpwatch/scanner.py — orchestrates a full ARP/neighbor-table scan:
read this Mac's ARP cache, find the current default gateway, compare
against what was seen last scan, and record everything.

Parsing is shared with secure/inventory/ (parse_arp_output(),
ArpEntry, normalize_mac, via secure.inventory.arp_table) rather than
duplicated — same reasoning as secure/listening/ reusing
secure/connections/lsof_parser.py: that parser already exists,
already has its own tests, and a second copy would be a maintenance
risk, not real independence. Running the command is still this
package's own (own _shell.py) — see PROJECT_NOTES.md's "keep every
monitoring feature in its own module."

This is the only file in the arpwatch package that touches the
database. This module only observes and records; per the Claude
prompt this phase was built from, it never performs any active ARP
spoofing test or otherwise touches the network beyond reading the
already-populated ARP cache.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from secure.arpwatch._shell import run
from secure.arpwatch.analysis import ArpAlert, detect_intra_scan_conflicts, detect_mac_changes, is_real_entry
from secure.arpwatch.gateway import get_default_gateway
from secure.inventory.arp_table import ArpEntry, parse_arp_output
from secure.storage.models import (
    add_arp_alert,
    add_arp_observations,
    list_arp_mappings,
    upsert_arp_mapping,
)


@dataclass
class ArpWatchResult:
    scanned_at: str
    run_id: str
    arp_available: bool = True
    gateway_ip: Optional[str] = None
    entries: List[ArpEntry] = field(default_factory=list)
    alerts: List[ArpAlert] = field(default_factory=list)


def scan_arp_table(conn: sqlite3.Connection) -> ArpWatchResult:
    """Run one ARP/neighbor-table scan and record the results.

    Every real ARP entry goes into arp_observations (full history).
    This Mac's current IP -> MAC state is upserted into arp_mappings.
    Any alert raised (MAC change, gateway MAC change, or a same-scan
    conflict — see analysis.py) is stored in arp_alerts.
    """
    now = datetime.now(timezone.utc).isoformat()
    run_id = uuid.uuid4().hex[:12]

    result = run(["arp", "-an"], timeout=10.0)
    if result.returncode is None:
        return ArpWatchResult(scanned_at=now, run_id=run_id, arp_available=False)

    # Read BEFORE writing anything this scan, or comparisons below
    # would just be comparing this run against itself.
    previous_by_ip = {m.ip: m.mac for m in list_arp_mappings(conn)}
    gateway_ip = get_default_gateway()

    all_entries = parse_arp_output(result.stdout)
    real_entries = [e for e in all_entries if is_real_entry(e)]

    conflict_alerts = detect_intra_scan_conflicts(real_entries, gateway_ip)

    # Last-write-wins for the "current mapping" snapshot when a
    # conflict exists — that specific inconsistency is already
    # captured by conflict_alerts above; this dict only needs to
    # represent "what should arp_mappings say now."
    current_by_ip: Dict[str, str] = {}
    for entry in real_entries:
        current_by_ip[entry.ip] = entry.mac

    change_alerts = detect_mac_changes(current_by_ip, previous_by_ip, gateway_ip)
    alerts = conflict_alerts + change_alerts

    obs_rows = [(e.ip, e.mac, e.hostname) for e in real_entries]
    if obs_rows:
        add_arp_observations(conn, run_id=run_id, rows=obs_rows)

    for ip, mac in current_by_ip.items():
        upsert_arp_mapping(conn, ip=ip, mac=mac, is_gateway=(ip == gateway_ip))

    for alert in alerts:
        alert.id = add_arp_alert(
            conn,
            run_id=run_id,
            kind=alert.kind,
            severity=alert.severity,
            ip=alert.ip,
            mac=alert.mac,
            previous_mac=alert.previous_mac,
            message=alert.message,
        )

    return ArpWatchResult(
        scanned_at=now,
        run_id=run_id,
        arp_available=True,
        gateway_ip=gateway_ip,
        entries=real_entries,
        alerts=alerts,
    )
