"""
inventory/scanner.py — orchestrates a full local-network device scan:
(optionally) a ping sweep to populate the ARP cache, then reading that
cache, resolving hostnames, looking up vendors, and recording
everything in the `devices` table.

This is the only file in the inventory package that touches the
database — every other module here just discovers or parses
information and hands back plain data (see the other modules for the
read-only/no-sudo methods used).
"""

from __future__ import annotations

import ipaddress
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from secure.baseline.engine import BaselineRunCounters, finalize_baseline_run
from secure.baseline.history import record_gap_observation
from secure.baseline.entities import INVENTORY, inventory_key
from secure.inventory.arp_table import ArpEntry, read_arp_table_with_availability
from secure.inventory.hostnames import resolve_hostname_with_status
from secure.inventory.network_info import get_local_subnet
from secure.inventory.ping_sweep import ping_sweep
from secure.inventory.vendor import lookup_vendor
from secure.storage.models import DeviceRecord, upsert_device

_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def _is_real_device(entry: ArpEntry) -> bool:
    """Filter out ARP rows that don't represent an actual device.

    An address a scan probed but got no reply from shows up in the ARP
    cache as an "incomplete" entry (mac=None) — that means "nothing is
    there," not "here's a device with no MAC," so it's excluded rather
    than stored. The broadcast MAC and multicast IPs (224.0.0.0/4,
    used for mDNS/protocol traffic) are real ARP rows but represent
    protocol destinations, not physical devices, so they're excluded
    too.
    """
    if entry.mac is None or entry.mac == _BROADCAST_MAC:
        return False
    try:
        if ipaddress.ip_address(entry.ip).is_multicast:
            return False
    except ValueError:
        return False
    return True


@dataclass
class ScanResult:
    scanned_at: str
    subnet: Optional[str]  # e.g. "192.168.1.10/24 (interface en0)", or None
    ping_sweep_performed: bool
    raw_arp_rows: int = 0  # everything arp -an returned, before filtering
    devices: List[Tuple[DeviceRecord, bool]] = field(default_factory=list)  # (record, was_new)
    # Phase 29 Stage 5: False means `arp -an` itself failed to run this
    # scan (not found/timed out) — zero devices found is then a sensor
    # failure, never a clean "nothing on the network" result. Mirrors
    # secure/arpwatch/scanner.py's own arp_available field.
    arp_available: bool = True
    # How many devices this scan has no hostname for because the
    # reverse-DNS lookup timed out or the resolver failed — NOT because
    # the device has no PTR record, which is the ordinary case and is
    # not counted here. Same "sensor failure, not silence" discipline
    # as arp_available above (invariant 5).
    hostname_lookups_degraded: int = 0

    @property
    def new_devices(self) -> List[DeviceRecord]:
        return [record for record, was_new in self.devices if was_new]

    @property
    def filtered_out(self) -> int:
        """How many raw ARP rows were empty addresses/broadcast/multicast, not devices."""
        return self.raw_arp_rows - len(self.devices)


def scan_network(
    conn: sqlite3.Connection,
    *,
    do_ping_sweep: bool = True,
    ping_timeout_seconds: int = 1,
    max_ping_workers: int = 32,
) -> ScanResult:
    """Discover devices on the local network and record them.

    Set do_ping_sweep=False to skip the active ping sweep and only
    read whatever's already in the ARP cache (faster, but likely finds
    fewer devices — only ones this Mac has talked to recently on its
    own).
    """
    started_at = datetime.now(timezone.utc)
    now = started_at.isoformat()

    subnet = get_local_subnet()
    performed_sweep = False
    if subnet is not None and do_ping_sweep:
        ping_sweep(
            subnet.hosts(),
            timeout_seconds=ping_timeout_seconds,
            max_workers=max_ping_workers,
        )
        performed_sweep = True

    entries, arp_available = read_arp_table_with_availability()
    real_entries = [entry for entry in entries if _is_real_device(entry)]

    baseline_run_id = uuid.uuid4().hex[:12]
    counters = BaselineRunCounters()
    if not arp_available:
        # Same "sensor failure, not silence" discipline as
        # wifi/scanner.py's status_unknown handling — a scan that found
        # zero devices because `arp` itself couldn't run must never look
        # identical to a scan that genuinely found zero devices.
        counters.record_error("ARP cache could not be read this scan (arp command unavailable/timed out)")

    results: List[Tuple[DeviceRecord, bool]] = []
    hostname_lookups_degraded = 0
    for entry in real_entries:
        hostname = entry.hostname
        if hostname is None:
            lookup = resolve_hostname_with_status(entry.ip)
            hostname = lookup.hostname
            if lookup.degraded:
                # A name missing because the resolver never answered is
                # a sensor that could not determine a value, so the pass
                # is 'partial' — the same channel persistence/scanner.py
                # uses for a codesign UNKNOWN (partial_sensor_data ->
                # incomplete_inputs), and deliberately not
                # record_error(): the device itself was observed and
                # stored, so this pass is degraded, never 'failed'.
                hostname_lookups_degraded += 1
                counters.incomplete_inputs += 1
        vendor = lookup_vendor(entry.mac)
        record, was_new = upsert_device(
            conn, ip=entry.ip, mac=entry.mac, hostname=hostname, vendor=vendor
        )
        results.append((record, was_new))

        # Product Phase 14: this Mac's LAN-device history has no
        # existing per-scan log to read from (devices only stores
        # first_seen/last_seen — see database.py's schema comment), so
        # every observation is logged here via the baseline_activity
        # gap-filler instead. Never blocks or slows the scan itself — a
        # failure here is caught, counted (Stage 4 approval item 2/3:
        # baseline_runs.errors_count), and the inventory scan's own
        # real result is still returned.
        try:
            record_gap_observation(
                conn, baseline_run_id, INVENTORY, inventory_key(record.mac, record.ip), now,
                counters=counters,
            )
        except Exception as exc:  # noqa: BLE001 - defensive, see baseline_runs.errors_count
            counters.record_error(f"inventory baseline observation failed for {record.ip!r}: {exc}")

    # Stage 4B: one baseline_runs row per scan, even when zero devices
    # were found this pass — a "nothing observed" pass is still a
    # clean, complete pass (status='success'), not silence.
    finalize_baseline_run(conn, baseline_run_id, started_at, counters)

    subnet_str = None
    if subnet is not None:
        subnet_str = f"{subnet.local_ip}/{subnet.prefix_len} (interface {subnet.interface})"

    return ScanResult(
        scanned_at=now,
        subnet=subnet_str,
        ping_sweep_performed=performed_sweep,
        raw_arp_rows=len(entries),
        devices=results,
        arp_available=arp_available,
        hostname_lookups_degraded=hostname_lookups_degraded,
    )
