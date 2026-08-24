"""
arpwatch/analysis.py — the pure "does this ARP data look suspicious"
logic: no subprocess calls, no database access, just plain data in and
a list of alerts out. Kept separate from scanner.py so it's testable
without a real Mac, same "pure function + shell wrapper" split used
throughout this app (see secure/checks/'s package docstring for where
that pattern started).

Three things are checked, each deliberately conservative about
severity — per the Claude prompt this phase was built from
("minimizing false positives"), because IP-to-MAC churn is mostly
normal life on a home network (phones sleep and reconnect, laptops
join and leave, DHCP leases move to different devices) and crying wolf
on all of it would just teach you to ignore this feature entirely:

    1. A non-gateway IP now resolves to a different MAC than last
       scan — severity "low". Usually a device was replaced, got a
       new network adapter, or a DHCP lease moved on. Only the
       gateway case below is treated as more than routine.
    2. The default gateway IP now resolves to a different MAC than
       last scan — severity "high". This is what ARP spoofing (an
       attacker inserting themselves between you and your router)
       looks like, but it's also exactly what happens after a router
       reboot, firmware update, or replacement — the message says
       both, deliberately not just the scary one.
    3. The SAME IP appears with more than one distinct MAC address
       within a single scan — severity "medium". A normal ARP cache
       (this app reads it, never writes to it) shouldn't show two
       different answers for the same address at once; it's a
       real inconsistency, but can also happen during ordinary
       transitions (a lease changing mid-scan), so it's flagged
       without assuming the worst.

This module never inspects, blocks, or reacts to anything — flagging
is the entire job. See the package docstring for the "no offensive ARP
spoofing tests, ever" rule this was built to honor.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Dict, List, Optional

from secure.inventory.arp_table import ArpEntry

_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def is_real_entry(entry: ArpEntry) -> bool:
    """Same filtering rule as secure/inventory/scanner.py's _is_real_device():
    an "incomplete" ARP row (mac=None) means nothing answered at that
    address, not a real mapping; the broadcast MAC and multicast IPs
    are protocol destinations, not a single device's mapping. Kept as
    its own small copy — a handful of lines, not worth importing a
    "private" helper from a different package for.
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
class ArpAlert:
    kind: str  # "mac_changed" | "gateway_mac_changed" | "ip_conflict"
    severity: str  # "low" | "medium" | "high"
    ip: str
    mac: Optional[str]
    previous_mac: Optional[str]
    message: str
    # Filled in by scanner.py after this alert is persisted — a pure
    # ArpAlert built by this module never has one yet.
    id: Optional[int] = None


def detect_intra_scan_conflicts(
    entries: List[ArpEntry], gateway_ip: Optional[str]
) -> List[ArpAlert]:
    """Flag any IP that appears with more than one distinct MAC in one scan."""
    macs_by_ip: Dict[str, set] = {}
    for entry in entries:
        macs_by_ip.setdefault(entry.ip, set()).add(entry.mac)

    alerts: List[ArpAlert] = []
    for ip, macs in sorted(macs_by_ip.items()):
        if len(macs) <= 1:
            continue
        mac_list = ", ".join(sorted(macs))
        gateway_note = " This is your default gateway." if ip == gateway_ip else ""
        alerts.append(
            ArpAlert(
                kind="ip_conflict",
                severity="medium",
                ip=ip,
                mac=None,
                previous_mac=None,
                message=(
                    f"{ip} answered ARP as {len(macs)} different MAC addresses in the same "
                    f"scan ({mac_list}).{gateway_note} A normal ARP cache shouldn't show two "
                    "answers for one address at once — this can happen during an ordinary "
                    "transition, but is also a signature of ARP spoofing if it keeps "
                    "happening."
                ),
            )
        )
    return alerts


def detect_mac_changes(
    current_by_ip: Dict[str, str],
    previous_by_ip: Dict[str, str],
    gateway_ip: Optional[str],
) -> List[ArpAlert]:
    """Compare this scan's IP -> MAC mapping against the last known mapping.

    Only IPs present in BOTH mappings are compared — an IP appearing
    for the first time isn't a "change" (that's secure/inventory/'s
    job, not this one), and an IP that stopped answering isn't either.
    """
    alerts: List[ArpAlert] = []
    for ip, mac in sorted(current_by_ip.items()):
        previous_mac = previous_by_ip.get(ip)
        if previous_mac is None or previous_mac == mac:
            continue

        is_gateway = ip == gateway_ip
        if is_gateway:
            message = (
                f"Your default gateway ({ip}) is now answering ARP as a different MAC "
                f"address ({previous_mac} -> {mac}). This is what ARP spoofing / a "
                "man-in-the-middle attempt looks like — but it's also exactly what happens "
                "after a router reboot, firmware update, or router replacement. If you "
                "didn't just do one of those, worth investigating."
            )
        else:
            message = (
                f"{ip} is now answering ARP as a different MAC address "
                f"({previous_mac} -> {mac}). Usually harmless — a DHCP lease moved to a "
                "different device, a device got a new network adapter, or it reconnected "
                "after being away. Worth a look only if you don't recognize the new address."
            )

        alerts.append(
            ArpAlert(
                kind="gateway_mac_changed" if is_gateway else "mac_changed",
                severity="high" if is_gateway else "low",
                ip=ip,
                mac=mac,
                previous_mac=previous_mac,
                message=message,
            )
        )
    return alerts
