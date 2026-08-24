"""
secure.inventory — Local Device Inventory.

Discovers devices currently visible on the local network this Mac is
connected to, using only safe, read-only, no-sudo local methods:

    - an ICMP ping sweep of this Mac's own subnet only, to populate
      the operating system's ARP cache (this never touches any other
      network, and never does anything beyond a single ping per host
      — no port scanning, no service fingerprinting);
    - reading that ARP cache (`arp -an`);
    - reverse-DNS hostname lookups (Python's own socket module — the
      same kind of lookup your Mac already does constantly);
    - a small built-in MAC-address-prefix (OUI) table for best-effort
      vendor names.

Every discovered device is stored (IP, MAC when available, hostname
when available, vendor when recognized, first-seen/last-seen
timestamps) and defaults to "unknown" until you mark it known — see
`secure inventory` in secure/cli.py or the "Device Inventory" GUI
category.

What this deliberately does NOT do, and why:
    - No port scanning or OS/service fingerprinting of other devices
      — that crosses from "notice what's on my network" into actively
      probing other machines, which is a different (and much more
      legally/ethically sensitive) thing.
    - No guarantee of completeness. A device that's asleep, that
      doesn't respond to ICMP, or that's on a different VLAN/subnet
      than this Mac simply won't show up. This is a best-effort
      snapshot, not a definitive census.
    - No calls out to the internet for vendor lookups (e.g. a hosted
      OUI database) — the vendor table here is small and local on
      purpose, consistent with this app's no-network-calls-except-
      where-explicitly-noted design (see secure/checks/software_update.py
      for the one exception elsewhere in the app).

See PROJECT_NOTES.md ("Local Device Inventory") for more.

    from secure.inventory import scan_network
    result = scan_network(conn)
    for record, was_new in result.devices:
        print(record.ip, record.mac, was_new)
"""

from __future__ import annotations

from secure.inventory.scanner import ScanResult, scan_network

__all__ = ["ScanResult", "scan_network"]
