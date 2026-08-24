"""
inventory/ping_sweep.py — sends one ICMP echo (ping) to each address
in this Mac's own subnet, so the operating system's ARP cache gets
populated with whatever responds. `arp_table.py` reads that cache
afterward; this module doesn't parse or return any responses itself
— the ping is purely to trigger the OS's own ARP resolution, which is
how it always discovers MAC addresses for IPs it wants to reach.

This is a "non-invasive discovery" method: one ICMP echo per host,
same as running `ping` by hand, never repeated, never any other kind
of packet. It stays entirely within the subnet passed in — see
network_info.py for how that subnet is determined (this Mac's own,
clamped to /24) — so it never touches a network you don't own.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import List

from secure.inventory._shell import run


def ping_sweep(hosts: List[str], *, timeout_seconds: int = 1, max_workers: int = 32) -> None:
    """Ping every host in `hosts` once, in parallel. Side-effect only (no return value)."""
    if not hosts:
        return

    def _ping_one(host: str) -> None:
        run(["ping", "-c", "1", "-t", str(timeout_seconds), host], timeout=timeout_seconds + 1)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # list() forces the map to fully execute before returning.
        list(executor.map(_ping_one, hosts))
