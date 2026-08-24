"""
inventory/arp_table.py — reads and parses this Mac's ARP cache.

The ARP cache maps IP addresses to MAC addresses for devices this Mac
has recently exchanged traffic with on the local network — that's
exactly the "which devices are visible right now" signal this feature
needs. Reading it (`arp -an`) needs no sudo and changes nothing.

Uses `-n` (numeric) specifically to skip arp's own built-in hostname
resolution — that step can hang well past a few seconds when arp is
run non-interactively (no controlling terminal), even though it feels
instant when you type `arp -a` yourself in Terminal. Hostnames are
resolved separately and more reliably by hostnames.py instead, so
nothing is lost by skipping arp's version of it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from secure.inventory._shell import run

# Matches lines like:
#   gateway.local (192.168.1.1) at ac:de:48:0:11:22 on en0 ifscope [ethernet]
#   ? (192.168.1.42) at (incomplete) on en0 ifscope [ethernet]
_ARP_LINE_RE = re.compile(
    r"^(?P<host>\S+)\s+\((?P<ip>\d+\.\d+\.\d+\.\d+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]+|\(incomplete\)|incomplete)"
)


@dataclass
class ArpEntry:
    ip: str
    mac: Optional[str]  # normalized "xx:xx:xx:xx:xx:xx", or None if incomplete
    hostname: Optional[str]  # None if arp couldn't resolve one (shown as "?")


def normalize_mac(mac: str) -> str:
    """Normalize a MAC address to lowercase, colon-separated, zero-padded octets.

    Accepts colon- or dash-separated input (`arp -a` on macOS uses
    colons but often omits leading zeros, e.g. "ac:de:48:0:11:22").
    """
    parts = mac.strip().replace("-", ":").split(":")
    return ":".join(part.zfill(2).lower() for part in parts)


def parse_arp_output(text: str) -> List[ArpEntry]:
    entries: List[ArpEntry] = []
    for line in text.splitlines():
        match = _ARP_LINE_RE.match(line.strip())
        if not match:
            continue

        host = match.group("host")
        ip = match.group("ip")
        mac_raw = match.group("mac").strip("()")

        mac = None if mac_raw == "incomplete" else normalize_mac(mac_raw)
        hostname = None if host == "?" else host

        entries.append(ArpEntry(ip=ip, mac=mac, hostname=hostname))
    return entries


def read_arp_table_with_availability() -> Tuple[List[ArpEntry], bool]:
    """Read this Mac's current ARP entries, and report whether `arp`
    itself actually ran (Phase 29 Stage 5 — see secure/arpwatch/
    scanner.py's own `arp_available` field, which this mirrors).

    Returns ([], False) when the command couldn't be run/timed out —
    never conflated with a genuine "ARP cache currently empty" result,
    which is ([], True).
    """
    # -n: numeric only, skip arp's own (slow/hang-prone when
    # non-interactive) hostname resolution. A generous timeout is
    # still a safety net, not the fix — see the module docstring.
    result = run(["arp", "-an"], timeout=10.0)
    if result.returncode is None:
        return [], False
    return parse_arp_output(result.stdout), True
