"""
inventory/network_info.py — figures out this Mac's own local subnet,
so the ping sweep (see ping_sweep.py) knows which addresses are "this
network" and stays within it.

Uses two read-only, no-sudo macOS commands:
    `route -n get default`  -> which network interface has the default route
    `ifconfig <interface>`  -> that interface's IPv4 address + netmask
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from secure.inventory._shell import run

_INET_NETMASK_RE = re.compile(r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+)")


@dataclass
class LocalSubnet:
    interface: str
    local_ip: str
    prefix_len: int

    def hosts(self, max_hosts: int = 256) -> List[str]:
        """Every other host address in this subnet, capped at `max_hosts`.

        Excludes this Mac's own address, the network address, and the
        broadcast address (ipaddress.hosts() already excludes the
        latter two for IPv4 networks).
        """
        network = ipaddress.ip_network(f"{self.local_ip}/{self.prefix_len}", strict=False)
        result = [str(ip) for ip in network.hosts() if str(ip) != self.local_ip]
        return result[:max_hosts]


def _parse_default_interface(route_output: str) -> Optional[str]:
    for line in route_output.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split(":", 1)[1].strip()
    return None


def _parse_ifconfig_inet(ifconfig_output: str) -> Optional[Tuple[str, int]]:
    match = _INET_NETMASK_RE.search(ifconfig_output)
    if not match:
        return None
    ip = match.group(1)
    prefix_len = bin(int(match.group(2), 16)).count("1")
    return ip, prefix_len


def get_local_subnet() -> Optional[LocalSubnet]:
    """Best-effort detection of this Mac's local subnet. None if it can't be determined.

    Subnets larger than /24 are clamped to /24 so a sweep never
    balloons into thousands of hosts; a smaller (more specific) prefix
    than /24 is used as-is.
    """
    route_result = run(["route", "-n", "get", "default"])
    if not route_result.ok:
        return None
    interface = _parse_default_interface(route_result.stdout)
    if not interface:
        return None

    ifconfig_result = run(["ifconfig", interface])
    if not ifconfig_result.ok:
        return None
    parsed = _parse_ifconfig_inet(ifconfig_result.stdout)
    if not parsed:
        return None

    ip, prefix_len = parsed
    if prefix_len < 24:
        prefix_len = 24
    return LocalSubnet(interface=interface, local_ip=ip, prefix_len=prefix_len)
