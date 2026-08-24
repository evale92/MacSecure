"""
arpwatch/gateway.py — finds this Mac's current default gateway IP
address, so arpwatch can tell "the router's MAC just changed" (worth
real attention) apart from "some random device's MAC changed"
(usually not).

Same method and same command as secure/inventory/network_info.py uses
to find the default interface (`route -n get default`) — this module
is its own independent copy rather than an import from inventory,
consistent with every package here owning its own subprocess calls;
only the pure text-parsing shape is similar, not shared code, and the
regex is a handful of lines, not something worth the coupling to avoid
duplicating (contrast with secure/listening/ reusing
secure/connections/lsof_parser.py, which really would be risky to
duplicate).
"""

from __future__ import annotations

import re
from typing import Optional

from secure.arpwatch._shell import run

_GATEWAY_RE = re.compile(r"^\s*gateway:\s*(\S+)", re.MULTILINE)


def parse_default_gateway(route_output: str) -> Optional[str]:
    """Extract the "gateway: 192.168.1.1" line from `route -n get default` output."""
    match = _GATEWAY_RE.search(route_output)
    return match.group(1) if match else None


def get_default_gateway() -> Optional[str]:
    """Return this Mac's current default gateway IP, or None if it can't be determined."""
    result = run(["route", "-n", "get", "default"], timeout=5.0)
    if result.returncode is None:
        return None
    return parse_default_gateway(result.stdout)
