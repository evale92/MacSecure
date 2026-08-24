"""
wifi/interface.py — finds the network interface macOS uses for Wi-Fi
(e.g. "en0"), so the rest of this package knows which interface to ask
about. Uses one read-only, no-sudo command:

    `networksetup -listallhardwareports` — lists every network
    hardware port this Mac knows about and its device name. This looks
    for the block whose "Hardware Port:" line reads "Wi-Fi" (current
    macOS wording) or "AirPort" (older wording, kept for safety) and
    reads the "Device:" line that follows it.
"""

from __future__ import annotations

import re
from typing import Optional

from secure.wifi._shell import run

_PORT_BLOCK_RE = re.compile(
    r"Hardware Port:\s*(?:Wi-Fi|AirPort)\s*\n\s*Device:\s*(\S+)", re.IGNORECASE
)


def parse_wifi_interface(listallhardwareports_output: str) -> Optional[str]:
    match = _PORT_BLOCK_RE.search(listallhardwareports_output)
    return match.group(1) if match else None


def find_wifi_interface() -> Optional[str]:
    result = run(["networksetup", "-listallhardwareports"], timeout=5.0)
    if not result.ok:
        return None
    return parse_wifi_interface(result.stdout)
