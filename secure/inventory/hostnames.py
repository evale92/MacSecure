"""
inventory/hostnames.py — best-effort reverse-DNS hostname lookup for a
discovered IP address.

Uses Python's built-in `socket` module only (no subprocess) — a
standard reverse-DNS/mDNS query, the same kind of lookup this Mac
already performs constantly. It doesn't otherwise contact the target
device. Many devices (phones, IoT gadgets) won't have a reverse-DNS
entry at all, which is normal — this returns None rather than an
error in that case.
"""

from __future__ import annotations

import socket
from typing import Optional


def resolve_hostname(ip: str, timeout: float = 1.0) -> Optional[str]:
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _aliases, _addresses = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)
