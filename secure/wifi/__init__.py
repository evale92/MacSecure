"""
secure/wifi/ — Phase 8: Wi-Fi Security Monitor.

Reads this Mac's current Wi-Fi connection (SSID, BSSID, channel, PHY
mode, security type, signal/noise) using only Apple-supported,
read-only, no-sudo tools (`networksetup`, `system_profiler`, and
optionally the deprecated `airport` command-line helper when it's
still present and permitted — see status.py). Tracks every network
this Mac has ever connected to, flags a first-time network or a new
access point (BSSID) under an already-known network name, warns about
weak or open security, and flags SSIDs that suspiciously resemble one
you already trust.

This package never joins, disconnects from, or otherwise changes any
Wi-Fi connection, and never performs any kind of Wi-Fi attack,
deauthentication, cracking, or packet injection — visibility only,
per the explicit instruction in the Claude prompt this phase was
built from. It also respects macOS's own privacy restrictions: when
this process hasn't been granted Location Services access, the BSSID
simply isn't available, and this package reports that honestly
(bssid_available=False) rather than pretending or working around it.
"""

from __future__ import annotations

from secure.wifi.scanner import WifiScanResult, scan_wifi
from secure.wifi.status import WifiStatus

__all__ = ["scan_wifi", "WifiScanResult", "WifiStatus"]
