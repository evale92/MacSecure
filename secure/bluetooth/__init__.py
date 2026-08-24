"""
secure/bluetooth/ — Phase 9: Bluetooth/BLE Visibility.

Reads whatever `system_profiler SPBluetoothDataType` reports (name,
address, paired/connected status, and signal strength when available)
with no sudo and no extra dependencies, tracks every Bluetooth device
this Mac has ever seen, flags a first-time device, and — conservatively
— flags a device that keeps showing up across multiple scans without
ever being marked trusted.

**Scope limitation, stated plainly**: this is visibility into devices
macOS itself already has some relationship with (paired, configured,
or currently connected — the same list in System Settings ->
Bluetooth), NOT a live radio scan of every nearby advertising BLE
device. A true "what's broadcasting near me right now, paired or not"
scanner needs CoreBluetooth framework access from a signed app with
Bluetooth permission — not achievable from a script invoking
command-line tools, and out of scope for this project's stdlib-only,
no-extra-dependencies design. See parser.py's docstring and
PROJECT_NOTES.md for the full explanation.

This package never attempts pairing, interception, exploitation, or
any other kind of unauthorized access, and never claims that a
device's mere proximity is evidence of anything malicious — per the
explicit instructions in the Claude prompt this phase was built from.
"""

from __future__ import annotations

from secure.bluetooth.scanner import BluetoothScanResult, scan_bluetooth

__all__ = ["scan_bluetooth", "BluetoothScanResult"]
