"""
bluetooth/ble — live BLE peripheral discovery, layered on top of the
system_profiler-based bluetooth/ package rather than replacing it.

This subpackage exists because system_profiler (see
secure/bluetooth/parser.py's scope note) only reports devices macOS
already has a relationship with — paired, configured, or connected. It
cannot see a peripheral simply advertising nearby that this Mac has
never paired with. This subpackage adds that: real, live "who's
broadcasting nearby right now" visibility via Bleak (which on macOS is
itself a PyObjC/CoreBluetooth wrapper) plus one small piece of direct
PyObjC/CoreBluetooth access (state.py) for a clean powered-on/off and
permission read.

**Read this before relying on it for more than it can actually do:**

    - CoreBluetooth identifies each peripheral with a per-app UUID
      (`cb_uuid` throughout this subpackage), NOT its real Bluetooth
      MAC address — Apple does this deliberately, for privacy. This is
      a genuinely different identifier space than
      secure/bluetooth/parser.py's system_profiler-derived addresses,
      and the two generally cannot be reliably correlated. See
      database.py's schema comment and PROJECT_NOTES.md for the full
      explanation.
    - Many modern phones (iOS and Android) additionally rotate their
      real BLE link-layer address every ~15 minutes for privacy,
      independent of anything CoreBluetooth or this app does. This
      means "first seen / last seen / persistent nearby" tracking here
      is a floor, not an exact count of distinct physical devices —
      no framework choice fixes this, it's how privacy-respecting
      devices are designed to behave.
    - Nearby presence alone is never treated as evidence of an attack.
      Only genuinely new state (a brand-new peripheral, a persistent
      pattern, or a significant RSSI swing) is ever surfaced, and
      always with informational/low severity — see
      secure/bluetooth/ble/scanner.py's module docstring for the full
      severity rationale.
    - This module never attempts pairing, connecting, interception,
      exploitation, jamming, spoofing, deauthentication, or any other
      kind of unauthorized access. It only listens to advertisements
      any nearby BLE peripheral already broadcasts publicly.
    - This cannot "fully protect" against Bluetooth attacks. It adds
      visibility, not prevention — no software can guarantee protection
      from vulnerabilities inside Apple's own Bluetooth stack.

Requires the `bleak` and `pyobjc-framework-CoreBluetooth` packages —
the first non-standard-library runtime dependencies in this project,
added deliberately for this feature. See requirements.txt and
PROJECT_NOTES.md for why.
"""

from secure.bluetooth.ble.scanner import BleScanResult, scan_ble_peripherals
from secure.bluetooth.ble.state import BluetoothStateResult, check_bluetooth_state

__all__ = [
    "scan_ble_peripherals",
    "BleScanResult",
    "check_bluetooth_state",
    "BluetoothStateResult",
]
