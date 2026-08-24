"""
bluetooth/ble/analysis.py — pure functions for interpreting BLE scan
data. No subprocess calls, no async, no database access, no Bleak/
PyObjC imports — see scanner.py for the parts that actually talk to
Bleak, and state.py for the parts that talk to PyObjC/CoreBluetooth
directly. Kept pure and dependency-free on purpose, same "pure
function + thin wrapper" split every other package in this app
follows, so this logic is testable without a Mac, Bluetooth hardware,
or either of the new dependencies installed.
"""

from __future__ import annotations

from typing import Optional

# How many dBm an RSSI reading has to move, scan-to-scan, before it's
# treated as a genuine change worth mentioning rather than ordinary
# noise. RSSI is a very rough, noisy distance proxy — normal
# environmental fluctuation (multipath fading, someone walking between
# the devices, minor movement) routinely produces swings of several
# dBm between two readings of a completely stationary device. 20 dBm
# is deliberately conservative so this doesn't fire on ordinary noise;
# it's meant to catch "this moved substantially," not "this wobbled."
RSSI_CHANGE_THRESHOLD = 20

# Same conservative reasoning as secure/bluetooth/scanner.py's
# _PERSISTENT_THRESHOLD: a device has to show up in several separate
# scans, while still untrusted, before "persistently nearby" is worth
# mentioning — a single sighting is not a pattern.
PERSISTENT_THRESHOLD = 3


def rssi_significant_change(
    previous_rssi: Optional[int],
    current_rssi: Optional[int],
    threshold: int = RSSI_CHANGE_THRESHOLD,
) -> bool:
    """True if current_rssi differs from previous_rssi by at least
    `threshold` dBm. False whenever either reading is missing — a
    missing reading is not evidence of a change, just missing data.
    """
    if previous_rssi is None or current_rssi is None:
        return False
    return abs(current_rssi - previous_rssi) >= threshold


def is_persistent_and_unknown(times_seen: int, trusted: bool, threshold: int = PERSISTENT_THRESHOLD) -> bool:
    """True if an untrusted peripheral has been seen often enough
    (>= threshold separate scans) to be worth a low-severity mention.
    Mirrors secure/bluetooth/scanner.py's inline persistent-unknown
    check, pulled out here as a pure function since this subpackage
    already separates its logic from its Bleak/PyObjC I/O.
    """
    return (not trusted) and times_seen >= threshold
