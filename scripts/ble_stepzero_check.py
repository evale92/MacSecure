#!/usr/bin/env python3
"""
ble_stepzero_check.py — standalone, one-time proof-of-concept for the
proposed Bleak/CoreBluetooth live-BLE-discovery expansion to Secure
Project MB's Bluetooth feature.

This is NOT part of the shipped Bluetooth feature and is not imported
by anything in secure/. It exists purely to answer one question before
any real implementation work happens: does live BLE discovery actually
work from the environment Secure Project MB runs in on THIS Mac?

It must be run manually, on the real Mac, in the same Python
environment (same interpreter / venv, launched the same way — Terminal,
PyCharm, etc.) that Secure Project MB actually uses. Results from a
different interpreter or a different parent app may not transfer,
since macOS's Bluetooth permission (TCC) is granted per requesting
process, not system-wide.

Setup (run once, in that same environment):
    pip install bleak pyobjc-framework-CoreBluetooth

Then:
    python3 scripts/ble_stepzero_check.py

The script prints exactly one final verdict line, one of:

    OPERATIONAL_SCAN_OK        Bluetooth on, authorized, scan completed,
                                one or more peripherals found.
    OPERATIONAL_ZERO_RESULTS   Bluetooth on, authorized, scan completed
                                without error, but zero peripherals were
                                found nearby. A genuine empty result —
                                not a permission or environment failure.
    POWERED_OFF                Bluetooth radio is off.
    PERMISSION_DENIED          CoreBluetooth reports this process is not
                                authorized to use Bluetooth.
    API_UNAVAILABLE_OR_ERROR   Could not even determine Bluetooth state —
                                missing dependencies, unsupported
                                hardware, or an unexpected error talking
                                to CoreBluetooth.

By design, a failure to obtain Bluetooth access is NEVER reported as
"zero nearby devices" — those are always distinct outcomes above.

The exit status carries the same distinction: 0 for the two
OPERATIONAL_* verdicts, 1 for every other one, so a caller that reads
only the exit status cannot mistake PERMISSION_DENIED for a working scan.
"""

from __future__ import annotations

import sys
import time

print(f"python executable : {sys.executable}")
print(f"python version    : {sys.version.split()[0]}")
print(f"platform          : {sys.platform}")
print("-" * 60)

# The only verdicts that mean live BLE discovery works here.
_OPERATIONAL_VERDICTS = frozenset({"OPERATIONAL_SCAN_OK", "OPERATIONAL_ZERO_RESULTS"})


def verdict(label: str, detail: str) -> None:
    print()
    print(detail)
    print()
    print(f"=== VERDICT: {label} ===")
    sys.exit(0 if label in _OPERATIONAL_VERDICTS else 1)


# --- Step 1: confirm both dependencies are importable at all -------------

try:
    import CoreBluetooth
    from Foundation import NSDate, NSObject, NSRunLoop
except ImportError as e:
    verdict(
        "API_UNAVAILABLE_OR_ERROR",
        f"Could not import PyObjC's CoreBluetooth bindings: {e}\n"
        "Install with: pip install pyobjc-framework-CoreBluetooth",
    )

try:
    import bleak
    from bleak import BleakScanner
except ImportError as e:
    verdict(
        "API_UNAVAILABLE_OR_ERROR",
        f"Could not import bleak: {e}\nInstall with: pip install bleak",
    )

import asyncio

# --- Step 2: read CBCentralManager.state directly -------------------------
# This is the clean, synchronous-ish signal that distinguishes powered-off
# vs. unauthorized vs. unsupported vs. genuinely ready — the exact thing
# Bleak does not reliably surface as a standalone pre-flight check.

_STATE_NAMES = {
    0: "unknown",
    1: "resetting",
    2: "unsupported",
    3: "unauthorized",
    4: "poweredOff",
    5: "poweredOn",
}


class _StateDelegate(NSObject):
    state_result = None

    def centralManagerDidUpdateState_(self, central):
        self.state_result = central.state()


def check_central_state(timeout_s: float = 5.0):
    delegate = _StateDelegate.alloc().init()
    manager = CoreBluetooth.CBCentralManager.alloc().initWithDelegate_queue_(delegate, None)
    deadline = time.time() + timeout_s
    while delegate.state_result is None and time.time() < deadline:
        NSRunLoop.currentRunLoop().runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.1))
    return manager, delegate.state_result


print("Checking CBCentralManager.state (the same permission check the")
print("real Bluetooth feature would need) ...")

try:
    _manager, state = check_central_state()
except Exception as e:
    verdict(
        "API_UNAVAILABLE_OR_ERROR",
        f"CBCentralManager could not be initialized: {type(e).__name__}: {e}",
    )

if state is None:
    verdict(
        "API_UNAVAILABLE_OR_ERROR",
        "CBCentralManager never reported a state within 5 seconds. This "
        "usually means CoreBluetooth couldn't fully initialize in this "
        "process at all (e.g. no TCC entry exists yet for it, or this "
        "process type can't host CoreBluetooth). Try running it once more "
        "— the first run is sometimes when macOS shows the permission "
        "prompt, if it shows one at all for an unbundled script.",
    )

state_name = _STATE_NAMES.get(int(state), f"unknown-code-{state}")
print(f"CBCentralManager.state = {int(state)} ({state_name})")

if state_name == "unauthorized":
    verdict(
        "PERMISSION_DENIED",
        "CoreBluetooth reports this process is NOT authorized to use "
        "Bluetooth. Grant access via System Settings -> Privacy & "
        "Security -> Bluetooth for whichever app actually launched this "
        "script (Terminal, iTerm, PyCharm, etc.), then re-run.",
    )

if state_name == "poweredOff":
    verdict("POWERED_OFF", "Bluetooth radio is off. Turn it on and re-run.")

if state_name == "unsupported":
    verdict(
        "API_UNAVAILABLE_OR_ERROR",
        "This Mac reports Bluetooth LE as unsupported.",
    )

if state_name != "poweredOn":
    verdict(
        "API_UNAVAILABLE_OR_ERROR",
        f"Unexpected CBCentralManager state: {state_name}. Not safe to "
        "proceed with a scan.",
    )

# --- Step 3: state is poweredOn + authorized — attempt a real scan -------

print("Bluetooth is on and authorized for this process.")
print("Attempting an 8-second live BLE scan via Bleak ...")


async def do_scan():
    return await BleakScanner.discover(timeout=8.0)


try:
    devices = asyncio.run(do_scan())
except Exception as e:
    verdict(
        "API_UNAVAILABLE_OR_ERROR",
        "CBCentralManager reported poweredOn + authorized, but the Bleak "
        f"scan itself raised an error: {type(e).__name__}: {e}",
    )

print(f"\nScan completed without error. {len(devices)} peripheral(s) found.")
for d in devices:
    print(f"  - {d.address}  name={d.name!r}  rssi={getattr(d, 'rssi', 'n/a')}")

if devices:
    verdict(
        "OPERATIONAL_SCAN_OK",
        f"Live BLE discovery works from this environment. {len(devices)} "
        "peripheral(s) seen.",
    )
else:
    verdict(
        "OPERATIONAL_ZERO_RESULTS",
        "Live BLE discovery ran successfully — Bluetooth on, authorized, "
        "scan completed without error — but zero nearby peripherals were "
        "found. This is a genuine empty result, not a permission or "
        "environment failure.",
    )
