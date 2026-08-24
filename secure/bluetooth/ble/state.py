"""
bluetooth/ble/state.py — reads CBCentralManager.state directly via
PyObjC's CoreBluetooth bindings, rather than through Bleak.

Why this exists as its own small module instead of just using Bleak
for everything: Bleak's macOS backend already IS PyObjC + CoreBluetooth
under the hood, so it doesn't give us anything Bleak can't in principle
reach — but Bleak doesn't reliably surface a clean, synchronous
"what's Bluetooth's state right now, before I even try to scan"
pre-flight check across versions. CBCentralManager.state gives exactly
that: poweredOn / poweredOff / unauthorized / unsupported / unknown /
resetting, straight from CoreBluetooth. This is the one deliberate
justification for touching PyObjC directly rather than relying on
Bleak for everything (see the Phase 9 BLE architecture plan in
PROJECT_NOTES.md).

This module deliberately never treats "couldn't determine state" as
"powered off" or "no devices nearby" — those are different, explicit
outcomes (see BluetoothStateResult below), same tri-state-honesty
discipline as secure/wifi/status.py's status_unknown field after the
Wi-Fi false-negative bugfix.

The PyObjC import happens lazily, inside _read_central_state(), not at
module load time — so this module (and anything that imports it) can
still be imported and unit-tested on a machine/sandbox without PyObjC
installed; only actually calling check_bluetooth_state() requires it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

STATE_POWERED_ON = "poweredOn"
STATE_POWERED_OFF = "poweredOff"
STATE_UNAUTHORIZED = "unauthorized"
STATE_UNSUPPORTED = "unsupported"
STATE_UNKNOWN = "unknown"
STATE_RESETTING = "resetting"
STATE_ERROR = "error"  # could not determine state at all (missing deps, timeout, unexpected error)

_CB_STATE_NAMES = {
    0: STATE_UNKNOWN,
    1: STATE_RESETTING,
    2: STATE_UNSUPPORTED,
    3: STATE_UNAUTHORIZED,
    4: STATE_POWERED_OFF,
    5: STATE_POWERED_ON,
}


@dataclass
class BluetoothStateResult:
    state_name: str  # one of the STATE_* constants above
    detail: str

    @property
    def available(self) -> bool:
        """True only when Bluetooth is confirmed on and authorized.

        Every other state — including STATE_ERROR — means "cannot
        safely proceed with a scan," and must never be treated as
        though a scan ran and simply found nothing.
        """
        return self.state_name == STATE_POWERED_ON


def _read_central_state(timeout_s: float = 5.0) -> Optional[int]:
    """Thin seam around PyObjC's CBCentralManager — the ONE place
    tests patch instead of touching PyObjC/CoreBluetooth directly, same
    "pure function + thin wrapper" pattern every other package's
    _shell.py follows for subprocess calls. Returns the raw
    CBManagerState integer, or None if no state was reported within
    timeout_s.

    Requires an active run loop to receive CoreBluetooth's delegate
    callback — CBCentralManager's state update arrives asynchronously,
    so this pumps NSRunLoop briefly in a loop rather than blocking on
    it once, since there's no bare "wait for callback" primitive for a
    script with no NSApplication event loop of its own.
    """
    import CoreBluetooth  # noqa: PLC0415 - deliberately lazy, see module docstring
    from Foundation import NSDate, NSObject, NSRunLoop

    class _StateDelegate(NSObject):
        state_result = None

        def centralManagerDidUpdateState_(self, central):
            self.state_result = central.state()

    delegate = _StateDelegate.alloc().init()
    # Keep a reference to the manager for the lifetime of this call —
    # CBCentralManager delivers callbacks only while it's alive.
    _manager = CoreBluetooth.CBCentralManager.alloc().initWithDelegate_queue_(delegate, None)

    deadline = time.time() + timeout_s
    while delegate.state_result is None and time.time() < deadline:
        NSRunLoop.currentRunLoop().runUntilDate_(NSDate.dateWithTimeIntervalSinceNow_(0.1))

    return delegate.state_result


def check_bluetooth_state(timeout_s: float = 5.0) -> BluetoothStateResult:
    """Return Bluetooth's current power/authorization state for this
    process. Never raises — any failure (missing PyObjC dependencies,
    a timeout, an unexpected CoreBluetooth error) comes back as
    STATE_ERROR with an explanatory detail message, distinct from every
    other state.
    """
    try:
        raw_state = _read_central_state(timeout_s=timeout_s)
    except ImportError as e:
        return BluetoothStateResult(
            state_name=STATE_ERROR,
            detail=(
                f"Could not import PyObjC's CoreBluetooth bindings: {e}. "
                "Install with: pip install pyobjc-framework-CoreBluetooth"
            ),
        )
    except Exception as e:
        return BluetoothStateResult(
            state_name=STATE_ERROR,
            detail=f"Could not read Bluetooth state: {type(e).__name__}: {e}",
        )

    if raw_state is None:
        return BluetoothStateResult(
            state_name=STATE_ERROR,
            detail=(
                f"CBCentralManager never reported a state within {timeout_s}s. "
                "CoreBluetooth may not have been able to initialize in this process."
            ),
        )

    state_name = _CB_STATE_NAMES.get(int(raw_state), STATE_UNKNOWN)

    details = {
        STATE_POWERED_ON: "Bluetooth is on and authorized for this process.",
        STATE_POWERED_OFF: "Bluetooth radio is off.",
        STATE_UNAUTHORIZED: (
            "This process is not authorized to use Bluetooth. Grant access via "
            "System Settings -> Privacy & Security -> Bluetooth for whichever app "
            "actually launched it (Terminal, iTerm, PyCharm, etc.)."
        ),
        STATE_UNSUPPORTED: "This Mac reports Bluetooth LE as unsupported.",
        STATE_RESETTING: "Bluetooth is temporarily resetting.",
        STATE_UNKNOWN: "Bluetooth state is not yet known.",
    }
    return BluetoothStateResult(state_name=state_name, detail=details.get(state_name, "Unknown state."))
