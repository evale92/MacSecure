"""
Tests for secure/bluetooth/ble/* (live BLE peripheral discovery).

Pure logic (analysis.py) is tested directly, no mocking needed.
state.py and scanner.py each have a deliberate "thin seam" function
(_read_central_state / _discover) that wraps the actual PyObjC/Bleak
calls — tests patch those seams instead of touching PyObjC or Bleak
directly, same pattern every other package's _shell.py mocking uses
(see test_bluetooth.py's _patch_shell). This means these tests run
without either dependency installed.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from secure.bluetooth.ble.analysis import (
    PERSISTENT_THRESHOLD,
    RSSI_CHANGE_THRESHOLD,
    is_persistent_and_unknown,
    rssi_significant_change,
)
from secure.bluetooth.ble.state import (
    STATE_ERROR,
    STATE_POWERED_OFF,
    STATE_POWERED_ON,
    STATE_UNAUTHORIZED,
    STATE_UNSUPPORTED,
    BluetoothStateResult,
    check_bluetooth_state,
)
from secure.storage.database import Database
from secure.storage.models import list_ble_alerts, list_ble_peripherals, set_ble_peripheral_trusted

# ---------- analysis.py (pure functions) ----------


def test_rssi_significant_change_true_when_swing_meets_threshold():
    assert rssi_significant_change(-50, -50 - RSSI_CHANGE_THRESHOLD) is True


def test_rssi_significant_change_false_when_swing_below_threshold():
    assert rssi_significant_change(-50, -50 - (RSSI_CHANGE_THRESHOLD - 1)) is False


def test_rssi_significant_change_false_when_either_reading_missing():
    assert rssi_significant_change(None, -60) is False
    assert rssi_significant_change(-60, None) is False
    assert rssi_significant_change(None, None) is False


def test_rssi_significant_change_respects_custom_threshold():
    assert rssi_significant_change(-50, -55, threshold=5) is True
    assert rssi_significant_change(-50, -54, threshold=5) is False


def test_is_persistent_and_unknown_true_at_threshold_when_untrusted():
    assert is_persistent_and_unknown(PERSISTENT_THRESHOLD, trusted=False) is True


def test_is_persistent_and_unknown_false_below_threshold():
    assert is_persistent_and_unknown(PERSISTENT_THRESHOLD - 1, trusted=False) is False


def test_is_persistent_and_unknown_false_when_trusted():
    assert is_persistent_and_unknown(PERSISTENT_THRESHOLD + 5, trusted=True) is False


# ---------- state.py (CBCentralManager.state read, seam mocked) ----------


def _patch_state(monkeypatch, return_value=None, raises=None):
    import secure.bluetooth.ble.state as state_module

    def fake(*args, **kwargs):
        if raises is not None:
            raise raises
        return return_value

    monkeypatch.setattr(state_module, "_read_central_state", fake)


def test_check_bluetooth_state_powered_on(monkeypatch):
    _patch_state(monkeypatch, return_value=5)  # CBManagerStatePoweredOn
    result = check_bluetooth_state()
    assert result.state_name == STATE_POWERED_ON
    assert result.available is True


def test_check_bluetooth_state_powered_off(monkeypatch):
    _patch_state(monkeypatch, return_value=4)  # CBManagerStatePoweredOff
    result = check_bluetooth_state()
    assert result.state_name == STATE_POWERED_OFF
    assert result.available is False


def test_check_bluetooth_state_unauthorized(monkeypatch):
    _patch_state(monkeypatch, return_value=3)  # CBManagerStateUnauthorized
    result = check_bluetooth_state()
    assert result.state_name == STATE_UNAUTHORIZED
    assert result.available is False
    assert "System Settings" in result.detail


def test_check_bluetooth_state_unsupported(monkeypatch):
    _patch_state(monkeypatch, return_value=2)  # CBManagerStateUnsupported
    result = check_bluetooth_state()
    assert result.state_name == STATE_UNSUPPORTED
    assert result.available is False


def test_check_bluetooth_state_timeout_is_error_not_powered_off(monkeypatch):
    # None means _read_central_state never got a callback within its
    # timeout — this must NOT be conflated with a confirmed
    # poweredOff/unauthorized reading. Distinct "we don't know" outcome.
    _patch_state(monkeypatch, return_value=None)
    result = check_bluetooth_state()
    assert result.state_name == STATE_ERROR
    assert result.available is False


def test_check_bluetooth_state_missing_dependency_is_error(monkeypatch):
    _patch_state(monkeypatch, raises=ImportError("no module named CoreBluetooth"))
    result = check_bluetooth_state()
    assert result.state_name == STATE_ERROR
    assert "pip install" in result.detail


def test_check_bluetooth_state_unexpected_exception_is_error_not_a_crash(monkeypatch):
    _patch_state(monkeypatch, raises=RuntimeError("something odd"))
    result = check_bluetooth_state()
    assert result.state_name == STATE_ERROR


def test_bluetooth_state_result_available_property_only_true_for_powered_on():
    assert BluetoothStateResult(state_name=STATE_POWERED_ON, detail="").available is True
    for name in (STATE_POWERED_OFF, STATE_UNAUTHORIZED, STATE_UNSUPPORTED, STATE_ERROR):
        assert BluetoothStateResult(state_name=name, detail="").available is False


# ---------- scanner.py (live scan, both seams mocked) ----------


def _fake_adv(local_name=None, rssi=None, manufacturer_data=None, service_uuids=None):
    return SimpleNamespace(
        local_name=local_name,
        rssi=rssi,
        manufacturer_data=manufacturer_data or {},
        service_uuids=service_uuids or [],
    )


def _fake_device(name=None):
    return SimpleNamespace(name=name)


def _patch_state_available(monkeypatch, available=True, state_name=None):
    import secure.bluetooth.ble.scanner as scanner_module

    name = state_name or (STATE_POWERED_ON if available else STATE_POWERED_OFF)
    monkeypatch.setattr(
        scanner_module,
        "check_bluetooth_state",
        lambda *a, **k: BluetoothStateResult(state_name=name, detail="mocked"),
    )


def _patch_discover(monkeypatch, devices):
    """devices: dict of {address: (device, adv)}"""
    import secure.bluetooth.ble.scanner as scanner_module

    monkeypatch.setattr(scanner_module, "_discover", lambda duration: devices)


def test_scan_ble_peripherals_unavailable_when_powered_off(tmp_path: Path, monkeypatch):
    _patch_state_available(monkeypatch, available=False, state_name=STATE_POWERED_OFF)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        from secure.bluetooth.ble.scanner import scan_ble_peripherals

        result = scan_ble_peripherals(db.conn)

    assert result.ble_available is False
    assert result.unavailable_reason == STATE_POWERED_OFF
    assert result.entries == []


def test_scan_ble_peripherals_unavailable_never_reported_as_zero_devices(tmp_path: Path, monkeypatch):
    # Same distinction the Wi-Fi status_unknown fix enforces: an
    # unavailable scan must be clearly different from "ran fine, found
    # nothing" — never silently collapsed into the same shape.
    _patch_state_available(monkeypatch, available=False, state_name=STATE_UNAUTHORIZED)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        from secure.bluetooth.ble.scanner import scan_ble_peripherals

        unavailable = scan_ble_peripherals(db.conn)

        _patch_state_available(monkeypatch, available=True)
        _patch_discover(monkeypatch, {})
        genuinely_empty = scan_ble_peripherals(db.conn)

    assert unavailable.ble_available is False
    assert genuinely_empty.ble_available is True
    assert genuinely_empty.entries == []


def test_scan_ble_peripherals_first_scan_all_new(tmp_path: Path, monkeypatch):
    _patch_state_available(monkeypatch, available=True)
    _patch_discover(
        monkeypatch,
        {
            "11111111-1111-1111-1111-111111111111": (
                _fake_device(name="Some Device"),
                _fake_adv(local_name="Some Device", rssi=-60, service_uuids=["180d"]),
            ),
            "22222222-2222-2222-2222-222222222222": (
                _fake_device(),
                _fake_adv(rssi=-70, manufacturer_data={76: b"\x01\x02"}),
            ),
        },
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        from secure.bluetooth.ble.scanner import scan_ble_peripherals

        result = scan_ble_peripherals(db.conn)
        peripherals = list_ble_peripherals(db.conn)

    assert result.ble_available is True
    assert len(result.entries) == 2
    assert len(result.new_peripherals) == 2
    assert len(peripherals) == 2
    assert all(p.trusted is False for p in peripherals)
    assert all(p.times_seen == 1 for p in peripherals)


def test_scan_ble_peripherals_second_scan_same_uuid_not_new(tmp_path: Path, monkeypatch):
    _patch_state_available(monkeypatch, available=True)
    devices = {
        "11111111-1111-1111-1111-111111111111": (
            _fake_device(name="Some Device"),
            _fake_adv(local_name="Some Device", rssi=-60),
        )
    }
    _patch_discover(monkeypatch, devices)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        from secure.bluetooth.ble.scanner import scan_ble_peripherals

        first = scan_ble_peripherals(db.conn)
        second = scan_ble_peripherals(db.conn)
        peripherals = list_ble_peripherals(db.conn)

    assert len(first.new_peripherals) == 1
    assert len(second.new_peripherals) == 0
    assert peripherals[0].times_seen == 2


def test_scan_ble_peripherals_rssi_significant_change_alert(tmp_path: Path, monkeypatch):
    _patch_state_available(monkeypatch, available=True)
    uuid_ = "11111111-1111-1111-1111-111111111111"

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        from secure.bluetooth.ble.scanner import scan_ble_peripherals

        _patch_discover(monkeypatch, {uuid_: (_fake_device(), _fake_adv(rssi=-50))})
        scan_ble_peripherals(db.conn)

        _patch_discover(
            monkeypatch, {uuid_: (_fake_device(), _fake_adv(rssi=-50 - RSSI_CHANGE_THRESHOLD))}
        )
        second = scan_ble_peripherals(db.conn)

    assert len(second.alerts) == 1
    assert second.alerts[0].kind == "rssi_significant_change"
    assert second.alerts[0].severity == "low"


def test_scan_ble_peripherals_no_rssi_alert_for_small_swing(tmp_path: Path, monkeypatch):
    _patch_state_available(monkeypatch, available=True)
    uuid_ = "11111111-1111-1111-1111-111111111111"

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        from secure.bluetooth.ble.scanner import scan_ble_peripherals

        _patch_discover(monkeypatch, {uuid_: (_fake_device(), _fake_adv(rssi=-50))})
        scan_ble_peripherals(db.conn)

        _patch_discover(monkeypatch, {uuid_: (_fake_device(), _fake_adv(rssi=-55))})
        second = scan_ble_peripherals(db.conn)

    assert second.alerts == []


def test_scan_ble_peripherals_persistent_unknown_after_threshold(tmp_path: Path, monkeypatch):
    _patch_state_available(monkeypatch, available=True)
    uuid_ = "11111111-1111-1111-1111-111111111111"
    _patch_discover(monkeypatch, {uuid_: (_fake_device(), _fake_adv(rssi=-50))})

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        from secure.bluetooth.ble.scanner import scan_ble_peripherals

        results = [scan_ble_peripherals(db.conn) for _ in range(PERSISTENT_THRESHOLD)]
        alerts = list_ble_alerts(db.conn)

    assert all(a.kind == "persistent_unknown" for a in alerts)
    assert all(a.severity == "low" for a in alerts)
    assert len(results[-1].alerts) == 1  # only fires once threshold is reached
    assert len(alerts) == 1


def test_scan_ble_peripherals_trusted_peripheral_never_alerted(tmp_path: Path, monkeypatch):
    _patch_state_available(monkeypatch, available=True)
    uuid_ = "11111111-1111-1111-1111-111111111111"
    _patch_discover(monkeypatch, {uuid_: (_fake_device(), _fake_adv(rssi=-50))})

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        from secure.bluetooth.ble.scanner import scan_ble_peripherals

        scan_ble_peripherals(db.conn)
        for p in list_ble_peripherals(db.conn):
            set_ble_peripheral_trusted(db.conn, p.id, True)

        for _ in range(PERSISTENT_THRESHOLD + 2):
            scan_ble_peripherals(db.conn)
        alerts = list_ble_alerts(db.conn)

    assert alerts == []


def test_scan_ble_peripherals_error_during_discover_is_unavailable_not_empty(tmp_path: Path, monkeypatch):
    _patch_state_available(monkeypatch, available=True)
    import secure.bluetooth.ble.scanner as scanner_module

    def boom(duration):
        raise RuntimeError("bleak blew up")

    monkeypatch.setattr(scanner_module, "_discover", boom)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        from secure.bluetooth.ble.scanner import scan_ble_peripherals

        result = scan_ble_peripherals(db.conn)

    assert result.ble_available is False
    assert result.unavailable_reason == "error"
    assert result.entries == []
