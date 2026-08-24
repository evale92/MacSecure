"""
Tests for secure/bluetooth/* (Bluetooth/BLE Visibility).

Sample system_profiler output feeds straight into the pure parsing
functions, so these don't need a real Mac. scan_bluetooth() itself is
tested end-to-end with the shell call mocked out, same approach as
test_arpwatch.py/test_listening.py/test_wifi.py.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.bluetooth._shell import ShellResult
from secure.bluetooth.parser import (
    normalize_bluetooth_address,
    parse_rssi,
    parse_system_profiler_bluetooth,
)
from secure.bluetooth.scanner import scan_bluetooth
from secure.storage.database import Database
from secure.storage.models import (
    list_bluetooth_alerts,
    list_bluetooth_devices,
    set_bluetooth_device_trusted,
)

# ---------- parse_system_profiler_bluetooth ----------

_SAMPLE_BLUETOOTH_OUTPUT = """\
Bluetooth:

      Apple Bluetooth Software Version: 8.0.0f2

      Hardware Settings:
          Address: AA-BB-CC-DD-EE-FF
          State: On
          Discoverable: Off

      Devices (Paired, Configured, etc.):
          Erick's AirPods Pro:
              Address: 11-22-33-44-55-66
              Firmware Version: 6A326
              Is Configured: Yes
              Paired: Yes
              Connected: No
              Not Connected Reason: Link Key Missing
          Magic Keyboard:
              Address: 22-33-44-55-66-77
              Firmware Version: 42.1
              Is Configured: Yes
              Paired: Yes
              Connected: Yes
              Services: Keyboard

      Connected:
          Magic Keyboard:
              Address: 22-33-44-55-66-77
              Firmware Version: 42.1
              Minor Type: Keyboard
              RSSI: -50
              Services: Keyboard
"""


def test_parse_system_profiler_bluetooth_extracts_devices():
    devices = parse_system_profiler_bluetooth(_SAMPLE_BLUETOOTH_OUTPUT)
    by_address = {d["address"]: d for d in devices}

    assert len(devices) == 2

    airpods = by_address["11-22-33-44-55-66"]
    assert airpods["name"] == "Erick's AirPods Pro"
    assert airpods["paired"] is True
    assert airpods["connected"] is False
    assert airpods["rssi_raw"] is None

    keyboard = by_address["22-33-44-55-66-77"]
    assert keyboard["name"] == "Magic Keyboard"
    assert keyboard["paired"] is True
    assert keyboard["connected"] is True
    assert keyboard["rssi_raw"] == "-50"  # merged in from the "Connected:" section


def test_parse_system_profiler_bluetooth_no_devices_section_is_empty():
    assert parse_system_profiler_bluetooth("Bluetooth:\n\n      Hardware Settings:\n          State: On\n") == []


def test_parse_system_profiler_bluetooth_empty_output_is_empty():
    assert parse_system_profiler_bluetooth("") == []


def test_parse_system_profiler_bluetooth_connected_only_device_still_included():
    # Unusual but handled: a device present in "Connected:" without
    # also appearing in "Devices (Paired, Configured, etc.):".
    output = (
        "Bluetooth:\n\n"
        "      Connected:\n"
        "          Some Speaker:\n"
        "              Address: 33-44-55-66-77-88\n"
        "              RSSI: -60\n"
    )
    devices = parse_system_profiler_bluetooth(output)
    assert len(devices) == 1
    assert devices[0]["address"] == "33-44-55-66-77-88"
    assert devices[0]["connected"] is True
    assert devices[0]["rssi_raw"] == "-60"


# ---------- normalize_bluetooth_address / parse_rssi ----------


def test_normalize_bluetooth_address():
    assert normalize_bluetooth_address("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


def test_normalize_bluetooth_address_none_is_none():
    assert normalize_bluetooth_address(None) is None
    assert normalize_bluetooth_address("") is None


def test_parse_rssi_valid():
    assert parse_rssi("-55") == -55


def test_parse_rssi_missing_is_none():
    assert parse_rssi(None) is None
    assert parse_rssi("") is None


def test_parse_rssi_garbage_is_none():
    assert parse_rssi("not a number") is None


# ---------- scan_bluetooth (end-to-end, shell mocked) ----------


def _patch_shell(monkeypatch, stdout, ok=True):
    import secure.bluetooth.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(ok=ok, stdout=stdout, stderr="" if ok else "error", returncode=0 if ok else None),
    )


def test_scan_bluetooth_first_scan_all_new(tmp_path: Path, monkeypatch):
    _patch_shell(monkeypatch, _SAMPLE_BLUETOOTH_OUTPUT)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_bluetooth(db.conn)
        devices = list_bluetooth_devices(db.conn)

    assert result.bluetooth_available is True
    assert len(result.entries) == 2
    assert len(result.new_devices) == 2
    assert len(devices) == 2
    assert all(d.trusted is False for d in devices)
    assert all(d.times_seen == 1 for d in devices)


def test_scan_bluetooth_second_scan_same_devices_not_new(tmp_path: Path, monkeypatch):
    _patch_shell(monkeypatch, _SAMPLE_BLUETOOTH_OUTPUT)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        first = scan_bluetooth(db.conn)
        second = scan_bluetooth(db.conn)
        devices = list_bluetooth_devices(db.conn)

    assert len(first.new_devices) == 2
    assert len(second.new_devices) == 0
    assert all(d.times_seen == 2 for d in devices)


def test_scan_bluetooth_persistent_unknown_device_alert_fires_after_threshold(tmp_path: Path, monkeypatch):
    _patch_shell(monkeypatch, _SAMPLE_BLUETOOTH_OUTPUT)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        results = [scan_bluetooth(db.conn) for _ in range(3)]
        alerts = list_bluetooth_alerts(db.conn)

    # No alert on scans 1-2 (times_seen only reaches the threshold on
    # scan 3), then exactly one alert per device on scan 3.
    assert results[0].alerts == []
    assert results[1].alerts == []
    assert len(results[2].alerts) == 2
    assert len(alerts) == 2
    assert all(a.kind == "persistent_unknown" for a in alerts)
    assert all(a.severity == "low" for a in alerts)


def test_scan_bluetooth_persistent_unknown_alert_not_repeated(tmp_path: Path, monkeypatch):
    _patch_shell(monkeypatch, _SAMPLE_BLUETOOTH_OUTPUT)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        for _ in range(5):  # well past the threshold
            scan_bluetooth(db.conn)
        alerts = list_bluetooth_alerts(db.conn)

    # Exactly one alert per device, not one per scan past the threshold.
    assert len(alerts) == 2


def test_scan_bluetooth_trusted_device_never_alerted(tmp_path: Path, monkeypatch):
    _patch_shell(monkeypatch, _SAMPLE_BLUETOOTH_OUTPUT)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        scan_bluetooth(db.conn)  # first scan creates both devices
        for device in list_bluetooth_devices(db.conn):
            set_bluetooth_device_trusted(db.conn, device.id, True)

        for _ in range(4):  # well past the threshold
            scan_bluetooth(db.conn)
        alerts = list_bluetooth_alerts(db.conn)

    assert alerts == []


def test_scan_bluetooth_unavailable(tmp_path: Path, monkeypatch):
    _patch_shell(monkeypatch, "", ok=False)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_bluetooth(db.conn)

    assert result.bluetooth_available is False
    assert result.entries == []


# ---------- pairing/connection transition detection ----------

_UNPAIRED_UNCONNECTED = """\
Bluetooth:

      Devices (Paired, Configured, etc.):
          Test Device:
              Address: 55-66-77-88-99-00
              Paired: No
              Connected: No
"""

_PAIRED_UNCONNECTED = """\
Bluetooth:

      Devices (Paired, Configured, etc.):
          Test Device:
              Address: 55-66-77-88-99-00
              Paired: Yes
              Connected: No
"""

_PAIRED_CONNECTED = """\
Bluetooth:

      Devices (Paired, Configured, etc.):
          Test Device:
              Address: 55-66-77-88-99-00
              Paired: Yes
              Connected: Yes
"""


def test_scan_bluetooth_new_pairing_alert_is_high_for_untrusted_device(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _patch_shell(monkeypatch, _UNPAIRED_UNCONNECTED)
        first = scan_bluetooth(db.conn)  # creates the device, untrusted, unpaired

        _patch_shell(monkeypatch, _PAIRED_UNCONNECTED)
        second = scan_bluetooth(db.conn)  # same device, now paired -> transition

        alerts = list_bluetooth_alerts(db.conn)

    assert first.alerts == []  # brand-new device, nothing to compare against yet
    assert len(second.alerts) == 1
    assert second.alerts[0].kind == "new_pairing"
    assert second.alerts[0].severity == "high"
    assert "does not prove an attack" in second.alerts[0].message
    assert len(alerts) == 1


def test_scan_bluetooth_first_connection_alert_is_medium_for_untrusted_device(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _patch_shell(monkeypatch, _PAIRED_UNCONNECTED)
        first = scan_bluetooth(db.conn)  # creates the device, already paired, not connected

        _patch_shell(monkeypatch, _PAIRED_CONNECTED)
        second = scan_bluetooth(db.conn)  # same device, now connected -> transition

        alerts = list_bluetooth_alerts(db.conn)

    assert first.alerts == []
    assert len(second.alerts) == 1
    assert second.alerts[0].kind == "first_connection"
    assert second.alerts[0].severity == "medium"
    assert len(alerts) == 1


def test_scan_bluetooth_new_pairing_and_first_connection_can_both_fire_same_scan(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _patch_shell(monkeypatch, _UNPAIRED_UNCONNECTED)
        scan_bluetooth(db.conn)  # creates the device

        _patch_shell(monkeypatch, _PAIRED_CONNECTED)
        second = scan_bluetooth(db.conn)  # unpaired->paired AND unconnected->connected at once

    kinds = {a.kind for a in second.alerts}
    assert kinds == {"new_pairing", "first_connection"}


def test_scan_bluetooth_trusted_device_never_gets_transition_alerts(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _patch_shell(monkeypatch, _UNPAIRED_UNCONNECTED)
        scan_bluetooth(db.conn)
        for device in list_bluetooth_devices(db.conn):
            set_bluetooth_device_trusted(db.conn, device.id, True)

        _patch_shell(monkeypatch, _PAIRED_CONNECTED)
        second = scan_bluetooth(db.conn)  # trusted device pairs+connects

    assert second.alerts == []


def test_scan_bluetooth_transition_not_repeated_when_state_unchanged(tmp_path: Path, monkeypatch):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _patch_shell(monkeypatch, _UNPAIRED_UNCONNECTED)
        scan_bluetooth(db.conn)

        _patch_shell(monkeypatch, _PAIRED_UNCONNECTED)
        second = scan_bluetooth(db.conn)  # transition fires here

        third = scan_bluetooth(db.conn)  # still paired, no NEW transition

    assert len(second.alerts) == 1
    assert second.alerts[0].kind == "new_pairing"
    # No repeat of the pairing transition on the third scan — this
    # device's times_seen also happens to hit _PERSISTENT_THRESHOLD
    # (3) on this exact scan, so a *different* alert kind
    # (persistent_unknown) is expected here; what must NOT reappear is
    # the transition alert itself, since paired didn't change again.
    third_kinds = {a.kind for a in third.alerts}
    assert "new_pairing" not in third_kinds
    assert "first_connection" not in third_kinds
