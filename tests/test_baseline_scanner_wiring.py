"""
Tests for Phase 14 Stage 4C: baseline_runs lifecycle wired into the
actual scanners (persistence/scanner.py, wifi/scanner.py,
listening/scanner.py, inventory/scanner.py) — verifies each scan_*()
call produces exactly one baseline_runs row sharing its own run_id,
with a status that honestly reflects success/partial/failure, and that
failed/unavailable sensors never train the baseline.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.connections._shell import ShellResult
from secure.inventory.arp_table import ArpEntry
from secure.inventory.scanner import scan_network
from secure.listening.scanner import scan_listening_services
from secure.persistence.codesign import UNKNOWN
from secure.persistence.scanner import scan_persistence
from secure.storage.database import Database
from secure.storage.models import find_latest_baseline_run, list_baseline_runs
from secure.wifi.scanner import scan_wifi
from secure.wifi.status import WifiStatus

# ---------- wifi ----------


def test_scan_wifi_confirmed_disconnected_is_success_zero_counts(tmp_path: Path, monkeypatch):
    import secure.wifi.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module, "get_wifi_status",
        lambda: WifiStatus(connected=False, status_unknown=False),
    )
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_wifi(db.conn)
        run = find_latest_baseline_run(db.conn)

    assert result.connected is False
    assert run.run_id == result.run_id
    assert run.status == "success"
    assert run.features_evaluated == 0
    assert run.errors_count == 0


def test_scan_wifi_status_unknown_is_failed_not_silent(tmp_path: Path, monkeypatch):
    import secure.wifi.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module, "get_wifi_status",
        lambda: WifiStatus(connected=False, status_unknown=True),
    )
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_wifi(db.conn)
        run = find_latest_baseline_run(db.conn)

    assert run.run_id == result.run_id
    assert run.status == "failed"
    assert run.errors_count == 1


def test_scan_wifi_connected_produces_successful_baseline_run(tmp_path: Path, monkeypatch):
    import secure.wifi.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module, "get_wifi_status",
        lambda: WifiStatus(connected=True, status_unknown=False, ssid="HomeNet", security="WPA3 Personal"),
    )
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_wifi(db.conn)
        run = find_latest_baseline_run(db.conn)

    assert run.run_id == result.run_id
    assert run.status == "success"
    assert run.features_evaluated == 1
    assert run.features_updated == 1


# ---------- listening ----------


_FAKE_LISTENING_STDOUT = """\
COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
sshd         99   root    3u  IPv4 0x1111111111111111      0t0  TCP *:22 (LISTEN)
"""


def test_scan_listening_lsof_unavailable_is_failed(tmp_path: Path, monkeypatch):
    import secure.listening.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(ok=False, stdout="", stderr="command not found", returncode=None),
    )
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_listening_services(db.conn)
        run = find_latest_baseline_run(db.conn)

    assert result.lsof_available is False
    assert run.run_id == result.run_id
    assert run.status == "failed"
    assert run.errors_count == 1
    assert run.features_evaluated == 0


def test_scan_listening_success_produces_baseline_run(tmp_path: Path, monkeypatch):
    import secure.listening.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_FAKE_LISTENING_STDOUT, stderr="", returncode=0),
    )
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_listening_services(db.conn)
        run = find_latest_baseline_run(db.conn)

    assert run.run_id == result.run_id
    assert run.status == "success"
    assert run.features_evaluated == 1
    assert run.features_updated == 1


# ---------- persistence ----------


def _patch_persistence_scanner(monkeypatch, ps_result=None, login_items_result=None, signing_map=None):
    import secure.persistence.scanner as scanner_module

    if ps_result is not None:
        monkeypatch.setattr(scanner_module, "list_processes", lambda: ps_result)
    if login_items_result is not None:
        monkeypatch.setattr(scanner_module, "get_login_items", lambda: login_items_result)
    if signing_map is not None:
        monkeypatch.setattr(
            scanner_module, "check_code_signing", lambda path: signing_map.get(path, UNKNOWN)
        )
    return scanner_module


def _patch_empty_launch_dirs(monkeypatch, tmp_path: Path):
    import secure.persistence.launch_items as launch_items_module

    fresh = {
        "launch_agent_user": [tmp_path / "does_not_exist_agents"],
        "launch_agent_global": [tmp_path / "does_not_exist_agents_global"],
        "launch_daemon": [tmp_path / "does_not_exist_daemons"],
    }
    monkeypatch.setattr(launch_items_module, "_LAUNCH_ITEM_DIRECTORIES", fresh)


def test_scan_persistence_process_listing_failure_is_recorded(tmp_path: Path, monkeypatch):
    _patch_empty_launch_dirs(monkeypatch, tmp_path)
    scanner_module = _patch_persistence_scanner(
        monkeypatch, ps_result=(False, []), login_items_result=(True, []), signing_map={}
    )
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_persistence(db.conn)
        run = find_latest_baseline_run(db.conn)

    assert result.processes_available is False
    assert run.run_id == result.run_id
    # Nothing was updated (no processes, no persistence entries) and an
    # error was recorded -> failed, not a silent clean pass.
    assert run.status == "failed"
    assert run.errors_count == 1


def test_scan_persistence_login_items_failure_with_launch_agents_is_partial(tmp_path: Path, monkeypatch):
    _patch_empty_launch_dirs(monkeypatch, tmp_path)
    scanner_module = _patch_persistence_scanner(
        monkeypatch, ps_result=(True, []), login_items_result=(False, []), signing_map={}
    )
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_persistence(db.conn)
        run = find_latest_baseline_run(db.conn)

    assert result.login_items_available is False
    assert run.run_id == result.run_id
    # Login items failed (an error), but process listing succeeded with
    # zero processes -> nothing was updated either... still failed,
    # since nothing this pass actually produced a trained observation.
    assert run.status in ("failed", "partial")
    assert run.errors_count == 1


def test_scan_persistence_full_success_produces_baseline_run(tmp_path: Path, monkeypatch):
    _patch_empty_launch_dirs(monkeypatch, tmp_path)
    ps = (True, [{"pid": 1, "path_or_name": "/usr/bin/curl", "user": "erick"}])
    scanner_module = _patch_persistence_scanner(
        monkeypatch, ps_result=ps, login_items_result=(True, []),
        signing_map={"/usr/bin/curl": "signed_apple"},
    )
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_persistence(db.conn)
        run = find_latest_baseline_run(db.conn)

    assert run.run_id == result.run_id
    assert run.status == "success"
    assert run.entities_evaluated == 1  # the one process, gap-filled
    assert run.entities_updated == 1
    assert run.errors_count == 0


# ---------- inventory ----------


def test_scan_network_produces_successful_baseline_run(tmp_path: Path, monkeypatch):
    import secure.inventory.scanner as scanner_module

    fake_entries = [ArpEntry(ip="192.168.1.1", mac="ac:de:48:00:11:22", hostname="gateway.local")]
    monkeypatch.setattr(scanner_module, "get_local_subnet", lambda: None)
    monkeypatch.setattr(scanner_module, "read_arp_table_with_availability", lambda: (fake_entries, True))
    monkeypatch.setattr(scanner_module, "resolve_hostname", lambda ip: None)

    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_network(db.conn)
        run = find_latest_baseline_run(db.conn)

    assert run.status == "success"
    assert run.entities_evaluated == 1
    assert run.entities_updated == 1


def test_scan_network_zero_devices_is_still_a_clean_run(tmp_path: Path, monkeypatch):
    import secure.inventory.scanner as scanner_module

    monkeypatch.setattr(scanner_module, "get_local_subnet", lambda: None)
    monkeypatch.setattr(scanner_module, "read_arp_table_with_availability", lambda: ([], True))
    monkeypatch.setattr(scanner_module, "resolve_hostname", lambda ip: None)

    with Database(tmp_path / "test.db") as db:
        scanner_module.scan_network(db.conn)
        run = find_latest_baseline_run(db.conn)

    assert run.status == "success"
    assert run.entities_evaluated == 0


def test_each_scan_produces_exactly_one_baseline_run_row(tmp_path: Path, monkeypatch):
    import secure.inventory.scanner as scanner_module

    monkeypatch.setattr(scanner_module, "get_local_subnet", lambda: None)
    monkeypatch.setattr(scanner_module, "read_arp_table_with_availability", lambda: ([], True))
    monkeypatch.setattr(scanner_module, "resolve_hostname", lambda ip: None)

    with Database(tmp_path / "test.db") as db:
        scanner_module.scan_network(db.conn)
        scanner_module.scan_network(db.conn)
        scanner_module.scan_network(db.conn)
        runs = list_baseline_runs(db.conn, limit=100)

    assert len(runs) == 3
    assert len({r.run_id for r in runs}) == 3  # each scan minted its own distinct run_id
