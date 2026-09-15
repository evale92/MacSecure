"""
Tests for secure/baseline/_shell.py (eligibility lookups + the
baseline_activity gap-filling writer) and its live wiring into
secure/inventory/scanner.py + secure/persistence/scanner.py — the two
entity_types (inventory devices, process executables) with no existing
per-scan history table of their own.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.baseline.history import (
    record_gap_observation,
    unreviewed_alert_severities_for_entity,
)
from secure.baseline.constants import ENTITY_CAPS
from secure.baseline.entities import INVENTORY, PROCESS, inventory_key, process_key
from secure.inventory.arp_table import ArpEntry
from secure.inventory.hostnames import NO_RECORD, HostnameLookup
from secure.inventory.scanner import scan_network
from secure.persistence.scanner import scan_persistence
from secure.storage.database import Database
from secure.storage.models import (
    add_arp_alert,
    add_persistence_alert,
    find_baseline_entity,
    list_baseline_activity,
    upsert_device,
)


# ---------- unreviewed_alert_severities_for_entity() ----------


def test_inventory_severity_lookup_via_arp_alerts(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_device(db.conn, ip="10.0.0.5", mac="aa:bb:cc:dd:ee:ff", hostname=None, vendor=None)
        add_arp_alert(db.conn, "run1", "mac_changed", "high", "10.0.0.5", "aa:aa", "bb:bb", "MAC changed")

        severities = unreviewed_alert_severities_for_entity(db.conn, INVENTORY, "aa:bb:cc:dd:ee:ff")
        assert severities == ["high"]


def test_inventory_severity_lookup_empty_for_unknown_device(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        severities = unreviewed_alert_severities_for_entity(db.conn, INVENTORY, "aa:bb:cc:dd:ee:ff")
        assert severities == []


def test_process_severity_lookup_via_persistence_alerts(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_persistence_alert(
            db.conn, "run1", "unusual_unsigned_process", "high", "process",
            "/opt/sketchy/tool", "tool", "unsigned process",
        )
        severities = unreviewed_alert_severities_for_entity(db.conn, PROCESS, "/opt/sketchy/tool")
        assert severities == ["high"]


def test_listening_has_no_direct_severity_source(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert unreviewed_alert_severities_for_entity(db.conn, "listening", "svc:80/tcp") == []


# ---------- record_gap_observation() ----------


def test_record_gap_observation_creates_and_matures_entity(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        for day in range(1, 20):
            record_gap_observation(
                db.conn, f"run{day}", PROCESS, "/usr/bin/curl",
                f"2026-07-{day:02d}T10:00:00+00:00",
            )
        entity = find_baseline_entity(db.conn, PROCESS, "/usr/bin/curl")
        assert entity is not None
        assert entity.observation_count == 19
        assert entity.eligible_distinct_days == 19


def test_record_gap_observation_is_excluded_by_unreviewed_high_alert(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_persistence_alert(
            db.conn, "run1", "unusual_unsigned_process", "high", "process",
            "/opt/sketchy/tool", "tool", "unsigned process",
        )
        record_gap_observation(
            db.conn, "run1", PROCESS, "/opt/sketchy/tool", "2026-08-01T00:00:00+00:00"
        )
        entity = find_baseline_entity(db.conn, PROCESS, "/opt/sketchy/tool")
        assert entity.eligible_weight_total == 0
        assert entity.observation_count == 1  # still visible for audit

        activity = list_baseline_activity(db.conn, PROCESS, "/opt/sketchy/tool")
        assert activity[0].eligibility_reason == "unreviewed_high_alert"


def test_record_gap_observation_respects_entity_cap(tmp_path: Path, monkeypatch):
    # This test harness's monkeypatch fixture only supports setattr, not
    # setitem (see tests/test_persistence.py's _patch_launch_dirs for
    # the same constraint) — mutate the module-level dict directly and
    # restore it manually instead.
    original_cap = ENTITY_CAPS.get("process")
    ENTITY_CAPS["process"] = 2
    try:
        _run_entity_cap_scenario(tmp_path)
    finally:
        if original_cap is None:
            del ENTITY_CAPS["process"]
        else:
            ENTITY_CAPS["process"] = original_cap


def _run_entity_cap_scenario(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record_gap_observation(db.conn, "r1", PROCESS, "/usr/bin/a", "2026-08-01T00:00:00+00:00")
        record_gap_observation(db.conn, "r2", PROCESS, "/usr/bin/b", "2026-08-01T00:00:00+00:00")
        # Third distinct entity exceeds the (monkeypatched) cap of 2 and
        # must not be created — this must be visible/inspectable, never
        # a silent crash or a silently-created row past the cap.
        record_gap_observation(db.conn, "r3", PROCESS, "/usr/bin/c", "2026-08-01T00:00:00+00:00")

        assert find_baseline_entity(db.conn, PROCESS, "/usr/bin/a") is not None
        assert find_baseline_entity(db.conn, PROCESS, "/usr/bin/b") is not None
        assert find_baseline_entity(db.conn, PROCESS, "/usr/bin/c") is None

        # An already-existing entity keeps accumulating past the cap —
        # only brand-new entities are blocked.
        record_gap_observation(db.conn, "r4", PROCESS, "/usr/bin/a", "2026-08-02T00:00:00+00:00")
        entity_a = find_baseline_entity(db.conn, PROCESS, "/usr/bin/a")
        assert entity_a.observation_count == 2


# ---------- live wiring: scan_network / scan_persistence ----------


def test_scan_network_writes_baseline_gap_observations(tmp_path: Path, monkeypatch):
    import secure.inventory.scanner as scanner_module

    fake_entries = [ArpEntry(ip="192.168.1.1", mac="ac:de:48:00:11:22", hostname="gateway.local")]
    monkeypatch.setattr(scanner_module, "get_local_subnet", lambda: None)
    monkeypatch.setattr(scanner_module, "read_arp_table_with_availability", lambda: (fake_entries, True))
    monkeypatch.setattr(
        scanner_module, "resolve_hostname_with_status", lambda ip: HostnameLookup(None, NO_RECORD)
    )

    with Database(tmp_path / "test.db") as db:
        scan_network(db.conn)
        entity = find_baseline_entity(db.conn, INVENTORY, inventory_key("ac:de:48:00:11:22", "192.168.1.1"))

    assert entity is not None
    assert entity.observation_count == 1


def test_scan_persistence_writes_baseline_gap_observations(tmp_path: Path, monkeypatch):
    import secure.persistence.launch_items as launch_items_module
    import secure.persistence.scanner as scanner_module

    fresh = {kind: [tmp_path / f"_unused_{kind}"] for kind in launch_items_module._LAUNCH_ITEM_DIRECTORIES}
    monkeypatch.setattr(launch_items_module, "_LAUNCH_ITEM_DIRECTORIES", fresh)

    monkeypatch.setattr(scanner_module, "list_processes", lambda: (
        True, [{"pid": "1", "ppid": "0", "user": "root", "path_or_name": "/usr/bin/true"}]
    ))
    monkeypatch.setattr(scanner_module, "get_login_items", lambda: (True, []))
    monkeypatch.setattr(scanner_module, "check_code_signing", lambda path: "signed")

    with Database(tmp_path / "test.db") as db:
        scan_persistence(db.conn)
        entity = find_baseline_entity(db.conn, PROCESS, process_key("/usr/bin/true"))

    assert entity is not None
    assert entity.observation_count == 1
