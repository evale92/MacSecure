"""
Tests for secure/baseline/history.py's read adapters — the functions
that read raw observation timestamps for the seven entity_types that
already have an existing *_events/*_observations table, rather than
duplicating them into baseline_activity.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.baseline import entities
from secure.baseline.history import (
    read_ble_observations,
    read_bluetooth_observations,
    read_entity_observations,
    read_file_watch_path_observations,
    read_listening_observations,
    read_persistence_observations,
    read_process_destination_observations,
    read_wifi_observations,
)
from secure.storage.database import Database
from secure.storage.models import (
    add_ble_observations,
    add_bluetooth_observations,
    add_connection_events,
    add_file_change_event,
    add_listening_events,
    add_persistence_observations,
    add_watch_path,
    add_wifi_observation,
)


def test_read_process_destination_observations(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_connection_events(
            db.conn, run_id="r1",
            rows=[("tcp", "10.0.0.5", 51000, "203.0.113.5", 443, "ESTABLISHED", 100, "Chrome")],
        )
        key = entities.process_destination_key("Chrome", "203.0.113.5", 443, "tcp")
        rows = read_process_destination_observations(db.conn, key)
        assert len(rows) == 1


def test_read_process_destination_observations_no_match(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_connection_events(
            db.conn, run_id="r1",
            rows=[("tcp", "10.0.0.5", 51000, "203.0.113.5", 443, "ESTABLISHED", 100, "Chrome")],
        )
        key = entities.process_destination_key("Safari", "203.0.113.5", 443, "tcp")
        assert read_process_destination_observations(db.conn, key) == []


def test_read_listening_observations_uses_identity_port_bucketing(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        # A privileged (fixed) port stays exact.
        add_listening_events(
            db.conn, run_id="r1",
            rows=[("tcp", "127.0.0.1", 80, "loopback", 200, "nginx")],
        )
        add_listening_events(
            db.conn, run_id="r2",
            rows=[("tcp", "127.0.0.1", 80, "loopback", 200, "nginx")],
        )
        key = entities.listening_key("nginx", "80", "tcp")
        rows = read_listening_observations(db.conn, key)
        assert len(rows) == 2


def test_read_listening_observations_ephemeral_port_bucket_matches_across_restarts(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        # Two different high, non-well-known ports for the same
        # process (simulating a restart with a new OS-assigned port)
        # must both bucket into the same "ephemeral" identity.
        add_listening_events(
            db.conn, run_id="r1",
            rows=[("tcp", "127.0.0.1", 55231, "loopback", 300, "IntelliJ IDEA")],
        )
        add_listening_events(
            db.conn, run_id="r2",
            rows=[("tcp", "127.0.0.1", 61984, "loopback", 300, "IntelliJ IDEA")],
        )
        key = entities.listening_key("IntelliJ IDEA", "ephemeral", "tcp")
        rows = read_listening_observations(db.conn, key)
        assert len(rows) == 2


def test_read_wifi_observations(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_wifi_observation(db.conn, run_id="r1", ssid="HomeNet", bssid="aa:bb", channel="6",
                              phy_mode="ac", security="WPA2", rssi=-50, noise=-90)
        rows = read_wifi_observations(db.conn, entities.wifi_key("HomeNet"))
        assert len(rows) == 1


def test_read_bluetooth_observations(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_bluetooth_observations(
            db.conn, run_id="r1",
            rows=[("aa-bb-cc", "Headphones", 0, 0, -60)],
        )
        rows = read_bluetooth_observations(db.conn, entities.bluetooth_key("aa-bb-cc"))
        assert len(rows) == 1


def test_read_ble_observations(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_ble_observations(
            db.conn, run_id="r1",
            rows=[("1234-uuid", "Watch", -55, "[]", "{}")],
        )
        rows = read_ble_observations(db.conn, entities.ble_key("1234-uuid"))
        assert len(rows) == 1


def test_read_persistence_observations_by_path(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_persistence_observations(
            db.conn, run_id="r1",
            rows=[("launch_agent_user", "com.example.agent", "/Users/erick/x.plist", "/usr/bin/agent", 1, 0)],
        )
        key = entities.persistence_key("launch_agent_user", "/Users/erick/x.plist")
        rows = read_persistence_observations(db.conn, key)
        assert len(rows) == 1


def test_read_file_watch_path_observations(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        watch_path, _ = add_watch_path(db.conn, "/Users/erick/Documents", recursive=True)
        add_file_change_event(
            db.conn, run_id="r1", watch_path_id=watch_path.id, path="/Users/erick/Documents/a.txt",
            old_path=None, change_type="created", previous_hash=None, new_hash="abc",
            rename_confidence=None, details={},
        )
        rows = read_file_watch_path_observations(db.conn, entities.file_watch_path_key(watch_path.id))
        assert len(rows) == 1


def test_read_entity_observations_dispatches_correctly(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_wifi_observation(db.conn, run_id="r1", ssid="HomeNet", bssid=None, channel=None,
                              phy_mode=None, security=None, rssi=None, noise=None)
        rows = read_entity_observations(db.conn, "wifi", "HomeNet")
        assert len(rows) == 1


def test_read_entity_observations_gap_types_return_empty(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        # "inventory"/"process" have no history table to read from —
        # their history lives in baseline_activity instead (see
        # list_baseline_activity()), not through this dispatcher.
        assert read_entity_observations(db.conn, "inventory", "aa:bb:cc") == []
        assert read_entity_observations(db.conn, "process", "/usr/bin/x") == []


def test_read_entity_observations_unknown_type_returns_empty(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert read_entity_observations(db.conn, "not_a_real_type", "x") == []
