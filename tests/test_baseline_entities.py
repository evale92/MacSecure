"""
Tests for secure/baseline/entities.py — pure entity_type/entity_key
derivation. No database, no I/O.

Run with:  pytest
"""

from __future__ import annotations

from secure.baseline import entities


def test_inventory_key_prefers_mac_over_ip():
    assert entities.inventory_key("aa:bb:cc:dd:ee:ff", "192.168.1.5") == "aa:bb:cc:dd:ee:ff"


def test_inventory_key_falls_back_to_ip():
    assert entities.inventory_key(None, "192.168.1.5") == "192.168.1.5"


def test_process_key_is_executable_path():
    assert entities.process_key("/usr/bin/curl") == "/usr/bin/curl"


def test_process_destination_key_shape():
    key = entities.process_destination_key("Syncthing", "203.0.113.5", 22067, "tcp")
    assert key == "Syncthing::203.0.113.5:22067/tcp"


def test_process_destination_key_unknown_process_name():
    key = entities.process_destination_key(None, "203.0.113.5", 443, "tcp")
    assert key == "(unknown)::203.0.113.5:443/tcp"


def test_two_processes_same_destination_get_different_entity_keys():
    # This is the whole point of process_destination as its own
    # entity_type — Chrome and a single-purpose CLI tool contacting
    # the same IP must never share one baseline (approval item 5).
    a = entities.process_destination_key("Chrome", "93.184.216.34", 443, "tcp")
    b = entities.process_destination_key("curl", "93.184.216.34", 443, "tcp")
    assert a != b


def test_listening_key_shape():
    assert entities.listening_key("ControlCenter", "5000", "tcp") == "ControlCenter:5000/tcp"


def test_wifi_key_is_ssid():
    assert entities.wifi_key("HomeNet") == "HomeNet"


def test_bluetooth_key_is_identifier():
    assert entities.bluetooth_key("aa-bb-cc") == "aa-bb-cc"


def test_ble_key_is_cb_uuid():
    assert entities.ble_key("1234-5678") == "1234-5678"


def test_persistence_key_shape():
    assert (
        entities.persistence_key("launch_agent_user", "/Users/erick/Library/LaunchAgents/x.plist")
        == "launch_agent_user::/Users/erick/Library/LaunchAgents/x.plist"
    )


def test_file_watch_path_key_is_stringified_id():
    assert entities.file_watch_path_key(7) == "7"


def test_entity_types_tuple_has_eleven_entries():
    # 9 through Phase 14, +2 (dns_query, tls_sni) added by Phase 19's
    # Zeek integration — see secure/baseline/entities.py.
    assert len(entities.ENTITY_TYPES) == 11
    assert len(set(entities.ENTITY_TYPES)) == 11
