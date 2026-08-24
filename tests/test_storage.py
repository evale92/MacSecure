"""
Tests for secure/storage/*.

Run with:  pytest
"""

from pathlib import Path

from secure.storage.database import Database, init_schema
from secure.storage.models import (
    add_arp_alert,
    add_arp_observations,
    add_ble_alert,
    add_ble_observations,
    add_bluetooth_alert,
    add_bluetooth_observations,
    add_connection_events,
    add_event,
    add_listening_events,
    add_posture_result,
    add_snapshot,
    add_wifi_alert,
    add_wifi_observation,
    count_events,
    find_arp_alert_by_id,
    find_ble_alert_by_id,
    find_ble_peripheral_by_id,
    find_bluetooth_alert_by_id,
    find_bluetooth_device_by_id,
    find_device_by_identifier,
    find_listening_service_by_id,
    find_remote_endpoint_by_id,
    find_wifi_alert_by_id,
    find_wifi_network_by_id,
    add_persistence_observations,
    find_persistence_alert_by_id,
    find_persistence_entry_by_id,
    find_process_entry_by_id,
    find_process_entry_by_path,
    has_ble_alert_of_kind,
    has_bluetooth_alert_of_kind,
    last_connection_run_id,
    last_posture_run_id,
    list_arp_alerts,
    list_arp_mappings,
    list_ble_alerts,
    list_ble_peripherals,
    list_bluetooth_alerts,
    list_bluetooth_devices,
    list_devices,
    list_events,
    list_known_ssids,
    list_listening_services,
    list_persistence_alerts,
    list_persistence_entries,
    list_process_entries,
    list_recent_connection_events,
    list_recent_listening_events,
    list_recent_posture_results,
    list_recent_snapshots,
    list_remote_endpoints,
    list_wifi_alerts,
    list_wifi_networks,
    add_persistence_alert,
    set_arp_alert_known,
    set_ble_alert_known,
    set_ble_peripheral_trusted,
    set_bluetooth_alert_known,
    set_bluetooth_device_trusted,
    set_device_friendly_name,
    set_device_known,
    set_listening_service_known,
    set_persistence_alert_known,
    set_persistence_entry_known,
    set_process_entry_known,
    set_remote_endpoint_known,
    set_wifi_alert_known,
    set_wifi_network_known,
    upsert_arp_mapping,
    upsert_ble_peripheral,
    upsert_bluetooth_device,
    upsert_device,
    upsert_persistence_entry,
    upsert_process_entry,
    upsert_listening_service,
    upsert_remote_endpoint,
    upsert_wifi_network,
)


def test_add_and_count_events(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert count_events(db.conn) == 0
        add_event(db.conn, category="note", message="first")
        add_event(db.conn, category="note", message="second")
        assert count_events(db.conn) == 2


def test_list_events_newest_first(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        add_event(db.conn, category="note", message="oldest")
        add_event(db.conn, category="note", message="newest")
        events = list_events(db.conn, limit=10)

    assert events[0].message == "newest"
    assert events[1].message == "oldest"


def test_add_and_list_posture_results(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        add_posture_result(
            db.conn,
            run_id="run-1",
            check_name="FileVault",
            status="PASS",
            message="FileVault is On.",
            remediation="",
        )
        add_posture_result(
            db.conn,
            run_id="run-1",
            check_name="Firewall",
            status="FAIL",
            message="Firewall is Off.",
            remediation="Turn it on.",
        )
        results = list_recent_posture_results(db.conn, limit=10)
        latest_run = last_posture_run_id(db.conn)

    assert len(results) == 2
    # newest first
    assert results[0].check_name == "Firewall"
    assert results[0].status == "FAIL"
    assert results[1].check_name == "FileVault"
    assert latest_run == "run-1"


def test_last_posture_run_id_none_when_empty(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert last_posture_run_id(db.conn) is None


def test_add_and_list_snapshots(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        add_snapshot(
            db.conn,
            window_minutes=15,
            summary="1 project file(s) changed",
            details_json='{"taken_at": "x"}',
        )
        snapshots = list_recent_snapshots(db.conn, limit=10)

    assert len(snapshots) == 1
    assert snapshots[0].window_minutes == 15
    assert snapshots[0].summary == "1 project file(s) changed"
    assert snapshots[0].details == '{"taken_at": "x"}'


def test_upsert_device_insert_then_update(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record1, was_new1 = upsert_device(
            db.conn, ip="192.168.1.50", mac="ac:de:48:00:11:22", hostname="laptop.local", vendor="Apple"
        )
        assert was_new1 is True
        assert record1.known is False
        assert record1.friendly_name is None
        assert record1.first_seen == record1.last_seen

        # Same MAC, new IP (simulating a DHCP lease change) and a
        # hostname this time resolved as None (shouldn't clobber the
        # one we already have).
        record2, was_new2 = upsert_device(
            db.conn, ip="192.168.1.51", mac="ac:de:48:00:11:22", hostname=None, vendor=None
        )

        devices = list_devices(db.conn)

    assert was_new2 is False
    assert record2.id == record1.id
    assert record2.ip == "192.168.1.51"
    assert record2.hostname == "laptop.local"  # preserved, not overwritten with None
    assert record2.vendor == "Apple"
    assert record2.last_seen >= record1.last_seen
    assert len(devices) == 1  # still one row, not two


def test_upsert_device_without_mac_dedupes_by_ip(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record1, was_new1 = upsert_device(
            db.conn, ip="192.168.1.60", mac=None, hostname=None, vendor=None
        )
        record2, was_new2 = upsert_device(
            db.conn, ip="192.168.1.60", mac=None, hostname="thing.local", vendor=None
        )
        devices = list_devices(db.conn)

    assert was_new1 is True
    assert was_new2 is False
    assert record2.id == record1.id
    assert record2.hostname == "thing.local"
    assert len(devices) == 1


def test_find_device_by_identifier_matches_mac_or_ip(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        upsert_device(db.conn, ip="192.168.1.70", mac="aa:bb:cc:dd:ee:ff", hostname=None, vendor=None)

        by_mac = find_device_by_identifier(db.conn, "aa:bb:cc:dd:ee:ff")
        by_ip = find_device_by_identifier(db.conn, "192.168.1.70")
        missing = find_device_by_identifier(db.conn, "10.0.0.99")

    assert by_mac is not None
    assert by_ip is not None
    assert by_mac.id == by_ip.id
    assert missing is None


def test_set_device_friendly_name_and_known(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record, _ = upsert_device(db.conn, ip="192.168.1.80", mac="11:22:33:44:55:66", hostname=None, vendor=None)
        assert record.known is False
        assert record.friendly_name is None

        set_device_friendly_name(db.conn, record.id, "Erick's iPhone")
        set_device_known(db.conn, record.id, True)

        updated = find_device_by_identifier(db.conn, "192.168.1.80")

    assert updated.friendly_name == "Erick's iPhone"
    assert updated.known is True


def test_add_and_list_connection_events(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        add_connection_events(
            db.conn,
            run_id="run-1",
            rows=[
                ("TCP", "192.168.1.23", 54321, "142.250.80.14", 443, "ESTABLISHED", 1234, "Google"),
                ("TCP", "*", 22, None, None, "LISTEN", 99, "sshd"),
            ],
        )
        events = list_recent_connection_events(db.conn, limit=10)
        latest_run = last_connection_run_id(db.conn)

    assert len(events) == 2
    # newest first (insertion order reversed)
    assert events[0].process_name == "sshd"
    assert events[0].remote_addr is None
    assert events[1].process_name == "Google"
    assert events[1].remote_port == 443
    assert latest_run == "run-1"


def test_last_connection_run_id_none_when_empty(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert last_connection_run_id(db.conn) is None


def test_upsert_remote_endpoint_insert_then_update(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record1, was_new1 = upsert_remote_endpoint(
            db.conn, remote_addr="142.250.80.14", remote_port=443, proto="TCP", process_name="Google"
        )
        assert was_new1 is True
        assert record1.known is False
        assert record1.first_seen == record1.last_seen

        # Same destination seen again, this time with no process name
        # resolved (shouldn't clobber the one we already have).
        record2, was_new2 = upsert_remote_endpoint(
            db.conn, remote_addr="142.250.80.14", remote_port=443, proto="TCP", process_name=None
        )
        endpoints = list_remote_endpoints(db.conn)

    assert was_new2 is False
    assert record2.id == record1.id
    assert record2.process_name == "Google"  # preserved, not overwritten with None
    assert len(endpoints) == 1  # still one row, not two


def test_upsert_remote_endpoint_distinguishes_by_port_and_proto(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        upsert_remote_endpoint(db.conn, remote_addr="1.2.3.4", remote_port=443, proto="TCP", process_name="a")
        upsert_remote_endpoint(db.conn, remote_addr="1.2.3.4", remote_port=80, proto="TCP", process_name="a")
        upsert_remote_endpoint(db.conn, remote_addr="1.2.3.4", remote_port=443, proto="UDP", process_name="a")
        endpoints = list_remote_endpoints(db.conn)

    assert len(endpoints) == 3  # different port or proto is a different endpoint


def test_set_remote_endpoint_known(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record, _ = upsert_remote_endpoint(
            db.conn, remote_addr="1.2.3.4", remote_port=443, proto="TCP", process_name="a"
        )
        assert record.known is False

        set_remote_endpoint_known(db.conn, record.id, True)
        updated = find_remote_endpoint_by_id(db.conn, record.id)

    assert updated.known is True


def test_find_remote_endpoint_by_id_missing_is_none(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert find_remote_endpoint_by_id(db.conn, 9999) is None


def test_add_and_list_listening_events(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        add_listening_events(
            db.conn,
            run_id="run-1",
            rows=[
                ("TCP", "*", 22, "network", 99, "sshd"),
                ("TCP", "127.0.0.1", 49220, "localhost", 1399, "Postman"),
            ],
        )
        events = list_recent_listening_events(db.conn, limit=10)

    assert len(events) == 2
    assert events[0].process_name == "Postman"  # newest first
    assert events[0].bind_scope == "localhost"
    assert events[1].process_name == "sshd"
    assert events[1].bind_scope == "network"


def test_upsert_listening_service_insert_then_update(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record1, was_new1 = upsert_listening_service(
            db.conn, proto="TCP", bind_scope="network", process_name="sshd",
            identity_port="22", local_addr="*", local_port=22,
        )
        assert was_new1 is True
        assert record1.known is False
        assert record1.first_seen == record1.last_seen

        # Same identity, seen again with a (hypothetically) different
        # concrete local_addr — local_addr/local_port are informational
        # only, not part of the identity, and get overwritten.
        record2, was_new2 = upsert_listening_service(
            db.conn, proto="TCP", bind_scope="network", process_name="sshd",
            identity_port="22", local_addr="0.0.0.0", local_port=22,
        )
        services = list_listening_services(db.conn)

    assert was_new2 is False
    assert record2.id == record1.id
    assert record2.local_addr == "0.0.0.0"
    assert len(services) == 1  # still one row, not two


def test_upsert_listening_service_distinguishes_by_identity_port(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        upsert_listening_service(
            db.conn, proto="TCP", bind_scope="localhost", process_name="Postman",
            identity_port="ephemeral", local_addr="127.0.0.1", local_port=49220,
        )
        # Same process/proto/bind_scope, but a later scan's port fell
        # into the same "ephemeral" bucket — this is exactly the
        # restart-noise case _identity_port() exists to collapse.
        upsert_listening_service(
            db.conn, proto="TCP", bind_scope="localhost", process_name="Postman",
            identity_port="ephemeral", local_addr="127.0.0.1", local_port=51111,
        )
        services = list_listening_services(db.conn)

    assert len(services) == 1


def test_set_listening_service_known(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record, _ = upsert_listening_service(
            db.conn, proto="TCP", bind_scope="network", process_name="sshd",
            identity_port="22", local_addr="*", local_port=22,
        )
        assert record.known is False

        set_listening_service_known(db.conn, record.id, True)
        updated = find_listening_service_by_id(db.conn, record.id)

    assert updated.known is True


def test_find_listening_service_by_id_missing_is_none(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert find_listening_service_by_id(db.conn, 9999) is None


def test_add_and_list_arp_observations(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        add_arp_observations(
            db.conn,
            run_id="run-1",
            rows=[
                ("192.168.1.1", "aa:aa:aa:aa:aa:aa", "gateway.local"),
                ("192.168.1.50", "bb:bb:bb:bb:bb:bb", None),
            ],
        )
        # No dedicated list_recent_arp_observations helper is needed by
        # any caller yet, so just confirm the rows landed via a raw
        # count — models.py's job here is only "store what it's given."
        count = db.conn.execute("SELECT COUNT(*) AS n FROM arp_observations").fetchone()["n"]

    assert count == 2


def test_upsert_arp_mapping_insert_then_update(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record1, was_new1 = upsert_arp_mapping(
            db.conn, ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa", is_gateway=True
        )
        assert was_new1 is True
        assert record1.is_gateway is True
        assert record1.first_seen == record1.last_seen

        record2, was_new2 = upsert_arp_mapping(
            db.conn, ip="192.168.1.1", mac="cc:cc:cc:cc:cc:cc", is_gateway=True
        )
        mappings = list_arp_mappings(db.conn)

    assert was_new2 is False
    assert record2.id == record1.id
    assert record2.mac == "cc:cc:cc:cc:cc:cc"  # updated to the new value
    assert len(mappings) == 1


def test_add_and_list_arp_alerts(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        alert_id = add_arp_alert(
            db.conn,
            run_id="run-1",
            kind="gateway_mac_changed",
            severity="high",
            ip="192.168.1.1",
            mac="cc:cc:cc:cc:cc:cc",
            previous_mac="aa:aa:aa:aa:aa:aa",
            message="test message",
        )
        alerts = list_arp_alerts(db.conn)

    assert len(alerts) == 1
    assert alerts[0].id == alert_id
    assert alerts[0].known is False
    assert alerts[0].severity == "high"


def test_set_arp_alert_known(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        alert_id = add_arp_alert(
            db.conn, run_id="run-1", kind="mac_changed", severity="low",
            ip="192.168.1.50", mac="bb:bb:bb:bb:bb:bb", previous_mac="aa:aa:aa:aa:aa:aa",
            message="test",
        )
        set_arp_alert_known(db.conn, alert_id, True)
        updated = find_arp_alert_by_id(db.conn, alert_id)

    assert updated.known is True


def test_find_arp_alert_by_id_missing_is_none(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert find_arp_alert_by_id(db.conn, 9999) is None


def test_add_wifi_observation(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        obs_id = add_wifi_observation(
            db.conn, run_id="run-1", ssid="HomeNetwork", bssid="aa:aa:aa:aa:aa:aa",
            channel="44 (5GHz, 80MHz)", phy_mode="802.11ax", security="WPA2 Personal",
            rssi=-50, noise=-90,
        )
        count = db.conn.execute("SELECT COUNT(*) AS n FROM wifi_observations").fetchone()["n"]

    assert obs_id is not None
    assert count == 1


def test_upsert_wifi_network_insert_then_update(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record1, was_new1 = upsert_wifi_network(db.conn, ssid="HomeNetwork", bssid="aa:aa:aa:aa:aa:aa")
        assert was_new1 is True
        assert record1.known is False
        assert record1.first_seen == record1.last_seen

        record2, was_new2 = upsert_wifi_network(db.conn, ssid="HomeNetwork", bssid="aa:aa:aa:aa:aa:aa")
        networks = list_wifi_networks(db.conn)

    assert was_new2 is False
    assert record2.id == record1.id
    assert len(networks) == 1


def test_upsert_wifi_network_without_bssid_dedupes_by_ssid(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record1, was_new1 = upsert_wifi_network(db.conn, ssid="CoffeeShop", bssid=None)
        record2, was_new2 = upsert_wifi_network(db.conn, ssid="CoffeeShop", bssid=None)
        networks = list_wifi_networks(db.conn)

    assert was_new1 is True
    assert was_new2 is False
    assert record2.id == record1.id
    assert len(networks) == 1


def test_upsert_wifi_network_distinguishes_by_bssid(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        upsert_wifi_network(db.conn, ssid="HomeNetwork", bssid="aa:aa:aa:aa:aa:aa")
        upsert_wifi_network(db.conn, ssid="HomeNetwork", bssid="bb:bb:bb:bb:bb:bb")
        networks = list_wifi_networks(db.conn)

    assert len(networks) == 2  # a second access point under the same SSID is a distinct entry


def test_set_wifi_network_known_and_list_known_ssids(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record, _ = upsert_wifi_network(db.conn, ssid="HomeNetwork", bssid="aa:aa:aa:aa:aa:aa")
        assert record.known is False
        assert list_known_ssids(db.conn) == []

        set_wifi_network_known(db.conn, record.id, True)
        updated = find_wifi_network_by_id(db.conn, record.id)
        known_ssids = list_known_ssids(db.conn)

    assert updated.known is True
    assert known_ssids == ["HomeNetwork"]


def test_find_wifi_network_by_id_missing_is_none(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert find_wifi_network_by_id(db.conn, 9999) is None


def test_add_and_list_wifi_alerts(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        alert_id = add_wifi_alert(
            db.conn, run_id="run-1", kind="similar_ssid", severity="medium",
            ssid="HomeNetwok", bssid=None, message="test message",
        )
        alerts = list_wifi_alerts(db.conn)

    assert len(alerts) == 1
    assert alerts[0].id == alert_id
    assert alerts[0].known is False
    assert alerts[0].severity == "medium"


def test_set_wifi_alert_known(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        alert_id = add_wifi_alert(
            db.conn, run_id="run-1", kind="similar_ssid", severity="medium",
            ssid="HomeNetwok", bssid=None, message="test",
        )
        set_wifi_alert_known(db.conn, alert_id, True)
        updated = find_wifi_alert_by_id(db.conn, alert_id)

    assert updated.known is True


def test_find_wifi_alert_by_id_missing_is_none(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert find_wifi_alert_by_id(db.conn, 9999) is None


def test_add_bluetooth_observations(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        add_bluetooth_observations(
            db.conn,
            run_id="run-1",
            rows=[
                ("aa:bb:cc:dd:ee:ff", "AirPods", True, False, None),
                ("11:22:33:44:55:66", "Keyboard", True, True, -50),
            ],
        )
        count = db.conn.execute("SELECT COUNT(*) AS n FROM bluetooth_observations").fetchone()["n"]

    assert count == 2


def test_upsert_bluetooth_device_insert_then_update(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record1, was_new1, was_paired1, was_connected1 = upsert_bluetooth_device(
            db.conn, identifier="aa:bb:cc:dd:ee:ff", name="AirPods", rssi=None
        )
        assert was_new1 is True
        assert record1.trusted is False
        assert record1.times_seen == 1
        assert record1.first_seen == record1.last_seen
        assert record1.paired is False
        assert record1.connected is False
        # No prior state exists for a brand-new device.
        assert was_paired1 is False
        assert was_connected1 is False

        # Seen again, this time with an RSSI reading, no name resolved
        # (shouldn't clobber the name we already have), and now paired.
        record2, was_new2, was_paired2, was_connected2 = upsert_bluetooth_device(
            db.conn, identifier="aa:bb:cc:dd:ee:ff", name=None, rssi=-60, paired=True, connected=False
        )
        devices = list_bluetooth_devices(db.conn)

    assert was_new2 is False
    assert record2.id == record1.id
    assert record2.name == "AirPods"  # preserved, not overwritten with None
    assert record2.last_rssi == -60
    assert record2.times_seen == 2
    assert record2.paired is True
    assert record2.connected is False
    # Reports the state BEFORE this call overwrote it (both were False).
    assert was_paired2 is False
    assert was_connected2 is False
    assert len(devices) == 1  # still one row, not two


def test_upsert_bluetooth_device_reports_prior_state_correctly(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        upsert_bluetooth_device(
            db.conn, identifier="aa:bb:cc:dd:ee:ff", name="Thing", rssi=None, paired=True, connected=False
        )
        # Third call: paired stays True, connected flips False -> True.
        record, was_new, was_paired, was_connected = upsert_bluetooth_device(
            db.conn, identifier="aa:bb:cc:dd:ee:ff", name="Thing", rssi=-40, paired=True, connected=True
        )

    assert was_new is False
    assert was_paired is True  # already paired before this call
    assert was_connected is False  # NOT connected before this call
    assert record.paired is True
    assert record.connected is True  # current state, post-update


def test_set_bluetooth_device_trusted(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record, *_ = upsert_bluetooth_device(db.conn, identifier="aa:bb:cc:dd:ee:ff", name="AirPods", rssi=None)
        assert record.trusted is False

        set_bluetooth_device_trusted(db.conn, record.id, True)
        updated = find_bluetooth_device_by_id(db.conn, record.id)

    assert updated.trusted is True


def test_find_bluetooth_device_by_id_missing_is_none(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert find_bluetooth_device_by_id(db.conn, 9999) is None


def test_add_and_list_bluetooth_alerts(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        alert_id = add_bluetooth_alert(
            db.conn, run_id="run-1", kind="persistent_unknown", severity="low",
            identifier="aa:bb:cc:dd:ee:ff", name="Unknown Device", message="test message",
        )
        alerts = list_bluetooth_alerts(db.conn)

    assert len(alerts) == 1
    assert alerts[0].id == alert_id
    assert alerts[0].known is False
    assert alerts[0].severity == "low"


def test_set_bluetooth_alert_known(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        alert_id = add_bluetooth_alert(
            db.conn, run_id="run-1", kind="persistent_unknown", severity="low",
            identifier="aa:bb:cc:dd:ee:ff", name=None, message="test",
        )
        set_bluetooth_alert_known(db.conn, alert_id, True)
        updated = find_bluetooth_alert_by_id(db.conn, alert_id)

    assert updated.known is True


def test_find_bluetooth_alert_by_id_missing_is_none(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert find_bluetooth_alert_by_id(db.conn, 9999) is None


def test_has_bluetooth_alert_of_kind(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert has_bluetooth_alert_of_kind(db.conn, "aa:bb:cc:dd:ee:ff", "persistent_unknown") is False

        add_bluetooth_alert(
            db.conn, run_id="run-1", kind="persistent_unknown", severity="low",
            identifier="aa:bb:cc:dd:ee:ff", name=None, message="test",
        )

        assert has_bluetooth_alert_of_kind(db.conn, "aa:bb:cc:dd:ee:ff", "persistent_unknown") is True
        assert has_bluetooth_alert_of_kind(db.conn, "aa:bb:cc:dd:ee:ff", "some_other_kind") is False


# ---------- ble_observations / ble_peripherals / ble_alerts ----------


def test_add_ble_observations(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        add_ble_observations(
            db.conn,
            run_id="run-1",
            rows=[
                ("11111111-1111-1111-1111-111111111111", "Some Device", -60, "[]", "{}"),
                ("22222222-2222-2222-2222-222222222222", None, None, '["180d"]', '{"0x004c": "0102"}'),
            ],
        )
        count = db.conn.execute("SELECT COUNT(*) AS n FROM ble_observations").fetchone()["n"]

    assert count == 2


def test_upsert_ble_peripheral_insert_then_update(tmp_path: Path):
    db_path = tmp_path / "test.db"
    uuid_ = "11111111-1111-1111-1111-111111111111"

    with Database(db_path) as db:
        record1, was_new1, prev_rssi1 = upsert_ble_peripheral(
            db.conn, cb_uuid=uuid_, name="Some Device", rssi=-60
        )
        assert was_new1 is True
        assert prev_rssi1 is None  # no prior state for a brand-new peripheral
        assert record1.trusted is False
        assert record1.times_seen == 1
        assert record1.first_rssi == -60
        assert record1.last_rssi == -60

        # Seen again with no name resolved (shouldn't clobber the name)
        # and a different RSSI — previous_rssi must reflect the OLD
        # value, not the one this call is about to write.
        record2, was_new2, prev_rssi2 = upsert_ble_peripheral(
            db.conn, cb_uuid=uuid_, name=None, rssi=-80
        )
        peripherals = list_ble_peripherals(db.conn)

    assert was_new2 is False
    assert prev_rssi2 == -60  # the value BEFORE this call overwrote it
    assert record2.id == record1.id
    assert record2.name == "Some Device"  # preserved
    assert record2.last_rssi == -80
    assert record2.first_rssi == -60  # baseline never changes after creation
    assert record2.times_seen == 2
    assert len(peripherals) == 1


def test_set_ble_peripheral_trusted(tmp_path: Path):
    db_path = tmp_path / "test.db"
    uuid_ = "11111111-1111-1111-1111-111111111111"

    with Database(db_path) as db:
        record, *_ = upsert_ble_peripheral(db.conn, cb_uuid=uuid_, name="Some Device", rssi=None)
        assert record.trusted is False

        set_ble_peripheral_trusted(db.conn, record.id, True)
        updated = find_ble_peripheral_by_id(db.conn, record.id)

    assert updated.trusted is True


def test_find_ble_peripheral_by_id_missing_is_none(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert find_ble_peripheral_by_id(db.conn, 9999) is None


def test_add_and_list_ble_alerts(tmp_path: Path):
    db_path = tmp_path / "test.db"
    uuid_ = "11111111-1111-1111-1111-111111111111"

    with Database(db_path) as db:
        alert_id = add_ble_alert(
            db.conn, run_id="run-1", kind="persistent_unknown", severity="low",
            cb_uuid=uuid_, name="Unknown Peripheral", message="test message",
        )
        alerts = list_ble_alerts(db.conn)

    assert len(alerts) == 1
    assert alerts[0].id == alert_id
    assert alerts[0].known is False
    assert alerts[0].severity == "low"


def test_set_ble_alert_known(tmp_path: Path):
    db_path = tmp_path / "test.db"
    uuid_ = "11111111-1111-1111-1111-111111111111"

    with Database(db_path) as db:
        alert_id = add_ble_alert(
            db.conn, run_id="run-1", kind="rssi_significant_change", severity="low",
            cb_uuid=uuid_, name=None, message="test",
        )
        set_ble_alert_known(db.conn, alert_id, True)
        updated = find_ble_alert_by_id(db.conn, alert_id)

    assert updated.known is True


def test_find_ble_alert_by_id_missing_is_none(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert find_ble_alert_by_id(db.conn, 9999) is None


def test_has_ble_alert_of_kind(tmp_path: Path):
    db_path = tmp_path / "test.db"
    uuid_ = "11111111-1111-1111-1111-111111111111"

    with Database(db_path) as db:
        assert has_ble_alert_of_kind(db.conn, uuid_, "persistent_unknown") is False

        add_ble_alert(
            db.conn, run_id="run-1", kind="persistent_unknown", severity="low",
            cb_uuid=uuid_, name=None, message="test",
        )

        assert has_ble_alert_of_kind(db.conn, uuid_, "persistent_unknown") is True
        assert has_ble_alert_of_kind(db.conn, uuid_, "some_other_kind") is False


# ---------- schema migration healing (bluetooth_devices paired/connected) ----------


def test_init_schema_heals_missing_columns_on_an_older_database(tmp_path: Path):
    """Simulate a database created under the OLD bluetooth_devices shape
    (no paired/connected columns) and confirm init_schema() adds them
    without disturbing existing data — the first schema migration this
    project has ever needed. See database.py's _COLUMN_MIGRATIONS.
    """
    import sqlite3

    db_path = tmp_path / "old.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE bluetooth_devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier  TEXT NOT NULL UNIQUE,
            name        TEXT,
            trusted     INTEGER NOT NULL DEFAULT 0,
            times_seen  INTEGER NOT NULL DEFAULT 0,
            last_rssi   INTEGER,
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "INSERT INTO bluetooth_devices (identifier, name, trusted, times_seen, last_rssi, first_seen, last_seen) "
        "VALUES ('aa:bb:cc:dd:ee:ff', 'Old Row', 1, 3, -50, 't0', 't1')"
    )
    conn.commit()

    # Now run the real schema init against this pre-existing, older DB —
    # this is exactly what happens when an existing user's database
    # (created before this migration existed) is opened by the new code.
    init_schema(conn)

    columns = {row["name"] for row in conn.execute("PRAGMA table_info(bluetooth_devices)")}
    assert "paired" in columns
    assert "connected" in columns

    row = conn.execute("SELECT * FROM bluetooth_devices WHERE identifier = 'aa:bb:cc:dd:ee:ff'").fetchone()
    assert row["name"] == "Old Row"  # existing data untouched
    assert row["times_seen"] == 3
    assert row["paired"] == 0  # healed in with the additive default
    assert row["connected"] == 0

    conn.close()


def test_init_schema_column_healing_is_idempotent(tmp_path: Path):
    """Calling init_schema() twice on an already-healed database must
    not error (no 'duplicate column' failure) — same "safe to call
    every run" guarantee the rest of init_schema() already has.
    """
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        init_schema(db.conn)  # second call, same connection
        columns = {row["name"] for row in db.conn.execute("PRAGMA table_info(bluetooth_devices)")}

    assert "paired" in columns
    assert "connected" in columns


# ---------- process_entries / persistence_observations / persistence_entries / persistence_alerts ----------


def test_upsert_process_entry_insert_then_update(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record1, was_new1 = upsert_process_entry(
            db.conn, executable_path="/usr/bin/true", process_name="true",
            run_as_user="root", signing_status="signed_apple",
        )
        assert was_new1 is True
        assert record1.known is False
        assert record1.times_seen == 1
        assert record1.signing_status == "signed_apple"

        # Seen again -- signing_status should NOT change even though a
        # different value is passed, since it's only ever stored at
        # creation time (see upsert_process_entry()'s docstring).
        record2, was_new2 = upsert_process_entry(
            db.conn, executable_path="/usr/bin/true", process_name="true",
            run_as_user="erick", signing_status="unsigned",
        )
        entries = list_process_entries(db.conn)

    assert was_new2 is False
    assert record2.id == record1.id
    assert record2.run_as_user == "erick"  # always overwritten
    assert record2.signing_status == "signed_apple"  # untouched on update
    assert record2.times_seen == 2
    assert len(entries) == 1


def test_upsert_process_entry_preserves_name_when_not_resolved(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        upsert_process_entry(
            db.conn, executable_path="/usr/bin/true", process_name="true", run_as_user="root"
        )
        record, _ = upsert_process_entry(
            db.conn, executable_path="/usr/bin/true", process_name=None, run_as_user="root"
        )

    assert record.process_name == "true"


def test_find_process_entry_by_path(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        assert find_process_entry_by_path(db.conn, "/usr/bin/true") is None
        upsert_process_entry(db.conn, executable_path="/usr/bin/true", process_name="true", run_as_user="root")
        found = find_process_entry_by_path(db.conn, "/usr/bin/true")

    assert found is not None
    assert found.executable_path == "/usr/bin/true"


def test_set_process_entry_known(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record, _ = upsert_process_entry(db.conn, executable_path="/usr/bin/true", process_name="true", run_as_user="root")
        assert record.known is False
        set_process_entry_known(db.conn, record.id, True)
        updated = find_process_entry_by_id(db.conn, record.id)

    assert updated.known is True


def test_find_process_entry_by_id_missing_is_none(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        assert find_process_entry_by_id(db.conn, 9999) is None


def test_add_persistence_observations(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        add_persistence_observations(
            db.conn,
            run_id="run-1",
            rows=[
                ("launch_agent_user", "com.example.agent", "/path/to.plist", "/usr/local/bin/agent", True, False),
                ("login_item", "Dropbox", None, "/Applications/Dropbox.app", None, None),
            ],
        )
        count = db.conn.execute("SELECT COUNT(*) AS n FROM persistence_observations").fetchone()["n"]

    assert count == 2


def test_upsert_persistence_entry_insert_then_update_by_path(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record1, was_new1, prev1 = upsert_persistence_entry(
            db.conn, kind="launch_agent_user", path="/path/to.plist", label="com.example.agent",
            program_path="/usr/local/bin/agent", signing_status="signed_developer",
        )
        assert was_new1 is True
        assert prev1 is None
        assert record1.known is False

        # Seen again -- signing_status IS re-checked/overwritten for
        # persistence entries (unlike process_entries).
        record2, was_new2, prev2 = upsert_persistence_entry(
            db.conn, kind="launch_agent_user", path="/path/to.plist", label=None,
            program_path="/usr/local/bin/agent", signing_status="unsigned",
        )
        entries = list_persistence_entries(db.conn)

    assert was_new2 is False
    assert record2.id == record1.id
    assert record2.label == "com.example.agent"  # preserved, not overwritten with None
    assert prev2 == "signed_developer"  # the value BEFORE this call
    assert record2.signing_status == "unsigned"  # current value, post-update
    assert len(entries) == 1


def test_upsert_persistence_entry_fallback_dedup_by_label_when_no_path(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record1, was_new1, _ = upsert_persistence_entry(
            db.conn, kind="login_item", path=None, label="SomeItem",
            program_path=None, signing_status=None,
        )
        record2, was_new2, _ = upsert_persistence_entry(
            db.conn, kind="login_item", path=None, label="SomeItem",
            program_path=None, signing_status=None,
        )
        entries = list_persistence_entries(db.conn)

    assert was_new1 is True
    assert was_new2 is False
    assert record2.id == record1.id
    assert len(entries) == 1


def test_set_persistence_entry_known(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        record, _, _ = upsert_persistence_entry(
            db.conn, kind="launch_daemon", path="/path/to.plist", label="x",
            program_path="/usr/local/bin/x", signing_status="signed_apple",
        )
        set_persistence_entry_known(db.conn, record.id, True)
        updated = find_persistence_entry_by_id(db.conn, record.id)

    assert updated.known is True


def test_find_persistence_entry_by_id_missing_is_none(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        assert find_persistence_entry_by_id(db.conn, 9999) is None


def test_add_and_list_persistence_alerts(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        alert_id = add_persistence_alert(
            db.conn, run_id="run-1", kind="new_persistence_entry", severity="medium",
            target_type="launch_agent_user", identifier="/path/to.plist",
            label="com.example.agent", message="test message",
        )
        alerts = list_persistence_alerts(db.conn)

    assert len(alerts) == 1
    assert alerts[0].id == alert_id
    assert alerts[0].known is False
    assert alerts[0].severity == "medium"
    assert alerts[0].target_type == "launch_agent_user"


def test_set_persistence_alert_known(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        alert_id = add_persistence_alert(
            db.conn, run_id="run-1", kind="unusual_unsigned_process", severity="high",
            target_type="process", identifier="/tmp/tool", label=None, message="test",
        )
        set_persistence_alert_known(db.conn, alert_id, True)
        updated = find_persistence_alert_by_id(db.conn, alert_id)

    assert updated.known is True


def test_find_persistence_alert_by_id_missing_is_none(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        assert find_persistence_alert_by_id(db.conn, 9999) is None
