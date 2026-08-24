"""
Tests for secure/inventory/* (Local Device Inventory).

These feed sample real-world command output straight into the pure
parsing functions, so they don't need to run on a Mac or invoke real
`arp`/`ifconfig`/`route`/`ping`. scan_network() itself is tested with
the discovery functions monkeypatched out, for the same reason.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.inventory.arp_table import ArpEntry, normalize_mac, parse_arp_output
from secure.inventory.network_info import (
    LocalSubnet,
    _parse_default_interface,
    _parse_ifconfig_inet,
)
from secure.inventory.scanner import _is_real_device, scan_network
from secure.inventory.vendor import lookup_vendor
from secure.storage.database import Database
from secure.storage.models import delete_junk_devices, list_devices, upsert_device

# ---------- normalize_mac ----------


def test_normalize_mac_pads_and_lowercases():
    assert normalize_mac("AC:DE:48:0:11:22") == "ac:de:48:00:11:22"


def test_normalize_mac_accepts_dashes():
    assert normalize_mac("AC-DE-48-00-11-22") == "ac:de:48:00:11:22"


# ---------- parse_arp_output ----------

_SAMPLE_ARP_OUTPUT = """\
? (192.168.1.1) at ac:de:48:0:11:22 on en0 ifscope [ethernet]
gateway.local (192.168.1.1) at ac:de:48:0:11:22 on en0 ifscope [ethernet]
? (192.168.1.42) at (incomplete) on en0 ifscope [ethernet]
laptop.local (192.168.1.50) at a4:83:e7:12:34:56 on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""


def test_parse_arp_output_extracts_entries():
    entries = parse_arp_output(_SAMPLE_ARP_OUTPUT)

    # Two separate lines for the same IP: one unresolved ("?"), one
    # resolved to "gateway.local" — parse_arp_output returns both as
    # distinct entries; deduping is upsert_device()'s job, not this
    # function's.
    gateway_entries = [e for e in entries if e.ip == "192.168.1.1"]
    assert len(gateway_entries) == 2
    assert gateway_entries[0].hostname is None
    assert gateway_entries[1].hostname == "gateway.local"
    assert gateway_entries[0].mac == gateway_entries[1].mac == "ac:de:48:00:11:22"

    laptop = next(e for e in entries if e.ip == "192.168.1.50")
    assert laptop.hostname == "laptop.local"
    assert laptop.mac == "a4:83:e7:12:34:56"


def test_parse_arp_output_marks_incomplete_as_no_mac():
    entries = parse_arp_output(_SAMPLE_ARP_OUTPUT)
    entry = next(e for e in entries if e.ip == "192.168.1.42")
    assert entry.mac is None


def test_parse_arp_output_unresolved_host_is_none():
    entries = parse_arp_output(_SAMPLE_ARP_OUTPUT)
    entry = next(e for e in entries if e.ip == "224.0.0.251")
    assert entry.hostname is None


def test_parse_arp_output_ignores_garbage_lines():
    entries = parse_arp_output("not an arp line\n\n   \nHostname mapping cleared")
    assert entries == []


# ---------- network_info parsing ----------

_SAMPLE_ROUTE_OUTPUT = """\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC>
"""


def test_parse_default_interface():
    assert _parse_default_interface(_SAMPLE_ROUTE_OUTPUT) == "en0"


def test_parse_default_interface_missing():
    assert _parse_default_interface("nothing useful here") is None


_SAMPLE_IFCONFIG_OUTPUT = """\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=6463<RXCSUM,TXCSUM,TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
	ether ac:de:48:00:11:22
	inet6 fe80::1%en0 prefixlen 64 secured scopeid 0x6
	inet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
	nd6 options=201<PERFORMNUD,DAD>
	media: autoselect
	status: active
"""


def test_parse_ifconfig_inet():
    result = _parse_ifconfig_inet(_SAMPLE_IFCONFIG_OUTPUT)
    assert result == ("192.168.1.23", 24)


def test_parse_ifconfig_inet_missing():
    assert _parse_ifconfig_inet("no inet line here") is None


def test_parse_ifconfig_inet_ignores_inet6():
    text = "\tinet6 fe80::1%en0 prefixlen 64 secured scopeid 0x6\n"
    assert _parse_ifconfig_inet(text) is None


# ---------- LocalSubnet.hosts ----------


def test_local_subnet_hosts_excludes_self_network_and_broadcast():
    subnet = LocalSubnet(interface="en0", local_ip="192.168.1.23", prefix_len=24)
    hosts = subnet.hosts()

    assert "192.168.1.23" not in hosts  # self excluded
    assert "192.168.1.0" not in hosts  # network address
    assert "192.168.1.255" not in hosts  # broadcast address
    assert "192.168.1.1" in hosts
    assert len(hosts) == 253


def test_local_subnet_hosts_respects_max_hosts():
    subnet = LocalSubnet(interface="en0", local_ip="10.0.0.5", prefix_len=16)
    hosts = subnet.hosts(max_hosts=10)
    assert len(hosts) == 10


# ---------- vendor lookup ----------


def test_lookup_vendor_known_prefix():
    assert lookup_vendor("b8:27:eb:11:22:33") == "Raspberry Pi Foundation"


def test_lookup_vendor_is_case_insensitive():
    assert lookup_vendor("B8:27:EB:11:22:33") == "Raspberry Pi Foundation"


def test_lookup_vendor_unknown_prefix_is_none():
    assert lookup_vendor("11:22:33:44:55:66") is None


def test_lookup_vendor_none_mac_is_none():
    assert lookup_vendor(None) is None


# ---------- scan_network (end-to-end, discovery mocked) ----------


def test_scan_network_records_devices_and_flags_new_ones(tmp_path: Path, monkeypatch):
    import secure.inventory.scanner as scanner_module

    fake_entries = [
        ArpEntry(ip="192.168.1.1", mac="ac:de:48:00:11:22", hostname="gateway.local"),
        ArpEntry(ip="192.168.1.50", mac="a4:83:e7:12:34:56", hostname=None),
    ]

    monkeypatch.setattr(scanner_module, "get_local_subnet", lambda: None)
    monkeypatch.setattr(scanner_module, "read_arp_table_with_availability", lambda: (fake_entries, True))
    monkeypatch.setattr(scanner_module, "resolve_hostname", lambda ip: None)
    monkeypatch.setattr(scanner_module, "ping_sweep", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("ping_sweep should not run when get_local_subnet() returns None")
    ))

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_network(db.conn)
        devices = list_devices(db.conn)

    assert result.subnet is None
    assert result.ping_sweep_performed is False
    assert len(result.devices) == 2
    assert len(result.new_devices) == 2  # first time seeing both
    assert len(devices) == 2

    gateway = next(r for r, _ in result.devices if r.ip == "192.168.1.1")
    assert gateway.vendor == "Apple"


def test_scan_network_second_scan_has_no_new_devices(tmp_path: Path, monkeypatch):
    import secure.inventory.scanner as scanner_module

    fake_entries = [ArpEntry(ip="192.168.1.1", mac="ac:de:48:00:11:22", hostname="gateway.local")]

    monkeypatch.setattr(scanner_module, "get_local_subnet", lambda: None)
    monkeypatch.setattr(scanner_module, "read_arp_table_with_availability", lambda: (fake_entries, True))
    monkeypatch.setattr(scanner_module, "resolve_hostname", lambda ip: None)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        first = scan_network(db.conn)
        second = scan_network(db.conn)

    assert len(first.new_devices) == 1
    assert len(second.new_devices) == 0


# ---------- _is_real_device filtering (the "256 fake devices" bugfix) ----------


def test_is_real_device_rejects_incomplete_entry():
    entry = ArpEntry(ip="192.168.1.42", mac=None, hostname=None)
    assert _is_real_device(entry) is False


def test_is_real_device_rejects_broadcast_mac():
    entry = ArpEntry(ip="192.168.1.255", mac="ff:ff:ff:ff:ff:ff", hostname=None)
    assert _is_real_device(entry) is False


def test_is_real_device_rejects_multicast_ip():
    entry = ArpEntry(ip="224.0.0.251", mac="01:00:5e:00:00:fb", hostname="mdns.mcast.net")
    assert _is_real_device(entry) is False


def test_is_real_device_accepts_normal_entry():
    entry = ArpEntry(ip="192.168.1.50", mac="a4:83:e7:12:34:56", hostname=None)
    assert _is_real_device(entry) is True


def test_scan_network_filters_out_incomplete_and_broadcast_entries(tmp_path: Path, monkeypatch):
    import secure.inventory.scanner as scanner_module

    fake_entries = [
        ArpEntry(ip="192.168.1.1", mac="ac:de:48:00:11:22", hostname="gateway.local"),
        ArpEntry(ip="192.168.1.2", mac=None, hostname=None),  # incomplete — nothing there
        ArpEntry(ip="192.168.1.3", mac=None, hostname=None),  # incomplete — nothing there
        ArpEntry(ip="192.168.1.255", mac="ff:ff:ff:ff:ff:ff", hostname=None),  # broadcast
        ArpEntry(ip="224.0.0.251", mac="01:00:5e:00:00:fb", hostname="mdns.mcast.net"),  # multicast
    ]

    monkeypatch.setattr(scanner_module, "get_local_subnet", lambda: None)
    monkeypatch.setattr(scanner_module, "read_arp_table_with_availability", lambda: (fake_entries, True))
    monkeypatch.setattr(scanner_module, "resolve_hostname", lambda ip: None)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_network(db.conn)
        devices = list_devices(db.conn)

    assert result.raw_arp_rows == 5
    assert len(result.devices) == 1  # only the real gateway entry
    assert result.filtered_out == 4
    assert len(devices) == 1
    assert devices[0].ip == "192.168.1.1"


def test_scan_network_arp_unavailable_is_not_a_false_clean(tmp_path: Path, monkeypatch):
    """Phase 29 Stage 5: `arp` failing to run entirely must never look
    like a clean 'zero devices on the network' scan — see
    secure/inventory/arp_table.py's read_arp_table_with_availability()
    and secure/arpwatch/scanner.py's own arp_available field, which this
    mirrors.
    """
    import secure.inventory.scanner as scanner_module

    monkeypatch.setattr(scanner_module, "get_local_subnet", lambda: None)
    monkeypatch.setattr(scanner_module, "read_arp_table_with_availability", lambda: ([], False))
    monkeypatch.setattr(scanner_module, "resolve_hostname", lambda ip: None)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_network(db.conn)

    assert result.arp_available is False
    assert result.devices == []


# ---------- delete_junk_devices (cleanup for rows written before filtering existed) ----------


def test_delete_junk_devices_removes_only_junk(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        # A real device, plus three rows that predate the scanner-level
        # filter (this is exactly what earlier broken scans wrote).
        upsert_device(db.conn, ip="192.168.1.50", mac="a4:83:e7:12:34:56", hostname=None, vendor=None)
        upsert_device(db.conn, ip="192.168.1.2", mac=None, hostname=None, vendor=None)
        upsert_device(db.conn, ip="192.168.1.255", mac="ff:ff:ff:ff:ff:ff", hostname=None, vendor=None)
        upsert_device(db.conn, ip="224.0.0.251", mac="01:00:5e:00:00:fb", hostname=None, vendor=None)

        removed = delete_junk_devices(db.conn)
        remaining = list_devices(db.conn)

    assert removed == 3
    assert len(remaining) == 1
    assert remaining[0].ip == "192.168.1.50"


def test_delete_junk_devices_no_junk_returns_zero(tmp_path: Path):
    db_path = tmp_path / "test.db"

    with Database(db_path) as db:
        upsert_device(db.conn, ip="192.168.1.50", mac="a4:83:e7:12:34:56", hostname=None, vendor=None)
        removed = delete_junk_devices(db.conn)

    assert removed == 0
