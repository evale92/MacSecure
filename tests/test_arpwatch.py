"""
Tests for secure/arpwatch/* (ARP / Neighbor Table Monitoring).

Sample ARP output and hand-built ArpEntry objects feed straight into
the pure analysis functions, so these don't need a real Mac.
scan_arp_table() itself is tested end-to-end with the shell calls
mocked out, same approach as test_connections.py/test_listening.py.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.arpwatch._shell import ShellResult
from secure.arpwatch.analysis import detect_intra_scan_conflicts, detect_mac_changes, is_real_entry
from secure.arpwatch.gateway import parse_default_gateway
from secure.arpwatch.scanner import scan_arp_table
from secure.inventory.arp_table import ArpEntry
from secure.storage.database import Database
from secure.storage.models import list_arp_alerts, list_arp_mappings

# ---------- parse_default_gateway ----------

_SAMPLE_ROUTE_OUTPUT = """\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC>
"""


def test_parse_default_gateway_extracts_ip():
    assert parse_default_gateway(_SAMPLE_ROUTE_OUTPUT) == "192.168.1.1"


def test_parse_default_gateway_missing_is_none():
    assert parse_default_gateway("nothing useful here") is None


# ---------- is_real_entry ----------


def test_is_real_entry_rejects_incomplete():
    entry = ArpEntry(ip="192.168.1.42", mac=None, hostname=None)
    assert is_real_entry(entry) is False


def test_is_real_entry_rejects_broadcast():
    entry = ArpEntry(ip="192.168.1.255", mac="ff:ff:ff:ff:ff:ff", hostname=None)
    assert is_real_entry(entry) is False


def test_is_real_entry_rejects_multicast():
    entry = ArpEntry(ip="224.0.0.251", mac="01:00:5e:00:00:fb", hostname=None)
    assert is_real_entry(entry) is False


def test_is_real_entry_accepts_normal():
    entry = ArpEntry(ip="192.168.1.50", mac="a4:83:e7:12:34:56", hostname=None)
    assert is_real_entry(entry) is True


# ---------- detect_intra_scan_conflicts ----------


def test_detect_intra_scan_conflicts_finds_two_macs_for_one_ip():
    entries = [
        ArpEntry(ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa", hostname=None),
        ArpEntry(ip="192.168.1.1", mac="bb:bb:bb:bb:bb:bb", hostname=None),
    ]
    alerts = detect_intra_scan_conflicts(entries, gateway_ip=None)
    assert len(alerts) == 1
    assert alerts[0].kind == "ip_conflict"
    assert alerts[0].severity == "medium"
    assert alerts[0].ip == "192.168.1.1"


def test_detect_intra_scan_conflicts_notes_gateway_in_message():
    entries = [
        ArpEntry(ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa", hostname=None),
        ArpEntry(ip="192.168.1.1", mac="bb:bb:bb:bb:bb:bb", hostname=None),
    ]
    alerts = detect_intra_scan_conflicts(entries, gateway_ip="192.168.1.1")
    assert "gateway" in alerts[0].message.lower()


def test_detect_intra_scan_conflicts_no_conflict_when_consistent():
    entries = [
        ArpEntry(ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa", hostname=None),
        ArpEntry(ip="192.168.1.2", mac="bb:bb:bb:bb:bb:bb", hostname=None),
    ]
    assert detect_intra_scan_conflicts(entries, gateway_ip=None) == []


def test_detect_intra_scan_conflicts_duplicate_lines_same_mac_is_fine():
    # e.g. the same device resolved once with a hostname, once without
    entries = [
        ArpEntry(ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa", hostname=None),
        ArpEntry(ip="192.168.1.1", mac="aa:aa:aa:aa:aa:aa", hostname="gateway.local"),
    ]
    assert detect_intra_scan_conflicts(entries, gateway_ip=None) == []


# ---------- detect_mac_changes ----------


def test_detect_mac_changes_flags_a_changed_ip():
    current = {"192.168.1.50": "bb:bb:bb:bb:bb:bb"}
    previous = {"192.168.1.50": "aa:aa:aa:aa:aa:aa"}
    alerts = detect_mac_changes(current, previous, gateway_ip=None)
    assert len(alerts) == 1
    assert alerts[0].kind == "mac_changed"
    assert alerts[0].severity == "low"
    assert alerts[0].previous_mac == "aa:aa:aa:aa:aa:aa"
    assert alerts[0].mac == "bb:bb:bb:bb:bb:bb"


def test_detect_mac_changes_gateway_change_is_high_severity():
    current = {"192.168.1.1": "bb:bb:bb:bb:bb:bb"}
    previous = {"192.168.1.1": "aa:aa:aa:aa:aa:aa"}
    alerts = detect_mac_changes(current, previous, gateway_ip="192.168.1.1")
    assert alerts[0].kind == "gateway_mac_changed"
    assert alerts[0].severity == "high"
    assert "gateway" in alerts[0].message.lower()


def test_detect_mac_changes_unchanged_mac_is_not_flagged():
    current = {"192.168.1.50": "aa:aa:aa:aa:aa:aa"}
    previous = {"192.168.1.50": "aa:aa:aa:aa:aa:aa"}
    assert detect_mac_changes(current, previous, gateway_ip=None) == []


def test_detect_mac_changes_brand_new_ip_is_not_flagged():
    """A new IP appearing is inventory's job, not arpwatch's."""
    current = {"192.168.1.99": "aa:aa:aa:aa:aa:aa"}
    previous = {}
    assert detect_mac_changes(current, previous, gateway_ip=None) == []


# ---------- scan_arp_table (end-to-end, shell mocked) ----------

_FAKE_ARP_OUTPUT = """\
? (192.168.1.1) at aa:aa:aa:aa:aa:aa on en0 ifscope [ethernet]
laptop.local (192.168.1.50) at bb:bb:bb:bb:bb:bb on en0 ifscope [ethernet]
"""

_FAKE_ROUTE_OUTPUT = """\
   route to: default
    gateway: 192.168.1.1
  interface: en0
"""


def _patch_shells(monkeypatch, arp_stdout, route_stdout=_FAKE_ROUTE_OUTPUT):
    import secure.arpwatch.scanner as scanner_module
    import secure.arpwatch.gateway as gateway_module

    monkeypatch.setattr(
        scanner_module, "run", lambda *a, **k: ShellResult(ok=True, stdout=arp_stdout, stderr="", returncode=0)
    )
    monkeypatch.setattr(
        gateway_module, "run", lambda *a, **k: ShellResult(ok=True, stdout=route_stdout, stderr="", returncode=0)
    )


def test_scan_arp_table_first_scan_has_no_alerts(tmp_path: Path, monkeypatch):
    _patch_shells(monkeypatch, _FAKE_ARP_OUTPUT)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_arp_table(db.conn)
        mappings = list_arp_mappings(db.conn)

    assert result.arp_available is True
    assert result.gateway_ip == "192.168.1.1"
    assert len(result.entries) == 2
    assert result.alerts == []
    assert len(mappings) == 2
    gateway_row = next(m for m in mappings if m.ip == "192.168.1.1")
    assert gateway_row.is_gateway is True


def test_scan_arp_table_detects_gateway_mac_change(tmp_path: Path, monkeypatch):
    second_arp = _FAKE_ARP_OUTPUT.replace("aa:aa:aa:aa:aa:aa", "cc:cc:cc:cc:cc:cc")

    calls = {"n": 0}

    def fake_run(*a, **k):
        calls["n"] += 1
        stdout = _FAKE_ARP_OUTPUT if calls["n"] == 1 else second_arp
        return ShellResult(ok=True, stdout=stdout, stderr="", returncode=0)

    import secure.arpwatch.scanner as scanner_module
    import secure.arpwatch.gateway as gateway_module

    monkeypatch.setattr(scanner_module, "run", fake_run)
    monkeypatch.setattr(
        gateway_module, "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_FAKE_ROUTE_OUTPUT, stderr="", returncode=0),
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        first = scan_arp_table(db.conn)
        second = scan_arp_table(db.conn)
        alerts = list_arp_alerts(db.conn)

    assert first.alerts == []
    assert len(second.alerts) == 1
    assert second.alerts[0].kind == "gateway_mac_changed"
    assert second.alerts[0].severity == "high"
    assert second.alerts[0].id is not None
    assert len(alerts) == 1
    assert alerts[0].known is False  # unreviewed by default


def test_scan_arp_table_detects_intra_scan_conflict(tmp_path: Path, monkeypatch):
    conflicting_arp = (
        "? (192.168.1.1) at aa:aa:aa:aa:aa:aa on en0 ifscope [ethernet]\n"
        "? (192.168.1.1) at dd:dd:dd:dd:dd:dd on en0 ifscope [ethernet]\n"
    )
    _patch_shells(monkeypatch, conflicting_arp)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_arp_table(db.conn)

    assert len(result.alerts) == 1
    assert result.alerts[0].kind == "ip_conflict"


def test_scan_arp_table_arp_unavailable(tmp_path: Path, monkeypatch):
    import secure.arpwatch.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(ok=False, stdout="", stderr="command not found", returncode=None),
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_arp_table(db.conn)

    assert result.arp_available is False
    assert result.entries == []
    assert result.alerts == []
