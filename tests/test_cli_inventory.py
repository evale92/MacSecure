"""
Tests for `secure/cli/inventory.py`'s identifier lookup — `secure
inventory mark <ip-or-mac>` and `secure inventory name <ip-or-mac>`.

Why this file exists (J-0339). A device's MAC is stored the way
`secure/inventory/arp_table.py::normalize_mac()` writes it: lowercase,
colon-separated, zero-padded. That function's own docstring says why the
padding is needed — macOS `arp -a` "often omits leading zeros, e.g.
ac:de:48:0:11:22". But the CLI handed the operator's identifier straight
to `find_device_by_identifier()`, which only lowercases it. Measured at
b26da14 against a device stored from exactly that arp line: the padded
MAC marked it (exit 0); the MAC as `arp -a` printed it, and the same MAC
dash-separated, both exited 1 with "No device found" for a device that
was in the table. No test named any `cmd_inventory_*` handler, so
nothing had ever asked.

The stored MAC in these tests comes from running a real `arp -a` line
through `parse_arp_output()`, not from a hand-typed padded string, so
the tests exercise the same normalization the scanner applies rather
than an assumption about it.

The negative cases matter as much as the positive ones: normalizing
the input must not make a *different* MAC match, must not disturb IP
lookup, and a miss must still exit 1 and change nothing — `mark known`
is the action that makes a device trusted, so a lookup that matched too
loosely would be worse than one that matched too strictly.

Run with:  pytest tests/test_cli_inventory.py
"""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path

from secure import cli
from secure.cli import inventory as cli_inventory
from secure.config import load_config
from secure.inventory.arp_table import parse_arp_output
from secure.storage.database import Database
from secure.storage.models import list_devices, upsert_device

ARP_LINE = "gateway.local (192.168.1.1) at ac:de:48:0:11:22 on en0 ifscope [ethernet]"
OTHER_LINE = "? (192.168.1.2) at ac:de:48:0:11:23 on en0 ifscope [ethernet]"


def _bootstrap_to_tmp(monkeypatch, tmp_path: Path):
    """Point `_bootstrap()` at an isolated temp app_dir, never ~/.secure.
    Same approach as tests/test_cli_wifi.py."""
    monkeypatch.setattr(cli, "load_config", lambda: load_config(app_dir=tmp_path))
    return load_config(app_dir=tmp_path)


def _run(fn, *args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*args)
    return rc, buf.getvalue()


def _store_from_arp(cfg, *lines: str) -> None:
    with Database(cfg.database_path()) as db:
        for entry in parse_arp_output("\n".join(lines)):
            upsert_device(db.conn, ip=entry.ip, mac=entry.mac, hostname=None, vendor=None)


def _devices_by_ip(cfg) -> dict:
    with Database(cfg.database_path()) as db:
        return {d.ip: d for d in list_devices(db.conn)}


def test_stored_mac_is_the_zero_padded_form(monkeypatch, tmp_path):
    """The premise of every test below: the scanner stores the padded MAC,
    so the arp-printed form is a different string from what is stored."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _store_from_arp(cfg, ARP_LINE)
    assert _devices_by_ip(cfg)["192.168.1.1"].mac == "ac:de:48:00:11:22"


def test_mark_accepts_the_mac_exactly_as_arp_prints_it(monkeypatch, tmp_path):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _store_from_arp(cfg, ARP_LINE)

    rc, out = _run(
        cli_inventory.cmd_inventory_mark,
        argparse.Namespace(identifier="ac:de:48:0:11:22", status="known"),
    )

    assert rc == 0, out
    assert "No device found" not in out
    assert _devices_by_ip(cfg)["192.168.1.1"].known is True


def test_name_accepts_an_uppercase_dash_separated_mac(monkeypatch, tmp_path):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _store_from_arp(cfg, ARP_LINE)

    rc, out = _run(
        cli_inventory.cmd_inventory_name,
        argparse.Namespace(identifier="AC-DE-48-00-11-22", name="Router"),
    )

    assert rc == 0, out
    assert _devices_by_ip(cfg)["192.168.1.1"].friendly_name == "Router"


def test_normalized_mac_marks_only_the_device_it_names(monkeypatch, tmp_path):
    """Two devices one octet apart: normalizing the input must select
    exactly the addressed one, and leave its neighbour untouched."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _store_from_arp(cfg, ARP_LINE, OTHER_LINE)

    rc, _ = _run(
        cli_inventory.cmd_inventory_mark,
        argparse.Namespace(identifier="AC:DE:48:0:11:23", status="known"),
    )

    devices = _devices_by_ip(cfg)
    assert rc == 0
    assert devices["192.168.1.2"].known is True
    assert devices["192.168.1.1"].known is False


def test_ip_identifier_still_matches(monkeypatch, tmp_path):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _store_from_arp(cfg, ARP_LINE)

    rc, out = _run(
        cli_inventory.cmd_inventory_mark,
        argparse.Namespace(identifier="192.168.1.1", status="known"),
    )

    assert rc == 0, out
    assert _devices_by_ip(cfg)["192.168.1.1"].known is True


def test_unknown_mac_exits_one_and_changes_nothing(monkeypatch, tmp_path):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _store_from_arp(cfg, ARP_LINE)

    rc, out = _run(
        cli_inventory.cmd_inventory_mark,
        argparse.Namespace(identifier="ac:de:48:0:11:99", status="known"),
    )

    assert rc == 1
    assert "No device found matching 'ac:de:48:0:11:99'" in out
    assert _devices_by_ip(cfg)["192.168.1.1"].known is False
