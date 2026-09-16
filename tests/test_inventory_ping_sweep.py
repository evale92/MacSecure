"""
Tests for the active half of secure/inventory: ping_sweep.py, the
do_ping_sweep gate in scanner.scan_network(), and the /24 clamp in
network_info.get_local_subnet() that bounds what a sweep may touch.

Every scan_network() test elsewhere stubs get_local_subnet() to None,
so the sweep branch was never entered. Three mutants survived all 138
tests in the eight files that reference secure.inventory (J-0579):

  - scanner.py `subnet is not None and do_ping_sweep` -> `subnet is not None`
    (`secure inventory scan --no-ping-sweep` would still send ICMP)
  - ping_sweep.py's `run([...])` replaced by an undefined name
    (the function body had never run)
  - network_info.py's `prefix_len = 24` replaced by `pass`

No test here sends a packet: `run` is rebound on the module that bound
it at import, so nothing reaches /sbin/ping, route or ifconfig.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

import secure.inventory.network_info as network_info_module
import secure.inventory.ping_sweep as ping_sweep_module
import secure.inventory.scanner as scanner_module
from secure.inventory._shell import ShellResult
from secure.inventory.hostnames import NO_RECORD, HostnameLookup
from secure.inventory.network_info import LocalSubnet, get_local_subnet
from secure.inventory.ping_sweep import ping_sweep
from secure.storage.database import Database


def _ok(stdout: str = "") -> ShellResult:
    return ShellResult(ok=True, stdout=stdout, stderr="", returncode=0)


# ---------- ping_sweep(): one echo per host, time-bounded ----------


def test_ping_sweep_sends_exactly_one_bounded_echo_per_host(monkeypatch):
    calls = []
    monkeypatch.setattr(
        ping_sweep_module, "run", lambda args, timeout: calls.append((args, timeout)) or _ok()
    )
    hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

    ping_sweep(hosts, timeout_seconds=2, max_workers=2)

    assert sorted(calls) == sorted(
        (["ping", "-c", "1", "-t", "2", host], 3) for host in hosts
    )


def test_ping_sweep_with_no_hosts_runs_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(ping_sweep_module, "run", lambda *a, **k: calls.append(a) or _ok())

    ping_sweep([])

    assert calls == []


# ---------- scan_network(): the sweep is something the operator requests ----------


def _scan(tmp_path: Path, monkeypatch, **kwargs):
    swept = []
    subnet = LocalSubnet(interface="en0", local_ip="192.168.1.23", prefix_len=24)
    monkeypatch.setattr(scanner_module, "get_local_subnet", lambda: subnet)
    monkeypatch.setattr(scanner_module, "read_arp_table_with_availability", lambda: ([], True))
    monkeypatch.setattr(
        scanner_module, "resolve_hostname_with_status", lambda ip: HostnameLookup(None, NO_RECORD)
    )
    monkeypatch.setattr(
        scanner_module, "ping_sweep", lambda hosts, **k: swept.append((list(hosts), k))
    )
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_network(db.conn, **kwargs)
    return result, swept, subnet


def test_scan_network_does_not_sweep_when_the_operator_declines(tmp_path: Path, monkeypatch):
    result, swept, _ = _scan(tmp_path, monkeypatch, do_ping_sweep=False)

    assert swept == []
    assert result.ping_sweep_performed is False


def test_scan_network_sweeps_the_detected_subnet_when_asked(tmp_path: Path, monkeypatch):
    # Positive control for the test above: with a subnet present, the
    # stub is reachable, so its silence there is the gate and not a
    # stub that is never called.
    result, swept, subnet = _scan(
        tmp_path, monkeypatch, ping_timeout_seconds=4, max_ping_workers=7
    )

    assert swept == [(subnet.hosts(), {"timeout_seconds": 4, "max_workers": 7})]
    assert result.ping_sweep_performed is True


# ---------- get_local_subnet(): a sweep never exceeds a /24 ----------


def _fake_commands(netmask: str):
    outputs = {
        "route": "   route to: default\ninterface: en0\n",
        "ifconfig": f"en0: flags=8863<UP>\n\tinet 10.20.30.40 netmask {netmask} broadcast 10.20.255.255\n",
    }
    return lambda args, timeout=5.0: _ok(outputs[args[0]])


def test_get_local_subnet_clamps_a_wider_network_to_24(monkeypatch):
    monkeypatch.setattr(network_info_module, "run", _fake_commands("0xffff0000"))

    subnet = get_local_subnet()

    assert subnet == LocalSubnet(interface="en0", local_ip="10.20.30.40", prefix_len=24)
    assert all(host.startswith("10.20.30.") for host in subnet.hosts())


def test_get_local_subnet_keeps_a_narrower_prefix(monkeypatch):
    monkeypatch.setattr(network_info_module, "run", _fake_commands("0xfffffff0"))

    assert get_local_subnet().prefix_len == 28


def test_get_local_subnet_is_none_when_route_fails(monkeypatch):
    monkeypatch.setattr(
        network_info_module,
        "run",
        lambda args, timeout=5.0: ShellResult(ok=False, stdout="", stderr="x", returncode=1),
    )

    assert get_local_subnet() is None
