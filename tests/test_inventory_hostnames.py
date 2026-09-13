"""
Tests for secure/inventory/hostnames.py (reverse-DNS hostname lookup).

Every other test in this repository that touches `resolve_hostname`
stubs it out at the call site — `tests/test_inventory.py`,
`tests/test_baseline_scanner_wiring.py` and
`tests/test_baseline_gap_filling.py` all monkeypatch
`scanner_module.resolve_hostname` to `lambda ip: None` — so until this
file existed the function's own body had never been executed by the
suite at all. These tests execute it, driving the one seam it has
(`socket.gethostbyaddr`) rather than the network, per TESTING_POLICY
rules 5 and 7.

Run with:  pytest
"""

from __future__ import annotations

import socket

import pytest

import secure.inventory.hostnames as hostnames_module
from secure.inventory.hostnames import resolve_hostname

# ---------- the resolving path ----------


def test_resolve_hostname_returns_the_resolved_name(monkeypatch):
    monkeypatch.setattr(
        hostnames_module.socket,
        "gethostbyaddr",
        lambda ip: ("printer.local", [], [ip]),
    )
    assert resolve_hostname("192.168.1.50") == "printer.local"


def test_resolve_hostname_passes_the_address_through_unchanged(monkeypatch):
    seen = []

    def fake_gethostbyaddr(ip):
        seen.append(ip)
        return ("host.example", [], [ip])

    monkeypatch.setattr(hostnames_module.socket, "gethostbyaddr", fake_gethostbyaddr)
    resolve_hostname("10.0.0.7")
    assert seen == ["10.0.0.7"]


def test_resolve_hostname_returns_only_the_name_not_the_aliases(monkeypatch):
    # gethostbyaddr returns a 3-tuple; only the canonical name is stored
    # on the device record, so the aliases and address list must not leak
    # into the return value.
    monkeypatch.setattr(
        hostnames_module.socket,
        "gethostbyaddr",
        lambda ip: ("nas.local", ["nas", "storage"], ["10.0.0.9"]),
    )
    assert resolve_hostname("10.0.0.9") == "nas.local"


# ---------- honest absence (TESTING_POLICY rule 9) ----------
#
# A device with no PTR record is the normal case for phones and IoT
# gadgets, and a resolver that is unreachable is the degraded one. Both
# come back as None here: this function's contract is best-effort, and
# an inventory scan must not abort because one address would not
# resolve. Each of these is a distinct exception type the platform
# resolver can raise, and each is asserted separately so that narrowing
# the except clause fails loudly.


def _raiser(exc):
    def _raise(ip):
        raise exc

    return _raise


def test_resolve_hostname_returns_none_on_herror(monkeypatch):
    # No PTR record for the address — the common, expected case.
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", _raiser(socket.herror(1, "Unknown host"))
    )
    assert resolve_hostname("192.168.1.99") is None


def test_resolve_hostname_returns_none_on_gaierror(monkeypatch):
    monkeypatch.setattr(
        hostnames_module.socket,
        "gethostbyaddr",
        _raiser(socket.gaierror(8, "nodename nor servname provided")),
    )
    assert resolve_hostname("192.168.1.99") is None


def test_resolve_hostname_returns_none_on_timeout(monkeypatch):
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", _raiser(socket.timeout("timed out"))
    )
    assert resolve_hostname("192.168.1.99") is None


def test_resolve_hostname_returns_none_on_oserror(monkeypatch):
    # e.g. the resolver socket itself is unavailable.
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", _raiser(OSError("network is down"))
    )
    assert resolve_hostname("192.168.1.99") is None


def test_resolve_hostname_does_not_swallow_unrelated_exceptions(monkeypatch):
    # A programming error inside the lookup must surface, not be
    # laundered into "this device has no hostname".
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", _raiser(ValueError("bad argument"))
    )
    with pytest.raises(ValueError):
        resolve_hostname("192.168.1.99")


# ---------- process-global state ----------
#
# scan_network() calls resolve_hostname once per discovered device
# (secure/inventory/scanner.py:120) inside a process that also runs the
# Tkinter GUI, so this function must not leave the process-wide socket
# default timeout altered behind it. Asserted on both exits.


def test_resolve_hostname_leaves_the_global_default_timeout_alone_on_success(monkeypatch):
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", lambda ip: ("host.example", [], [ip])
    )
    before = socket.getdefaulttimeout()
    resolve_hostname("10.0.0.1")
    assert socket.getdefaulttimeout() == before


def test_resolve_hostname_leaves_the_global_default_timeout_alone_on_failure(monkeypatch):
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", _raiser(socket.herror(1, "Unknown host"))
    )
    before = socket.getdefaulttimeout()
    resolve_hostname("10.0.0.1")
    assert socket.getdefaulttimeout() == before


def test_resolve_hostname_restores_a_preexisting_default_timeout(monkeypatch):
    # Not the default None: if the host application had already set a
    # process-wide timeout, an inventory scan must hand it back intact.
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", lambda ip: ("host.example", [], [ip])
    )
    original = socket.getdefaulttimeout()
    socket.setdefaulttimeout(30.0)
    try:
        resolve_hostname("10.0.0.1")
        assert socket.getdefaulttimeout() == 30.0
    finally:
        socket.setdefaulttimeout(original)
