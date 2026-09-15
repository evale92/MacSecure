"""
Tests for secure/inventory/hostnames.py (reverse-DNS hostname lookup).

Every other test in this repository that touches this module stubs it
out at the call site — `tests/test_inventory.py`,
`tests/test_baseline_scanner_wiring.py` and
`tests/test_baseline_gap_filling.py` all monkeypatch
`scanner_module.resolve_hostname_with_status` — so until this file
existed the function's own body had never been executed by the suite
at all. These tests execute it, driving the one seam it has
(`socket.gethostbyaddr`) rather than the network, per TESTING_POLICY
rules 5 and 7.

Run with:  pytest
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

import secure.inventory.hostnames as hostnames_module
from secure.inventory.hostnames import (
    ERROR,
    NO_RECORD,
    RESOLVED,
    TIMED_OUT,
    resolve_hostname,
    resolve_hostname_with_status,
)

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


# ---------- the deadline, and whether it binds (J-0187) ----------
#
# The old body set socket.setdefaulttimeout(timeout) around the call.
# That is documented to affect newly created socket objects only, and
# socket.gethostbyaddr() goes through the platform resolver in C
# without creating one — so the timeout bounded nothing, and a lookup
# that hung held up the whole serial scan. These drive a lookup that
# never returns: under the old body every one of them would hang
# forever, which is what makes them a real check rather than a
# restatement of the code.


def _blocking_gethostbyaddr(release: threading.Event, entered: threading.Event):
    def _blocked(ip):
        entered.set()
        release.wait(30.0)
        return ("late.example", [], [ip])

    return _blocked


def test_lookup_that_never_returns_is_abandoned_at_the_deadline(monkeypatch):
    release = threading.Event()
    entered = threading.Event()
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", _blocking_gethostbyaddr(release, entered)
    )
    try:
        result = resolve_hostname_with_status("10.0.0.5", timeout=0.05)
        # Waited on rather than sampled: under a loaded full-suite run
        # the worker may not be scheduled within the deadline, and
        # "the thread had not started yet" is not the thing being
        # asserted here — that the lookup ran and was abandoned is.
        assert entered.wait(10.0)
        assert result.status == TIMED_OUT
        assert result.hostname is None
    finally:
        release.set()


def test_the_caller_stops_waiting_rather_than_hanging(monkeypatch):
    # Not a tight timing assertion (TESTING_POLICY rule 6): the bound is
    # deliberately 100x the deadline, because what is being established
    # is "returns at all", not "returns in exactly 0.05s".
    release = threading.Event()
    entered = threading.Event()
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", _blocking_gethostbyaddr(release, entered)
    )
    try:
        started = time.monotonic()
        resolve_hostname_with_status("10.0.0.5", timeout=0.05)
        assert time.monotonic() - started < 5.0
    finally:
        release.set()


def test_the_deadline_waited_on_is_the_one_the_caller_asked_for(monkeypatch):
    # The whole defect this replaced was a `timeout` parameter that
    # reached nothing. "Some bound exists" is not enough to catch that
    # coming back: a hard-coded wait passes every elapsed-time check
    # below it, so assert the caller's own value is what gets waited on.
    joins = []
    real_thread = hostnames_module.threading.Thread

    class _RecordingThread(real_thread):
        def join(self, timeout=None):
            joins.append(timeout)
            return super().join(timeout)

    monkeypatch.setattr(hostnames_module.threading, "Thread", _RecordingThread)
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", lambda ip: ("host.example", [], [ip])
    )
    resolve_hostname_with_status("10.0.0.1", timeout=0.25)
    assert joins == [0.25]


def test_a_late_answer_does_not_become_the_result(monkeypatch):
    # The abandoned worker eventually finishes with a name. That name
    # belongs to nobody: the call already returned TIMED_OUT, and the
    # plain-string wrapper must not hand back a hostname either.
    release = threading.Event()
    entered = threading.Event()
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", _blocking_gethostbyaddr(release, entered)
    )
    try:
        assert resolve_hostname("10.0.0.5", timeout=0.05) is None
    finally:
        release.set()


# ---------- a timeout is not "no PTR record" (invariant 5) ----------
#
# Both come back without a hostname. One is a phone with no reverse-DNS
# entry, which is ordinary; the other is a sensor that did not answer.
# Invariant 5 forbids the second being indistinguishable from the first,
# and `hostname is None` alone cannot tell them apart — which is exactly
# why the status exists.


def test_no_record_and_timeout_are_distinguishable(monkeypatch):
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", _raiser(socket.herror(1, "Unknown host"))
    )
    no_record = resolve_hostname_with_status("192.168.1.99")

    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", _raiser(socket.timeout("timed out"))
    )
    timed_out = resolve_hostname_with_status("192.168.1.99")

    assert no_record.hostname is None and timed_out.hostname is None
    assert no_record.status != timed_out.status
    assert no_record.degraded is False  # the device simply has no name
    assert timed_out.degraded is True  # the lookup failed; say so


def test_status_resolved_carries_the_name_and_is_not_degraded(monkeypatch):
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", lambda ip: ("printer.local", [], [ip])
    )
    result = resolve_hostname_with_status("192.168.1.50")
    assert result == hostnames_module.HostnameLookup("printer.local", RESOLVED)
    assert result.degraded is False


def test_gaierror_is_no_record_not_a_sensor_failure(monkeypatch):
    monkeypatch.setattr(
        hostnames_module.socket,
        "gethostbyaddr",
        _raiser(socket.gaierror(8, "nodename nor servname provided")),
    )
    result = resolve_hostname_with_status("192.168.1.99")
    assert result.status == NO_RECORD
    assert result.degraded is False


def test_an_unusable_resolver_is_error_and_degraded(monkeypatch):
    # e.g. the resolver socket itself is unavailable — that is the
    # sensor failing, not the address lacking a name.
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", _raiser(OSError("network is down"))
    )
    result = resolve_hostname_with_status("192.168.1.99")
    assert result.status == ERROR
    assert result.degraded is True


def test_unrelated_exception_crosses_back_out_of_the_worker(monkeypatch):
    # The lookup now runs on another thread. A programming error raised
    # there must still reach the caller rather than be swallowed into a
    # quiet "no hostname" — the same contract the plain wrapper has.
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", _raiser(ValueError("bad argument"))
    )
    with pytest.raises(ValueError):
        resolve_hostname_with_status("192.168.1.99")


def test_the_worker_thread_never_outlives_the_interpreter(monkeypatch):
    # A lookup stuck in the platform resolver cannot be cancelled from
    # Python, so the only thing keeping it from blocking interpreter
    # exit is that the thread is a daemon.
    seen = []
    real_thread = hostnames_module.threading.Thread

    def _record(*args, **kwargs):
        thread = real_thread(*args, **kwargs)
        seen.append(thread)
        return thread

    monkeypatch.setattr(hostnames_module.threading, "Thread", _record)
    monkeypatch.setattr(
        hostnames_module.socket, "gethostbyaddr", lambda ip: ("host.example", [], [ip])
    )
    resolve_hostname_with_status("10.0.0.1")
    assert len(seen) == 1
    assert seen[0].daemon is True
