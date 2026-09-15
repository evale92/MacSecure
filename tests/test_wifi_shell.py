"""
Tests for secure/wifi/_shell.py — the single place the wifi package
runs a subprocess.

No test imported `run` from this module before this file:
tests/test_wifi.py imports only `ShellResult` and patches `run` out on
both `secure.wifi.status` and `secure.wifi.interface`, so neither how
`run()` picks a binary nor its failure branches had ever been executed.

The property under test is the one J-0251 established for
secure/checks/_shell.py and J-0252 carried to arpwatch, inventory and
connections: `$PATH` does not choose the binary. The call sites pass the
bare names `ipconfig`, `networksetup` and `system_profiler`, and their
output becomes the recorded SSID and security mode — so a user-writable
shim ahead of `/usr/sbin` could decide which network the baseline says
this Mac joined, and how it was secured.

Run with:  pytest
"""

from __future__ import annotations

import subprocess

import pytest

from secure.wifi._shell import _SYSTEM_BIN_DIRS, _resolve, run

_SHIM_NAME = "secure_wifi_shim"
_SHIM_OUTPUT = "SHIMMED"

# Every bare name a secure/wifi/ call site passes to run().
_WIFI_COMMANDS = ("ipconfig", "networksetup", "system_profiler")


def _write_shim(directory, name=_SHIM_NAME):
    """An executable that announces itself, so anything that runs it is
    visible in the captured stdout rather than inferred."""
    path = directory / name
    path.write_text(f"#!/bin/sh\necho {_SHIM_OUTPUT}\n")
    path.chmod(0o755)
    return path


# ---------- $PATH is not the authority ----------


def test_a_shim_earlier_in_path_is_genuinely_reachable(tmp_path, monkeypatch):
    # Positive control for the tests below. If this fails, the poisoned
    # PATH never worked and their assertions would pass for the wrong
    # reason.
    _write_shim(tmp_path, name="networksetup")
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    completed = subprocess.run(["networksetup", "-help"], capture_output=True, text=True)

    assert completed.stdout.strip() == _SHIM_OUTPUT


def test_bare_name_is_not_resolved_through_path(tmp_path, monkeypatch):
    _write_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

    result = run([_SHIM_NAME])

    assert _SHIM_OUTPUT not in result.stdout
    assert result.ok is False
    assert result.returncode is None


def test_a_shim_cannot_impersonate_networksetup(tmp_path, monkeypatch):
    # `-help` rather than the call sites' `-getairportnetwork <iface>`:
    # the question is which binary answers, not what this Mac is joined to.
    shim = _write_shim(tmp_path, name="networksetup")
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    result = run(["networksetup", "-help"], timeout=10.0)

    assert _resolve("networksetup") != str(shim)
    assert _SHIM_OUTPUT not in result.stdout


@pytest.mark.parametrize("command", _WIFI_COMMANDS)
def test_every_wifi_command_resolves_to_a_system_dir(command, monkeypatch):
    # Guards the fix from the other side: if any of these lived outside
    # _SYSTEM_BIN_DIRS, the Wi-Fi status would now always read unknown.
    monkeypatch.setenv("PATH", "")

    resolved = _resolve(command)

    assert resolved is not None
    assert resolved.rsplit("/", 1)[0] in _SYSTEM_BIN_DIRS


# ---------- but real commands still run ----------


def test_a_system_tool_named_bare_still_runs(monkeypatch):
    # Emptying PATH entirely proves the lookup uses _SYSTEM_BIN_DIRS and
    # not the environment.
    monkeypatch.setenv("PATH", "")

    result = run(["echo", "hello"])

    assert result.ok is True
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"


def test_an_explicit_path_is_run_as_given(tmp_path, monkeypatch):
    # status.py passes the airport binary as an absolute path; that must
    # keep working without being looked up in _SYSTEM_BIN_DIRS.
    shim = _write_shim(tmp_path)
    monkeypatch.setenv("PATH", "")

    result = run([str(shim)])

    assert result.ok is True
    assert result.stdout.strip() == _SHIM_OUTPUT


# ---------- honest absence (TESTING_POLICY rule 9, invariant 5) ----------


def test_an_unfindable_command_reports_absence_not_a_clean_result():
    # ok False is what status.py reads as "this source failed"; with every
    # fast source failed it reports status_unknown, not "disconnected".
    result = run(["secure_no_such_tool_anywhere"])

    assert result.ok is False
    assert result.returncode is None
    assert "secure_no_such_tool_anywhere" in result.stderr
    for directory in _SYSTEM_BIN_DIRS:
        assert directory in result.stderr


def test_a_command_that_hangs_reports_a_timeout_not_a_clean_result():
    result = run(["sleep", "5"], timeout=0.2)

    assert result.ok is False
    assert result.returncode is None
    assert "timed out" in result.stderr


def test_a_non_zero_exit_is_reported_not_raised():
    result = run(["false"])

    assert result.ok is False
    assert result.returncode == 1
