"""
Tests for secure/inventory/_shell.py — the single place the inventory
package runs a subprocess.

No test imported this module before this file: arp_table.py,
network_info.py and ping_sweep.py import `run` from it, and their tests
feed parsers canned text, so neither how `run()` picks a binary nor its
failure branches had ever been executed.

The property under test is the one J-0251 established for
secure/checks/_shell.py and f642a1e carried to secure/arpwatch: `$PATH`
does not choose the binary. The call sites pass bare names (`arp -an`,
`route -n get default`, `ifconfig <iface>`, `ping -c 1 ...`), and their
output becomes the device inventory and the subnet it is taken from —
so a user-writable shim ahead of `/usr/sbin` could decide which devices
are recorded as present.

`ping` is only ever resolved here, never run: running it would send a
packet, and a test does not change what the network sees.

Run with:  pytest
"""

from __future__ import annotations

import subprocess

from secure.inventory._shell import _SYSTEM_BIN_DIRS, _resolve, run

_SHIM_NAME = "secure_inventory_shim"
_SHIM_OUTPUT = "SHIMMED"
_INVENTORY_TOOLS = ("arp", "route", "ifconfig", "ping")


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
    _write_shim(tmp_path, name="arp")
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    completed = subprocess.run(["arp", "-an"], capture_output=True, text=True)

    assert completed.stdout.strip() == _SHIM_OUTPUT


def test_bare_name_is_not_resolved_through_path(tmp_path, monkeypatch):
    _write_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

    result = run([_SHIM_NAME])

    assert _SHIM_OUTPUT not in result.stdout
    assert result.ok is False
    assert result.returncode is None


def test_a_shim_cannot_impersonate_the_read_only_inventory_tools(tmp_path, monkeypatch):
    # The names the package really asks for, in the argv shapes it uses.
    # ping is covered by the resolution test below instead of being run.
    for name in ("arp", "route", "ifconfig"):
        _write_shim(tmp_path, name=name)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    for argv in (["arp", "-an"], ["route", "-n", "get", "default"], ["ifconfig", "lo0"]):
        result = run(argv, timeout=10.0)
        assert _SHIM_OUTPUT not in result.stdout, argv


def test_a_shim_named_ping_is_not_what_ping_resolves_to(tmp_path, monkeypatch):
    shim = _write_shim(tmp_path, name="ping")
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    assert _resolve("ping") != str(shim)


def test_the_tools_inventory_uses_resolve_to_system_dirs(monkeypatch):
    # Guards the fix from the other side: if any of these lived outside
    # _SYSTEM_BIN_DIRS, every inventory scan would now report absence.
    monkeypatch.setenv("PATH", "")

    for program in _INVENTORY_TOOLS:
        resolved = _resolve(program)
        assert resolved is not None, program
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
    shim = _write_shim(tmp_path)
    monkeypatch.setenv("PATH", "")

    result = run([str(shim)])

    assert result.ok is True
    assert result.stdout.strip() == _SHIM_OUTPUT


# ---------- honest absence (TESTING_POLICY rule 9, invariant 5) ----------


def test_an_unfindable_command_reports_absence_not_a_clean_result():
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
