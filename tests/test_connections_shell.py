"""
Tests for secure/connections/_shell.py — the single place the
connections package runs a subprocess.

No test imported `run` from this module before this file:
tests/test_connections.py imports only `ShellResult` and patches
`scanner.run` out at the call site, so neither how `run()` picks a
binary nor its failure branches had ever been executed.

The property under test is the one J-0251 established for
secure/checks/_shell.py and J-0252 carried to arpwatch and inventory:
`$PATH` does not choose the binary. The one call site passes the bare
name `lsof`, and its output becomes the recorded connection baseline —
so a user-writable shim ahead of `/usr/sbin` could decide which
processes are recorded as talking to the network.

Run with:  pytest
"""

from __future__ import annotations

import subprocess

from secure.connections._shell import _SYSTEM_BIN_DIRS, _resolve, run

_SHIM_NAME = "secure_connections_shim"
_SHIM_OUTPUT = "SHIMMED"


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
    _write_shim(tmp_path, name="lsof")
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    completed = subprocess.run(["lsof", "-v"], capture_output=True, text=True)

    assert completed.stdout.strip() == _SHIM_OUTPUT


def test_bare_name_is_not_resolved_through_path(tmp_path, monkeypatch):
    _write_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

    result = run([_SHIM_NAME])

    assert _SHIM_OUTPUT not in result.stdout
    assert result.ok is False
    assert result.returncode is None


def test_a_shim_cannot_impersonate_lsof(tmp_path, monkeypatch):
    # `-v` rather than the scanner's `-i -n -P +c0`: the question is which
    # binary answers, and the version flag asks it without listing sockets.
    shim = _write_shim(tmp_path, name="lsof")
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    result = run(["lsof", "-v"], timeout=10.0)

    assert _resolve("lsof") != str(shim)
    assert _SHIM_OUTPUT not in result.stdout


def test_lsof_resolves_to_a_system_dir(monkeypatch):
    # Guards the fix from the other side: if lsof lived outside
    # _SYSTEM_BIN_DIRS, every connections scan would now report absence.
    monkeypatch.setenv("PATH", "")

    resolved = _resolve("lsof")

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
    shim = _write_shim(tmp_path)
    monkeypatch.setenv("PATH", "")

    result = run([str(shim)])

    assert result.ok is True
    assert result.stdout.strip() == _SHIM_OUTPUT


# ---------- honest absence (TESTING_POLICY rule 9, invariant 5) ----------


def test_an_unfindable_command_reports_absence_not_a_clean_result():
    # returncode None is exactly what scanner.py reads as "lsof
    # unavailable", recorded as a sensor failure rather than an empty scan.
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
