"""
Tests for secure/listening/_shell.py — the single place the listening
package runs a subprocess.

tests/test_listening.py patches `run` out at scanner.py's import site,
so before this file no test executed `secure.listening._shell.run()`
itself. The property under test is the one J-0251 established for
secure/checks/_shell.py: `$PATH` does not choose the binary. scanner.py
asks for bare `lsof`, and on a typical Mac `/opt/homebrew/bin` is
user-writable and ahead of `/usr/sbin`, so a shim there could hand the
scanner an empty socket table and every listener would vanish from the
report.

Run with:  pytest
"""

from __future__ import annotations

import subprocess

from secure.listening._shell import _SYSTEM_BIN_DIRS, run

_SHIM_OUTPUT = "SHIMMED"


def _write_shim(directory, name):
    """An executable that announces itself, so anything that runs it is
    visible in the captured stdout rather than inferred."""
    path = directory / name
    path.write_text(f"#!/bin/sh\necho {_SHIM_OUTPUT}\n")
    path.chmod(0o755)
    return path


# ---------- $PATH is not the authority ----------


def test_a_shim_earlier_in_path_is_genuinely_reachable(tmp_path, monkeypatch):
    # Positive control for the test below. If this fails, the poisoned
    # PATH never worked and the real assertion would pass for the wrong
    # reason.
    _write_shim(tmp_path, "lsof")
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    completed = subprocess.run(["lsof"], capture_output=True, text=True)

    assert completed.stdout.strip() == _SHIM_OUTPUT


def test_a_shim_cannot_impersonate_lsof(tmp_path, monkeypatch):
    # The exact argv secure/listening/scanner.py sends.
    _write_shim(tmp_path, "lsof")
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    result = run(["lsof", "-i", "-n", "-P", "+c0"], timeout=15.0)

    assert _SHIM_OUTPUT not in result.stdout


def test_bare_name_outside_system_dirs_is_not_resolved_through_path(tmp_path, monkeypatch):
    _write_shim(tmp_path, "secure_listening_shim")
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

    result = run(["secure_listening_shim"])

    assert _SHIM_OUTPUT not in result.stdout
    assert result.ok is False
    assert result.returncode is None


# ---------- but real commands still run ----------


def test_a_system_tool_named_bare_still_runs(monkeypatch):
    # Emptying PATH entirely proves the lookup uses _SYSTEM_BIN_DIRS and
    # not the environment.
    monkeypatch.setenv("PATH", "")

    result = run(["echo", "hello"])

    assert result.ok is True
    assert result.returncode == 0
    assert result.stdout.strip() == "hello"


def test_the_command_this_package_runs_is_in_a_system_dir():
    # scanner.py's only command. If lsof ever moves, this fails here
    # instead of every scan silently reporting the sensor unavailable.
    import os

    assert any(os.access(os.path.join(d, "lsof"), os.X_OK) for d in _SYSTEM_BIN_DIRS)


def test_an_explicit_path_is_run_as_given(tmp_path, monkeypatch):
    shim = _write_shim(tmp_path, "secure_listening_shim")
    monkeypatch.setenv("PATH", "")

    result = run([str(shim)])

    assert result.ok is True
    assert result.stdout.strip() == _SHIM_OUTPUT


# ---------- honest absence (invariant 5) ----------


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
