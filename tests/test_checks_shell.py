"""
Tests for secure/checks/_shell.py — the single place posture checks
run a subprocess.

Unlike tests/test_checks.py, which patches `run` out at each check
module's import site, these actually execute `run()`. Before this file
existed nothing in the suite did: no test imported
`secure.checks._shell` at all, so neither its resolution of a command
name nor its two failure branches had ever been run.

The property under test is that `$PATH` does not choose the binary.
Five of the six call sites in secure/checks/ pass a bare name
(`fdesetup`, `spctl`, `csrutil`, `defaults`, `softwareupdate`), and on
a typical Mac `/opt/homebrew/bin` is user-writable and sits ahead of
`/usr/bin` and `/usr/sbin` — so PATH lookup would let an unprivileged
file decide what `secure check` reports, which is invariant 1 read
backwards.

Run with:  pytest
"""

from __future__ import annotations

import subprocess

from secure.checks._shell import _SYSTEM_BIN_DIRS, run

_SHIM_NAME = "secure_posture_shim"
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
    # Positive control for the test below. If this fails, the poisoned
    # PATH never worked and the real assertion would pass for the wrong
    # reason.
    _write_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

    completed = subprocess.run([_SHIM_NAME], capture_output=True, text=True)

    assert completed.stdout.strip() == _SHIM_OUTPUT


def test_bare_name_is_not_resolved_through_path(tmp_path, monkeypatch):
    _write_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

    result = run([_SHIM_NAME])

    assert _SHIM_OUTPUT not in result.stdout
    assert result.ok is False
    assert result.returncode is None


def test_a_shim_cannot_impersonate_a_real_system_tool(tmp_path, monkeypatch):
    # The shape that matters: the name is one a check really asks for.
    # `csrutil` in a writable PATH entry must not be what answers.
    _write_shim(tmp_path, name="csrutil")
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

    result = run(["csrutil", "status"])

    assert _SHIM_OUTPUT not in result.stdout


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
    # A caller that names a file owns that choice — this is how
    # secure/checks/firewall.py reaches
    # /usr/libexec/ApplicationFirewall/socketfilterfw, which is in none
    # of _SYSTEM_BIN_DIRS.
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
    # `false` exits 1 by design; callers decide what that means, so run()
    # must hand it back rather than treat it as a failure to run.
    result = run(["false"])

    assert result.ok is False
    assert result.returncode == 1
