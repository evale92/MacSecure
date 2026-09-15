"""
Tests for secure/diagnostics/_shell.py — the single place the diagnostics
package runs a subprocess.

No test imported `run` from this module before this file:
tests/test_diagnostics.py substitutes `run` in hardware.py, so neither how
`run()` picks a binary nor its failure branches had ever been executed.

The property under test is the one J-0251 established for
secure/checks/_shell.py and J-0252 carried to arpwatch, inventory,
connections, wifi, bluetooth and correlate: `$PATH` does not choose the
binary. hardware.py, system.py and tools.py pass the bare names `sysctl`,
`vm_stat`, `pmset` and `ps`, and what they print becomes the hardware
specs, system health and dev-tool usage the operator reads — so a
user-writable shim ahead of the system dirs could report whatever it
liked, or hide a process from the `ps` aggregate.

Run with:  pytest
"""

from __future__ import annotations

import subprocess

import pytest

from secure.diagnostics import hardware, tools
from secure.diagnostics._shell import _SYSTEM_BIN_DIRS, _resolve, run

_SHIM_NAME = "secure_diagnostics_shim"
_SHIM_OUTPUT = "SHIMMED"
# A process name no real Mac is running, so a `ps` shim's row is unmistakable.
_SHIM_PROCESS = "secure_diag_shimproc"

# Every bare name a secure/diagnostics/ call site passes to run().
_DIAGNOSTICS_COMMANDS = ("sysctl", "vm_stat", "pmset", "ps")


def _write_shim(directory, name=_SHIM_NAME, output=_SHIM_OUTPUT):
    """An executable that announces itself, so anything that runs it is
    visible in the captured stdout rather than inferred."""
    path = directory / name
    path.write_text(f"#!/bin/sh\necho '{output}'\n")
    path.chmod(0o755)
    return path


def _write_ps_shim(directory):
    return _write_shim(
        directory,
        name="ps",
        output=f"  PID    RSS  %CPU COMM\n    1   1024  99.0 {_SHIM_PROCESS}",
    )


# ---------- $PATH is not the authority ----------


def test_a_shim_earlier_in_path_is_genuinely_reachable(tmp_path, monkeypatch):
    # Positive control for the tests below. If this fails, the poisoned
    # PATH never worked and their assertions would pass for the wrong
    # reason.
    _write_shim(tmp_path, name="sysctl")
    _write_ps_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    sysctl = subprocess.run(["sysctl", "-n", "hw.ncpu"], capture_output=True, text=True)
    ps = subprocess.run(["ps", "-axo", "pid,rss,pcpu,comm"], capture_output=True, text=True)

    assert sysctl.stdout.strip() == _SHIM_OUTPUT
    assert _SHIM_PROCESS in ps.stdout


def test_bare_name_is_not_resolved_through_path(tmp_path, monkeypatch):
    _write_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

    result = run([_SHIM_NAME])

    assert _SHIM_OUTPUT not in result.stdout
    assert result.ok is False
    assert result.returncode is None


def test_a_shim_cannot_supply_a_hardware_spec(tmp_path, monkeypatch):
    # Through the real call site, not just run().
    shim = _write_shim(tmp_path, name="sysctl")
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    value = hardware._sysctl("hw.ncpu")

    assert _resolve("sysctl") != str(shim)
    assert value != _SHIM_OUTPUT


def test_a_shim_cannot_supply_the_process_list_tools_aggregates(tmp_path, monkeypatch):
    shim = _write_ps_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    usages = tools.collect_dev_tool_usage(_SHIM_PROCESS)

    assert _resolve("ps") != str(shim)
    assert [u.process_count for u in usages] == [0]


@pytest.mark.parametrize("command", _DIAGNOSTICS_COMMANDS)
def test_every_diagnostics_command_resolves_to_a_system_dir(command, monkeypatch):
    # Guards the fix from the other side: if any of these lived outside
    # _SYSTEM_BIN_DIRS, its field would now always read as unavailable.
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
    shim = _write_shim(tmp_path)
    monkeypatch.setenv("PATH", "")

    result = run([str(shim)])

    assert result.ok is True
    assert result.stdout.strip() == _SHIM_OUTPUT


# ---------- honest absence (TESTING_POLICY rule 9, invariant 5) ----------


def test_an_unfindable_command_reports_absence_not_a_clean_result():
    # returncode None / ok False is what every call site reads as
    # "unavailable", never as a measured value.
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
