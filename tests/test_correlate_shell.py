"""
Tests for secure/correlate/_shell.py — the single place the correlate
package runs a subprocess.

No test imported `run` from this module before this file:
tests/test_correlate.py substitutes the `_read_boottime_output()` seam
in context.py, so neither how `run()` picks a binary nor its failure
branches had ever been executed.

The property under test is the one J-0251 established for
secure/checks/_shell.py and J-0252 carried to arpwatch, inventory,
connections, wifi and bluetooth: `$PATH` does not choose the binary.
context.py passes the bare name `sysctl`, and the boot time it reads
decides whether apply_context() discounts a weak cluster as start-up
churn — so a user-writable shim ahead of `/usr/sbin` could claim a boot
a minute ago and lower the score of whatever it wanted hidden.

Run with:  pytest
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone

import pytest

from secure.correlate import context
from secure.correlate._shell import _SYSTEM_BIN_DIRS, _resolve, run

_SHIM_NAME = "secure_correlate_shim"
_SHIM_OUTPUT = "SHIMMED"
# A boot time no real Mac reports, so a shim's answer is unmistakable.
_SHIM_BOOT_SECONDS = 86400

# Every bare name a secure/correlate/ call site passes to run().
_CORRELATE_COMMANDS = ("sysctl",)


def _write_shim(directory, name=_SHIM_NAME, output=_SHIM_OUTPUT):
    """An executable that announces itself, so anything that runs it is
    visible in the captured stdout rather than inferred."""
    path = directory / name
    path.write_text(f"#!/bin/sh\necho '{output}'\n")
    path.chmod(0o755)
    return path


def _write_sysctl_shim(directory):
    return _write_shim(
        directory,
        name="sysctl",
        output=f"{{ sec = {_SHIM_BOOT_SECONDS}, usec = 0 }} Fri Jan  2 00:00:00 1970",
    )


# ---------- $PATH is not the authority ----------


def test_a_shim_earlier_in_path_is_genuinely_reachable(tmp_path, monkeypatch):
    # Positive control for the tests below. If this fails, the poisoned
    # PATH never worked and their assertions would pass for the wrong
    # reason.
    _write_sysctl_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    completed = subprocess.run(["sysctl", "-n", "kern.boottime"], capture_output=True, text=True)

    assert f"sec = {_SHIM_BOOT_SECONDS}," in completed.stdout


def test_bare_name_is_not_resolved_through_path(tmp_path, monkeypatch):
    _write_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")

    result = run([_SHIM_NAME])

    assert _SHIM_OUTPUT not in result.stdout
    assert result.ok is False
    assert result.returncode is None


def test_a_shim_cannot_supply_the_boot_time_context_reads(tmp_path, monkeypatch):
    # Through the real call site, not just run(): the boot time that
    # apply_context() would act on must not be the shim's.
    shim = _write_sysctl_shim(tmp_path)
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin:/usr/sbin:/sbin")

    boot_time = context.get_boot_time()

    assert _resolve("sysctl") != str(shim)
    assert boot_time != datetime.fromtimestamp(_SHIM_BOOT_SECONDS, tz=timezone.utc)


@pytest.mark.parametrize("command", _CORRELATE_COMMANDS)
def test_every_correlate_command_resolves_to_a_system_dir(command, monkeypatch):
    # Guards the fix from the other side: if any of these lived outside
    # _SYSTEM_BIN_DIRS, boot time would now always read as unknown.
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
    # returncode None is what _read_boottime_output() reads as "boot
    # time unknown", so no boot-proximity discount is applied.
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
