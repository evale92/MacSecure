"""
Tests for secure/persistence/_shell.py — the single place the
persistence package runs a subprocess.

tests/test_persistence.py patches `run` out at each import site, so
until this file nothing executed `secure.persistence._shell.run()`.

The property under test is the one tests/test_checks_shell.py pins for
secure/checks (J-0251): `$PATH` does not choose the binary. All three
call sites here pass a bare name (`ps`, `osascript`, `codesign`), and
on a typical Mac `/opt/homebrew/bin` is user-writable and ahead of
`/usr/bin`. For `codesign` that is the whole finding: a shim printing
a Developer ID authority would make an unsigned persistence item read
as signed, and signing is what decides whether it is alert-worthy.

Run with:  pytest
"""

from __future__ import annotations

import subprocess

from secure.persistence._shell import _SYSTEM_BIN_DIRS, run

_SHIM_NAME = "secure_persistence_shim"
_SHIM_OUTPUT = "SHIMMED"
_FORGED_SIGNATURE = "Authority=Developer ID Application: Forged"


def _write_shim(directory, name=_SHIM_NAME, output=_SHIM_OUTPUT):
    """An executable that announces itself, so anything that runs it is
    visible in the captured output rather than inferred."""
    path = directory / name
    path.write_text(f"#!/bin/sh\necho '{output}'\necho '{output}' >&2\n")
    path.chmod(0o755)
    return path


# ---------- $PATH is not the authority ----------


def test_a_shim_earlier_in_path_is_genuinely_reachable(tmp_path, monkeypatch):
    # Positive control: if the poisoned PATH never worked, the tests
    # below would pass for the wrong reason.
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


def test_a_codesign_shim_cannot_make_an_unsigned_file_look_signed(tmp_path, monkeypatch):
    # End to end through the real caller: check_code_signing() on a file
    # that is certainly unsigned, with a forging `codesign` first in PATH.
    from secure.persistence.codesign import SIGNED_DEVELOPER, check_code_signing

    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    _write_shim(shim_dir, name="codesign", output=_FORGED_SIGNATURE)
    monkeypatch.setenv("PATH", f"{shim_dir}:/usr/bin:/bin")
    target = tmp_path / "tool"
    target.write_text("#!/bin/sh\n")

    assert check_code_signing(str(target)) != SIGNED_DEVELOPER


# ---------- but real commands still run ----------


def test_a_system_tool_named_bare_still_runs(monkeypatch):
    # Emptying PATH proves the lookup uses _SYSTEM_BIN_DIRS, not the
    # environment.
    monkeypatch.setenv("PATH", "")

    result = run(["echo", "hello"])

    assert result.ok is True
    assert result.stdout.strip() == "hello"


def test_every_command_this_package_runs_is_in_a_system_dir():
    # The three names the persistence callers pass. If one ever moves,
    # this fails here instead of every scan silently reporting UNKNOWN.
    import os

    for name in ("ps", "osascript", "codesign"):
        assert any(
            os.access(os.path.join(d, name), os.X_OK) for d in _SYSTEM_BIN_DIRS
        ), name


def test_an_explicit_path_is_run_as_given(tmp_path, monkeypatch):
    shim = _write_shim(tmp_path)
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
