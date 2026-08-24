"""
Tests for Phase 29 Stage 7 (performance/failure-modes audit): several
deliberately induced failure conditions — a corrupted config.json, a
corrupted/non-SQLite database file, and a permission-denied app
directory — must each produce a clear, actionable error and a non-zero
exit code, never a raw Python traceback and never a silent "clean"
result.

Follows the same isolated-temp-app-dir monkeypatch convention
tests/test_cli_ai.py already established (`monkeypatch.setattr(cli,
"load_config", ...)`), NOT `monkeypatch.setenv("HOME", ...)` —
secure/config.py's DEFAULT_APP_DIR is computed once at module import
time from Path.home(), so patching the HOME environment variable after
secure.config has already been imported has no effect on it.

Run with:  pytest
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from secure import cli
from secure.config import ConfigError, config_file_path, load_config


def _bootstrap_to_tmp(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cli, "load_config", lambda: load_config(app_dir=tmp_path))


# =========================================================================
# secure/config.py — ConfigError on a corrupted/malformed config.json
# =========================================================================


def test_load_config_raises_config_error_on_invalid_json(tmp_path: Path):
    config_file_path(tmp_path).write_text("{not valid json!!!")

    with pytest.raises(ConfigError) as exc_info:
        load_config(tmp_path)

    assert "not valid JSON" in str(exc_info.value)
    assert str(config_file_path(tmp_path)) in str(exc_info.value)


def test_load_config_raises_config_error_on_non_object_json(tmp_path: Path):
    config_file_path(tmp_path).write_text("[1, 2, 3]")

    with pytest.raises(ConfigError) as exc_info:
        load_config(tmp_path)

    assert "not a JSON object" in str(exc_info.value)


def test_load_config_still_works_normally_after_this_change(tmp_path: Path):
    """The hardening above must not touch the well-formed path."""
    cfg = load_config(tmp_path)
    assert cfg.device_role == "workstation"


# =========================================================================
# secure/cli/__init__.py's main() — clean exit-2 errors, not tracebacks
# =========================================================================


def test_main_reports_corrupted_config_cleanly(tmp_path: Path, monkeypatch, capsys):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    config_file_path(tmp_path).write_text("{not valid json!!!")

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["status"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "Configuration error" in captured.err
    assert "Traceback" not in captured.err


def test_main_reports_corrupted_database_cleanly(tmp_path: Path, monkeypatch, capsys):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    (tmp_path / "secure.db").write_bytes(b"garbage, not a real sqlite database file" * 5)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["status"])

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "Database error" in captured.err
    assert "Traceback" not in captured.err


def test_main_reports_permission_denied_app_dir_cleanly(tmp_path: Path, monkeypatch, capsys):
    app_dir = tmp_path / "locked"
    app_dir.mkdir()
    _bootstrap_to_tmp(monkeypatch, app_dir)
    os.chmod(app_dir, 0o000)
    try:
        with pytest.raises(SystemExit) as exc_info:
            cli.main(["status"])

        captured = capsys.readouterr()
        assert exc_info.value.code == 2
        assert "Permission error" in captured.err
        assert "Traceback" not in captured.err
    finally:
        os.chmod(app_dir, 0o700)  # restore so pytest's own tmp_path cleanup can remove it


def test_main_still_exits_zero_on_a_healthy_environment(tmp_path: Path, monkeypatch):
    """The three failure-path handlers above must not swallow or alter
    the ordinary, healthy exit code for a normal command.
    """
    _bootstrap_to_tmp(monkeypatch, tmp_path)

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["status"])

    assert exc_info.value.code == 0
