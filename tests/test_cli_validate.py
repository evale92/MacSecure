"""
Tests for the `secure validate ...` CLI front end (secure/cli/validate.py,
Phase 27 Stage 5-6). Follows the same isolated-temp-app-dir /
_run_capturing_stdout convention as tests/test_cli_detect.py.

secure/validate/runner.py and report.py already have their own
dedicated unit tests (tests/test_validate_runner.py,
test_validate_report.py) — this file's job is only to check the CLI
layer wires those correctly: argument parsing, exit codes, and output
formatting.

Run with:  pytest
"""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path

from secure import cli
from secure.cli import validate as validate_cli
from secure.config import load_config


def _bootstrap_to_tmp(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cli, "load_config", lambda: load_config(app_dir=tmp_path))
    return load_config(app_dir=tmp_path)


def _run_capturing_stdout(fn, *args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*args)
    return rc, buf.getvalue()


def _ns(**kwargs) -> argparse.Namespace:
    return argparse.Namespace(**kwargs)


# ---------- run ----------


def test_validate_run_exits_0_and_prints_every_outcome_bucket(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(validate_cli.cmd_validate_run, _ns())
    assert rc == 0
    for outcome in ("PASS", "PARTIAL", "MISS", "NOT_EVALUABLE", "SENSOR_UNAVAILABLE"):
        assert outcome in stdout


def test_validate_run_persists_a_findable_run(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _run_capturing_stdout(validate_cli.cmd_validate_run, _ns())

    from secure.storage.database import Database
    from secure.storage.models import find_latest_validation_run

    with Database(cfg.database_path()) as db:
        run = find_latest_validation_run(db.conn)
    assert run is not None
    assert run.scenario_count > 0


# ---------- list ----------


def test_validate_list_before_any_run_says_so(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(validate_cli.cmd_validate_list, _ns(limit=50))
    assert rc == 0
    assert "No validation runs yet" in stdout


def test_validate_list_after_run_shows_the_run_id(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    _run_capturing_stdout(validate_cli.cmd_validate_run, _ns())
    rc, stdout = _run_capturing_stdout(validate_cli.cmd_validate_list, _ns(limit=50))
    assert rc == 0
    assert "[complete]" in stdout


# ---------- show ----------


def test_validate_show_unknown_run_id_returns_1(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(validate_cli.cmd_validate_show, _ns(run_id="not-a-real-run"))
    assert rc == 1
    assert "No validation run found" in stdout


def test_validate_show_prints_full_per_scenario_detail(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _, run_stdout = _run_capturing_stdout(validate_cli.cmd_validate_run, _ns())

    from secure.storage.database import Database
    from secure.storage.models import find_latest_validation_run

    with Database(cfg.database_path()) as db:
        run_id = find_latest_validation_run(db.conn).run_id

    rc, stdout = _run_capturing_stdout(validate_cli.cmd_validate_show, _ns(run_id=run_id))
    assert rc == 0
    assert "category:" in stdout
    assert "expected:" in stdout
    assert "persistence_new_launch_daemon_unsigned" in stdout


# ---------- report ----------


def test_validate_report_before_any_run_returns_1(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        validate_cli.cmd_validate_report, _ns(run_id=None, output_dir=str(tmp_path / "out"), no_json=False)
    )
    assert rc == 1


def test_validate_report_writes_both_files_by_default(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    _run_capturing_stdout(validate_cli.cmd_validate_run, _ns())

    out_dir = tmp_path / "out"
    rc, stdout = _run_capturing_stdout(
        validate_cli.cmd_validate_report, _ns(run_id=None, output_dir=str(out_dir), no_json=False)
    )
    assert rc == 0
    assert (out_dir / "VALIDATION_REPORT.md").exists()
    assert (out_dir / "validation_report.json").exists()
    assert "Wrote" in stdout


def test_validate_report_no_json_flag_skips_json(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    _run_capturing_stdout(validate_cli.cmd_validate_run, _ns())

    out_dir = tmp_path / "out2"
    rc, stdout = _run_capturing_stdout(
        validate_cli.cmd_validate_report, _ns(run_id=None, output_dir=str(out_dir), no_json=True)
    )
    assert rc == 0
    assert (out_dir / "VALIDATION_REPORT.md").exists()
    assert not (out_dir / "validation_report.json").exists()
