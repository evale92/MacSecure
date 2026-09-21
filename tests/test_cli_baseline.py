"""
Tests for Phase 14 Stage 4D: the `secure baseline` CLI command group
(status/list/show/exclude/include/freeze/unfreeze/reset), defined in
secure/cli.py.

Follows the same isolated-temp-app-dir pattern as
tests/test_cli_alert_history.py (the first file to unit-test CLI
handlers directly, since every cmd_* reads the real ~/.secure/config.json
via _bootstrap() by default).

Run with:  pytest
"""

from __future__ import annotations

import argparse
import contextlib
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure import cli
from secure.baseline import engine
from secure.baseline.entities import PROCESS, process_key
from secure.baseline.history import record_gap_observation
from secure.config import load_config
from secure.storage.database import Database
from secure.storage.models import find_baseline_entity, get_or_create_baseline_entity


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


# ---------- status ----------


def test_baseline_status_empty(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(cli.cmd_baseline_status, _ns())
    assert rc == 0
    assert "Total entities: 0" in stdout
    assert "No baseline runs recorded yet." in stdout


def test_baseline_status_reflects_entities(tmp_path: Path, monkeypatch):
    # A single observation moves an entity to LEARNING (not
    # NO_BASELINE, which means "never observed at all" — see
    # maturity.py); record_gap_observation() alone doesn't create a
    # baseline_runs row (only a scanner's finalize_baseline_run() does),
    # so "no runs yet" is also correctly expected here.
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    key = process_key("/usr/bin/curl")
    with Database(cfg.database_path()) as db:
        # Relative date: a fixed one ages into STALE (see maturity.py).
        seen = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        record_gap_observation(db.conn, "run1", PROCESS, key, seen)

    rc, stdout = _run_capturing_stdout(cli.cmd_baseline_status, _ns())
    assert rc == 0
    assert "Total entities: 1" in stdout
    assert "learning" in stdout
    assert "No baseline runs recorded yet." in stdout


def test_baseline_status_shows_latest_run_from_a_real_scanner(tmp_path: Path, monkeypatch):
    from secure.connections._shell import ShellResult
    from secure.connections.scanner import scan_connections
    import secure.connections.scanner as scanner_module

    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    monkeypatch.setattr(
        scanner_module, "run",
        lambda *a, **k: ShellResult(
            ok=True,
            stdout="COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n",
            stderr="", returncode=0,
        ),
    )
    with Database(cfg.database_path()) as db:
        result = scan_connections(db.conn)

    rc, stdout = _run_capturing_stdout(cli.cmd_baseline_status, _ns())
    assert rc == 0
    assert "Most recent baseline run:" in stdout
    assert result.run_id in stdout
    assert "success" in stdout


# ---------- list ----------


def test_baseline_list_no_entities(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        cli.cmd_baseline_list,
        _ns(entity_type=None, maturity=None, excluded=None, frozen=None),
    )
    assert rc == 0
    assert "No baseline entities match" in stdout


def test_baseline_list_filters_by_entity_type(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        get_or_create_baseline_entity(db.conn, "process", process_key("/usr/bin/curl"))
        get_or_create_baseline_entity(db.conn, "wifi", "HomeNetwork")

    rc, stdout = _run_capturing_stdout(
        cli.cmd_baseline_list,
        _ns(entity_type="wifi", maturity=None, excluded=None, frozen=None),
    )
    assert rc == 0
    assert "HomeNetwork" in stdout
    assert "curl" not in stdout


def test_baseline_list_shows_excluded_and_frozen_flags(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        get_or_create_baseline_entity(db.conn, "process", process_key("/usr/bin/curl"))

    cli.cmd_baseline_exclude(_ns(entity_type="process", entity_key=process_key("/usr/bin/curl")))

    rc, stdout = _run_capturing_stdout(
        cli.cmd_baseline_list,
        _ns(entity_type=None, maturity=None, excluded=None, frozen=None),
    )
    assert rc == 0
    assert "[EXCLUDED]" in stdout


# ---------- show ----------


def test_baseline_show_no_entity_record(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        cli.cmd_baseline_show, _ns(entity_type="process", entity_key="/nope")
    )
    assert rc == 0
    assert "No entity-level baseline record yet" in stdout
    assert "No anomaly events recorded" in stdout


def test_baseline_show_includes_feature_maturity_and_anomalies(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    entity_key = "launch_agent::/x.plist"
    with Database(cfg.database_path()) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key, "signing_status",
            "unsigned", "2026-08-19T00:00:00+00:00", is_unsigned=True,
        )

    rc, stdout = _run_capturing_stdout(
        cli.cmd_baseline_show, _ns(entity_type="persistence", entity_key=entity_key)
    )
    assert rc == 0
    assert "signing_status" in stdout
    # First-ever observation for a brand-new entity is RARITY_NEVER_SEEN
    # (40 points) -> above SCORE_TIER_NONE_MAX, so it should have
    # persisted as a real anomaly event, visible here.
    assert "Recent anomaly events" in stdout


# ---------- exclude / include / freeze / unfreeze ----------


def test_baseline_exclude_then_include(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    key = process_key("/usr/bin/curl")

    rc, stdout = _run_capturing_stdout(cli.cmd_baseline_exclude, _ns(entity_type="process", entity_key=key))
    assert rc == 0
    assert "Excluded process" in stdout
    with Database(cfg.database_path()) as db:
        assert find_baseline_entity(db.conn, "process", key).excluded is True

    rc, stdout = _run_capturing_stdout(cli.cmd_baseline_include, _ns(entity_type="process", entity_key=key))
    assert rc == 0
    assert "Included" in stdout
    with Database(cfg.database_path()) as db:
        assert find_baseline_entity(db.conn, "process", key).excluded is False


def test_baseline_freeze_then_unfreeze(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    key = process_key("/usr/bin/curl")

    rc, stdout = _run_capturing_stdout(cli.cmd_baseline_freeze, _ns(entity_type="process", entity_key=key))
    assert rc == 0
    assert "Froze process" in stdout
    with Database(cfg.database_path()) as db:
        assert find_baseline_entity(db.conn, "process", key).frozen is True

    rc, stdout = _run_capturing_stdout(cli.cmd_baseline_unfreeze, _ns(entity_type="process", entity_key=key))
    assert rc == 0
    assert "Unfroze" in stdout
    with Database(cfg.database_path()) as db:
        assert find_baseline_entity(db.conn, "process", key).frozen is False


def test_baseline_exclude_creates_entity_row_for_feature_only_type(tmp_path: Path, monkeypatch):
    # "persistence" never gets a baseline_entities row from a scanner —
    # exclude must still work by creating one (get_or_create_baseline_entity).
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, _ = _run_capturing_stdout(
        cli.cmd_baseline_exclude, _ns(entity_type="persistence", entity_key="launch_agent::/x.plist")
    )
    assert rc == 0
    with Database(cfg.database_path()) as db:
        entity = find_baseline_entity(db.conn, "persistence", "launch_agent::/x.plist")
    assert entity is not None
    assert entity.excluded is True


# ---------- reset ----------


def test_baseline_reset_one_entity(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    key = process_key("/usr/bin/curl")
    with Database(cfg.database_path()) as db:
        for day in range(25):
            record_gap_observation(db.conn, f"run{day}", PROCESS, key, f"2026-08-{1+day:02d}T00:00:00+00:00")
        assert find_baseline_entity(db.conn, "process", key).maturity_state == "established"

    rc, stdout = _run_capturing_stdout(
        cli.cmd_baseline_reset,
        _ns(entity_type="process", entity_key=key, all=False, all_entity_type=None, yes=False),
    )
    assert rc == 0
    assert "Reset baseline for process" in stdout
    with Database(cfg.database_path()) as db:
        assert find_baseline_entity(db.conn, "process", key).maturity_state == "no_baseline"


def test_baseline_reset_missing_args_returns_error(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        cli.cmd_baseline_reset,
        _ns(entity_type=None, entity_key=None, all=False, all_entity_type=None, yes=False),
    )
    assert rc == 1
    assert "Provide both entity_type and entity_key" in stdout


def test_baseline_reset_all_without_yes_is_a_dry_preview(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        get_or_create_baseline_entity(db.conn, "process", process_key("/usr/bin/curl"))
        get_or_create_baseline_entity(db.conn, "process", process_key("/usr/bin/ssh"))

    rc, stdout = _run_capturing_stdout(
        cli.cmd_baseline_reset,
        _ns(entity_type=None, entity_key=None, all=True, all_entity_type=None, yes=False),
    )
    assert rc == 1
    assert "This would reset 2 entities" in stdout
    assert "Re-run with --all --yes" in stdout

    # Nothing was actually touched.
    with Database(cfg.database_path()) as db:
        entity = find_baseline_entity(db.conn, "process", process_key("/usr/bin/curl"))
    assert entity is not None  # still exists, untouched


def test_baseline_reset_all_with_yes_resets_everything_in_scope(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        for day in range(25):
            record_gap_observation(
                db.conn, f"run{day}", PROCESS, process_key("/usr/bin/curl"),
                f"2026-08-{1+day:02d}T00:00:00+00:00",
            )
        get_or_create_baseline_entity(db.conn, "wifi", "HomeNetwork")

    # Scope --all to just "process" via --entity-type -> wifi entity untouched.
    rc, stdout = _run_capturing_stdout(
        cli.cmd_baseline_reset,
        _ns(entity_type=None, entity_key=None, all=True, all_entity_type="process", yes=True),
    )
    assert rc == 0
    assert "Reset 1 entity" in stdout

    with Database(cfg.database_path()) as db:
        assert find_baseline_entity(db.conn, "process", process_key("/usr/bin/curl")).maturity_state == "no_baseline"
        # The wifi entity was out of scope (--entity-type process) and
        # must still exist untouched — "Reset 1 entity" above already
        # confirms only the in-scope process entity was actually reset.
        assert find_baseline_entity(db.conn, "wifi", "HomeNetwork") is not None


def test_baseline_reset_all_combined_with_specific_entity_is_rejected(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        cli.cmd_baseline_reset,
        _ns(entity_type="process", entity_key="/usr/bin/curl", all=True, all_entity_type=None, yes=True),
    )
    assert rc == 1
    assert "Don't combine --all" in stdout
