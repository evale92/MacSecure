"""
Tests for the `secure detect ...` CLI front end (secure/cli/detect.py,
Phase 25 Stage 5). Follows the same isolated-temp-app-dir /
_run_capturing_stdout convention as tests/test_cli_dfir.py.

secure/detect/registry.py, validate.py, and firing_history.py already
have their own dedicated unit tests (tests/test_detect_registry.py,
test_detect_validate.py, test_detect_firing_history.py) — this file's
job is only to check the CLI layer wires those correctly: argument
parsing, exit codes, and output formatting, including the
tracking-only note for suricata/correlate on enable/disable.

Run with:  pytest
"""

from __future__ import annotations

import argparse
import contextlib
import io
import shutil
from pathlib import Path

from secure import cli
from secure.cli import detect as detect_cli
from secure.config import load_config
from secure.detect.registry import sync_registry
from secure.storage.database import Database

SIGMA_FIXTURES = Path(__file__).parent / "fixtures" / "sigma" / "rules"


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


def _seed_correlate_rules(cfg) -> None:
    """The two static correlate engines always sync cleanly with no
    filesystem fixtures needed — the cheapest way to get a real
    cataloged rule id for enable/disable/show/test/annotate tests."""
    with Database(cfg.database_path()) as db:
        sync_registry(db.conn, cfg)


# ---------- sync ----------


def test_detect_sync_reports_counts_across_all_four_families(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(detect_cli.cmd_detect_sync, _ns())
    assert rc == 0
    assert "Synced detection rule catalog" in stdout
    # Nothing else configured, but the 2 static correlate engines always
    # register — proving sync touched every family, not just sigma/yarax.
    assert "correlate: 2" in stdout


def test_detect_sync_is_idempotent_and_preserves_operator_state(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _run_capturing_stdout(detect_cli.cmd_detect_sync, _ns())

    with Database(cfg.database_path()) as db:
        from secure.storage.models import find_detection_rule, set_detection_rule_enabled

        record = find_detection_rule(db.conn, "correlate", "temporal_clustering")
        set_detection_rule_enabled(db.conn, record.id, False)

    _run_capturing_stdout(detect_cli.cmd_detect_sync, _ns())

    with Database(cfg.database_path()) as db:
        from secure.storage.models import find_detection_rule

        record = find_detection_rule(db.conn, "correlate", "temporal_clustering")
        assert record.enabled is False  # a routine resync must never silently re-enable it


# ---------- list ----------


def test_detect_list_reports_no_rules_before_sync(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        detect_cli.cmd_detect_list,
        _ns(family=None, enabled_only=False, disabled_only=False, validation_status=None, limit=200),
    )
    assert rc == 0
    assert "No detection rules match" in stdout


def test_detect_list_filters_by_family(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _seed_correlate_rules(cfg)

    rc, stdout = _run_capturing_stdout(
        detect_cli.cmd_detect_list,
        _ns(family="correlate", enabled_only=False, disabled_only=False, validation_status=None, limit=200),
    )
    assert rc == 0
    assert "temporal_clustering" in stdout
    assert "chain_scoring" in stdout

    rc, stdout = _run_capturing_stdout(
        detect_cli.cmd_detect_list,
        _ns(family="sigma", enabled_only=False, disabled_only=False, validation_status=None, limit=200),
    )
    assert rc == 0
    assert "No detection rules match" in stdout


def test_detect_list_disabled_only_reflects_real_state(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _seed_correlate_rules(cfg)
    with Database(cfg.database_path()) as db:
        from secure.storage.models import find_detection_rule, set_detection_rule_enabled

        record = find_detection_rule(db.conn, "correlate", "chain_scoring")
        set_detection_rule_enabled(db.conn, record.id, False)

    rc, stdout = _run_capturing_stdout(
        detect_cli.cmd_detect_list,
        _ns(family=None, enabled_only=False, disabled_only=True, validation_status=None, limit=200),
    )
    assert rc == 0
    assert "chain_scoring" in stdout
    assert "temporal_clustering" not in stdout


# ---------- show ----------


def test_detect_show_unknown_id_returns_1(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(detect_cli.cmd_detect_show, _ns(rule_id=999, limit=20))
    assert rc == 1
    assert "No detection rule found" in stdout


def test_detect_show_reports_live_capability_and_no_firings(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _seed_correlate_rules(cfg)
    with Database(cfg.database_path()) as db:
        from secure.storage.models import find_detection_rule

        record = find_detection_rule(db.conn, "correlate", "chain_scoring")

    rc, stdout = _run_capturing_stdout(detect_cli.cmd_detect_show, _ns(rule_id=record.id, limit=20))
    assert rc == 0
    assert "chain_scoring" in stdout
    assert "capability now: evaluable" in stdout
    assert "never tested" in stdout
    assert "No recorded firings" in stdout


def test_detect_show_notes_tracking_only_for_correlate(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _seed_correlate_rules(cfg)
    with Database(cfg.database_path()) as db:
        from secure.storage.models import find_detection_rule

        record = find_detection_rule(db.conn, "correlate", "chain_scoring")

    rc, stdout = _run_capturing_stdout(detect_cli.cmd_detect_show, _ns(rule_id=record.id, limit=20))
    assert rc == 0
    assert "tracking-only" in stdout


# ---------- enable / disable ----------


def test_detect_enable_disable_unknown_id_returns_1(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(detect_cli.cmd_detect_enable, _ns(rule_id=999))
    assert rc == 1
    rc, stdout = _run_capturing_stdout(detect_cli.cmd_detect_disable, _ns(rule_id=999))
    assert rc == 1


def test_detect_disable_correlate_prints_tracking_only_note(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _seed_correlate_rules(cfg)
    with Database(cfg.database_path()) as db:
        from secure.storage.models import find_detection_rule

        record = find_detection_rule(db.conn, "correlate", "chain_scoring")

    rc, stdout = _run_capturing_stdout(detect_cli.cmd_detect_disable, _ns(rule_id=record.id))
    assert rc == 0
    assert "Disabled" in stdout
    assert "tracking-only" in stdout
    assert "never consults it" in stdout


def test_detect_disable_sigma_does_not_print_tracking_only_note(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(
        SIGMA_FIXTURES / "process_creation_match.yml",
        cfg.sigma_rules_dir_path() / "process_creation_match.yml",
    )
    with Database(cfg.database_path()) as db:
        sync_registry(db.conn, cfg)
        from secure.storage.models import list_detection_rules

        record = list_detection_rules(db.conn, family="sigma")[0]

    rc, stdout = _run_capturing_stdout(detect_cli.cmd_detect_disable, _ns(rule_id=record.id))
    assert rc == 0
    assert "Disabled" in stdout
    assert "tracking-only" not in stdout


def test_detect_enable_disable_roundtrip_changes_stored_state(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _seed_correlate_rules(cfg)
    with Database(cfg.database_path()) as db:
        from secure.storage.models import find_detection_rule

        record = find_detection_rule(db.conn, "correlate", "temporal_clustering")

    _run_capturing_stdout(detect_cli.cmd_detect_disable, _ns(rule_id=record.id))
    with Database(cfg.database_path()) as db:
        from secure.storage.models import find_detection_rule_by_id

        assert find_detection_rule_by_id(db.conn, record.id).enabled is False

    _run_capturing_stdout(detect_cli.cmd_detect_enable, _ns(rule_id=record.id))
    with Database(cfg.database_path()) as db:
        from secure.storage.models import find_detection_rule_by_id

        assert find_detection_rule_by_id(db.conn, record.id).enabled is True


# ---------- test ----------


def test_detect_test_unknown_id_returns_1(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(detect_cli.cmd_detect_test, _ns(rule_id=999, family=None))
    assert rc == 1
    assert "No detection rule found" in stdout


def test_detect_test_no_rules_cataloged_returns_0(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(detect_cli.cmd_detect_test, _ns(rule_id=None, family="sigma"))
    assert rc == 0
    assert "No detection rules to test" in stdout


def test_detect_test_single_correlate_rule_passes_and_records_validation(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _seed_correlate_rules(cfg)
    with Database(cfg.database_path()) as db:
        from secure.storage.models import find_detection_rule

        record = find_detection_rule(db.conn, "correlate", "temporal_clustering")

    rc, stdout = _run_capturing_stdout(detect_cli.cmd_detect_test, _ns(rule_id=record.id, family=None))
    assert rc == 0
    assert "PASSED" in stdout

    with Database(cfg.database_path()) as db:
        from secure.storage.models import find_detection_rule_by_id

        updated = find_detection_rule_by_id(db.conn, record.id)
        assert updated.validation_status == "passed"
        assert updated.last_tested_at is not None


def test_detect_test_family_batch_runs_every_matching_rule(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _seed_correlate_rules(cfg)

    rc, stdout = _run_capturing_stdout(detect_cli.cmd_detect_test, _ns(rule_id=None, family="correlate"))
    assert rc == 0
    assert "temporal_clustering" in stdout
    assert "chain_scoring" in stdout


# ---------- annotate ----------


def test_detect_annotate_unknown_id_returns_1(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(detect_cli.cmd_detect_annotate, _ns(rule_id=999, notes="x"))
    assert rc == 1


def test_detect_annotate_sets_false_positive_notes(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    _seed_correlate_rules(cfg)
    with Database(cfg.database_path()) as db:
        from secure.storage.models import find_detection_rule

        record = find_detection_rule(db.conn, "correlate", "temporal_clustering")

    rc, stdout = _run_capturing_stdout(
        detect_cli.cmd_detect_annotate,
        _ns(rule_id=record.id, notes="fires on routine backup scripts, not malicious"),
    )
    assert rc == 0
    assert "fires on routine backup scripts" in stdout

    with Database(cfg.database_path()) as db:
        from secure.storage.models import find_detection_rule_by_id

        updated = find_detection_rule_by_id(db.conn, record.id)
        assert updated.false_positive_notes == "fires on routine backup scripts, not malicious"
