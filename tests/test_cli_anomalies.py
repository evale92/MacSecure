"""
Tests for Phase 14 Stage 4E: the `secure anomalies` CLI command group
(list/show/mark), defined in secure/cli.py.

Follows the same isolated-temp-app-dir pattern as
tests/test_cli_alert_history.py / tests/test_cli_baseline.py.

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
from secure.config import load_config
from secure.storage.database import Database
from secure.storage.models import find_anomaly_event_by_id, list_events

NOW = datetime(2026, 8, 19, 12, 0, 0, tzinfo=timezone.utc)


def _iso(dt):
    return dt.isoformat()


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


def _list_ns(**overrides):
    base = dict(
        tier=None, entity_type=None, known=False, unknown=False,
        since_hours=None, limit=50,
    )
    base.update(overrides)
    return _ns(**base)


# ---------- list ----------


def test_anomalies_list_empty(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_list, _list_ns())
    assert rc == 0
    assert "No anomaly events match" in stdout


def test_anomalies_list_shows_recorded_event(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    entity_key = "launch_agent::/x.plist"
    with Database(cfg.database_path()) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key, "signing_status",
            "unsigned", _iso(NOW), is_unsigned=True,
        )

    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_list, _list_ns())
    assert rc == 0
    assert "#1" in stdout
    assert "persistence/launch_agent::/x.plist" in stdout
    assert "UNKNOWN" in stdout


def test_anomalies_list_filters_by_tier(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    entity_key = "launch_agent::/x.plist"
    with Database(cfg.database_path()) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key, "signing_status",
            "unsigned", _iso(NOW), is_unsigned=True,
        )

    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_list, _list_ns(tier="critical"))
    assert rc == 0
    assert "No anomaly events match" in stdout

    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_list, _list_ns(tier="low"))
    assert rc == 0
    assert "#1" in stdout


def test_anomalies_list_known_unknown_filters(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    entity_key = "launch_agent::/x.plist"
    with Database(cfg.database_path()) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key, "signing_status",
            "unsigned", _iso(NOW), is_unsigned=True,
        )

    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_list, _list_ns(unknown=True))
    assert "#1" in stdout
    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_list, _list_ns(known=True))
    assert "No anomaly events match" in stdout

    cli.cmd_anomalies_mark(_ns(event_id=1, status="known"))

    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_list, _list_ns(known=True))
    assert "#1" in stdout
    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_list, _list_ns(unknown=True))
    assert "No anomaly events match" in stdout


def test_anomalies_list_since_hours_excludes_older_events(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    entity_key = "launch_agent::/x.plist"
    old_time = datetime.now(timezone.utc) - timedelta(days=10)
    with Database(cfg.database_path()) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key, "signing_status",
            "unsigned", _iso(old_time), is_unsigned=True,
        )

    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_list, _list_ns(since_hours=1.0))
    assert "No anomaly events match" in stdout

    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_list, _list_ns(since_hours=24 * 30))
    assert "#1" in stdout


# ---------- show ----------


def test_anomalies_show_not_found(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_show, _ns(event_id=999))
    assert rc == 1
    assert "No anomaly event found with id 999" in stdout


def test_anomalies_show_full_breakdown(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    entity_key = "launch_agent::/x.plist"
    with Database(cfg.database_path()) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key, "signing_status",
            "unsigned", _iso(NOW), is_unsigned=True,
        )

    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_show, _ns(event_id=1))
    assert rc == 0
    assert "Anomaly #1" in stdout
    assert "Score breakdown:" in stdout
    assert "rarity" in stdout
    assert "Maturity at time of observation: no_baseline" in stdout
    # persistence is a feature-only entity_type — no entity-level row
    # exists unless an operator action creates one, so this must show
    # up as a caveat, not a crash.
    assert "Caveats:" in stdout
    assert "no entity-level baseline record exists" in stdout


def test_anomalies_show_reflects_current_exclude_state_as_caveat(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    entity_key = "launch_agent::/x.plist"
    with Database(cfg.database_path()) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key, "signing_status",
            "unsigned", _iso(NOW), is_unsigned=True,
        )

    cli.cmd_baseline_exclude(_ns(entity_type="persistence", entity_key=entity_key))

    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_show, _ns(event_id=1))
    assert rc == 0
    assert "currently EXCLUDED from baseline scoring" in stdout


# ---------- mark ----------


def test_anomalies_mark_known_then_unknown(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    entity_key = "launch_agent::/x.plist"
    with Database(cfg.database_path()) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key, "signing_status",
            "unsigned", _iso(NOW), is_unsigned=True,
        )

    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_mark, _ns(event_id=1, status="known"))
    assert rc == 0
    assert "Marked anomaly #1" in stdout
    with Database(cfg.database_path()) as db:
        assert find_anomaly_event_by_id(db.conn, 1).known is True

    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_mark, _ns(event_id=1, status="unknown"))
    assert rc == 0
    with Database(cfg.database_path()) as db:
        assert find_anomaly_event_by_id(db.conn, 1).known is False


def test_anomalies_mark_not_found(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(cli.cmd_anomalies_mark, _ns(event_id=999, status="known"))
    assert rc == 1
    assert "No anomaly event found with id 999" in stdout


# ---------- Stage 4F: append-only review-state history ----------


def test_anomalies_mark_logs_unknown_to_known_transition(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    entity_key = "launch_agent::/x.plist"
    with Database(cfg.database_path()) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key, "signing_status",
            "unsigned", _iso(NOW), is_unsigned=True,
        )

    cli.cmd_anomalies_mark(_ns(event_id=1, status="known"))

    with Database(cfg.database_path()) as db:
        events = list_events(db.conn)
    review_events = [e for e in events if e.category == "anomaly_review_change"]
    assert len(review_events) == 1
    assert "UNKNOWN -> KNOWN" in review_events[0].message
    assert "anomaly_events #1" in review_events[0].message
    assert "persistence/launch_agent::/x.plist" in review_events[0].message
    assert "signing_status" in review_events[0].message
    assert "tier=low" in review_events[0].message


def test_anomalies_mark_logs_known_to_unknown_transition(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    entity_key = "launch_agent::/x.plist"
    with Database(cfg.database_path()) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key, "signing_status",
            "unsigned", _iso(NOW), is_unsigned=True,
        )

    cli.cmd_anomalies_mark(_ns(event_id=1, status="known"))
    cli.cmd_anomalies_mark(_ns(event_id=1, status="unknown"))

    with Database(cfg.database_path()) as db:
        events = list_events(db.conn)
    review_events = [e for e in events if e.category == "anomaly_review_change"]
    assert len(review_events) == 2
    # Newest first (list_events orders id DESC).
    assert "KNOWN -> UNKNOWN" in review_events[0].message
    assert "UNKNOWN -> KNOWN" in review_events[1].message


def test_anomalies_mark_same_status_twice_does_not_duplicate_history(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    entity_key = "launch_agent::/x.plist"
    with Database(cfg.database_path()) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "persistence", entity_key, "signing_status",
            "unsigned", _iso(NOW), is_unsigned=True,
        )

    cli.cmd_anomalies_mark(_ns(event_id=1, status="known"))
    cli.cmd_anomalies_mark(_ns(event_id=1, status="known"))  # no-op re-mark

    with Database(cfg.database_path()) as db:
        events = list_events(db.conn)
    review_events = [e for e in events if e.category == "anomaly_review_change"]
    assert len(review_events) == 1  # only the real transition, not the no-op re-mark


def test_anomalies_mark_not_found_does_not_write_history(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    cli.cmd_anomalies_mark(_ns(event_id=999, status="known"))
    cfg = load_config(app_dir=tmp_path)
    with Database(cfg.database_path()) as db:
        events = list_events(db.conn)
    assert [e for e in events if e.category == "anomaly_review_change"] == []


def test_anomalies_mark_includes_source_reference_when_present(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    entity_key = "svc:80/tcp"
    with Database(cfg.database_path()) as db:
        engine.evaluate_and_record_feature_observation(
            db.conn, "run1", "listening", entity_key, "bind_scope", "network",
            _iso(NOW), is_network_bind=True, source_table="listening_services", source_id=7,
        )

    cli.cmd_anomalies_mark(_ns(event_id=1, status="known"))

    with Database(cfg.database_path()) as db:
        events = list_events(db.conn)
    review_events = [e for e in events if e.category == "anomaly_review_change"]
    assert len(review_events) == 1
    assert "source=listening_services#7" in review_events[0].message
