"""
Tests for Product Phase 13's alert-review-state history: the
append-only trail written to the existing `events` table whenever an
alert's known/unknown state actually changes (see
`secure.cli._record_alert_review_change` and each `cmd_*_mark_alert`
handler in secure/cli.py).

No CLI command handler in this project is unit-tested elsewhere (they
all read the real `~/.secure/config.json` via `_bootstrap()` by
default) — these tests are the first to do so, via monkeypatching
`secure.cli.load_config` to point at a temp `app_dir`, so nothing here
touches the real home directory.

Run with:  pytest
"""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path

from secure import cli
from secure.config import load_config
from secure.storage.database import Database
from secure.storage.models import (
    add_arp_alert,
    add_correlation_alert,
    add_persistence_alert,
    count_events,
    list_arp_alerts,
    list_correlation_alerts,
    list_events,
)


def _bootstrap_to_tmp(monkeypatch, tmp_path: Path):
    """Point secure.cli's _bootstrap() at an isolated temp app_dir,
    exactly like the real one but never touching ~/.secure."""
    monkeypatch.setattr(cli, "load_config", lambda: load_config(app_dir=tmp_path))
    return load_config(app_dir=tmp_path)


def _run_capturing_stdout(fn, *args):
    """This test harness doesn't support pytest's `capsys` fixture, so
    stdout is captured manually — used to confirm existing CLI output
    text/exit codes are unchanged by the Phase 13 history addition."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*args)
    return rc, buf.getvalue()


# ---------- the pure helper ----------


def test_record_alert_review_change_unknown_to_known(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        cli._record_alert_review_change(
            db.conn, source_table="arp_alerts", alert_id=7, subject="10.0.0.5",
            severity="low", was_known=False, now_known=True,
        )
        events = list_events(db.conn)
    assert len(events) == 1
    assert events[0].category == "alert_review_change"
    assert "UNKNOWN -> KNOWN" in events[0].message
    assert "arp_alerts alert #7" in events[0].message
    assert "10.0.0.5" in events[0].message
    assert "severity=low" in events[0].message


def test_record_alert_review_change_known_to_unknown(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        cli._record_alert_review_change(
            db.conn, source_table="file_integrity_alerts", alert_id=3, subject="/etc/hosts",
            severity="high", was_known=True, now_known=False,
        )
        events = list_events(db.conn)
    assert len(events) == 1
    assert "KNOWN -> UNKNOWN" in events[0].message


def test_record_alert_review_change_does_not_store_full_message_text():
    # Refinement: "Do not store unnecessarily large duplicated alert
    # messages when a concise subject is sufficient." The subject
    # (not a full message) is what gets embedded.
    import inspect

    sig = inspect.signature(cli._record_alert_review_change)
    assert "message" not in sig.parameters
    assert "subject" in sig.parameters


# ---------- end-to-end through a real cmd_*_mark_alert handler ----------


def test_arpwatch_mark_logs_unknown_to_known_transition(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_arp_alert(db.conn, "run1", "mac_changed", "low", "10.0.0.5", "aa:aa", "bb:bb", "MAC changed")

    rc, stdout = _run_capturing_stdout(cli.cmd_arpwatch_mark, argparse.Namespace(alert_id="1", status="known"))
    assert rc == 0
    assert "Marked #1" in stdout  # existing stdout text unchanged

    with Database(cfg.database_path()) as db:
        events = list_events(db.conn)
        alerts = list_arp_alerts(db.conn)

    assert alerts[0].known is True
    review_events = [e for e in events if e.category == "alert_review_change"]
    assert len(review_events) == 1
    assert "UNKNOWN -> KNOWN" in review_events[0].message
    assert "arp_alerts alert #1" in review_events[0].message
    assert "10.0.0.5" in review_events[0].message


def test_arpwatch_mark_logs_known_to_unknown_transition(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_arp_alert(db.conn, "run1", "mac_changed", "low", "10.0.0.5", "aa:aa", "bb:bb", "MAC changed")

    # First mark known, then mark unknown — two real transitions.
    cli.cmd_arpwatch_mark(argparse.Namespace(alert_id="1", status="known"))
    rc = cli.cmd_arpwatch_mark(argparse.Namespace(alert_id="1", status="unknown"))
    assert rc == 0

    with Database(cfg.database_path()) as db:
        events = list_events(db.conn)

    review_events = [e for e in events if e.category == "alert_review_change"]
    assert len(review_events) == 2
    # Newest first (list_events orders id DESC).
    assert "KNOWN -> UNKNOWN" in review_events[0].message
    assert "UNKNOWN -> KNOWN" in review_events[1].message


def test_arpwatch_mark_same_status_twice_does_not_duplicate_history(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_arp_alert(db.conn, "run1", "mac_changed", "low", "10.0.0.5", "aa:aa", "bb:bb", "MAC changed")

    cli.cmd_arpwatch_mark(argparse.Namespace(alert_id="1", status="known"))
    cli.cmd_arpwatch_mark(argparse.Namespace(alert_id="1", status="known"))  # no-op re-mark

    with Database(cfg.database_path()) as db:
        events = list_events(db.conn)
    review_events = [e for e in events if e.category == "alert_review_change"]
    assert len(review_events) == 1  # only the real transition, not the no-op re-mark


def test_arpwatch_mark_not_found_does_not_write_history(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()):
        pass  # ensure the db file/schema exists, empty

    rc, stdout = _run_capturing_stdout(cli.cmd_arpwatch_mark, argparse.Namespace(alert_id="999", status="known"))
    assert rc == 1  # existing exit code behavior unchanged
    assert "No arpwatch alert found" in stdout  # existing stdout text unchanged

    with Database(cfg.database_path()) as db:
        assert count_events(db.conn) == 0


def test_correlate_mark_alert_uses_module_count_as_subject(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_correlation_alert(
            db.conn, "run1", "fp1", 60.0, "2026-08-19T00:00:00", "2026-08-19T00:01:00",
            2, 3, 15, "high", "multi_module", None, "explanation",
            [{"module": "process", "kind": "new_process", "strength": "strong", "identifier": "p1",
              "label": None, "source_table": "x", "source_id": 1, "timestamp": "2026-08-19T00:00:00"}],
        )

    rc = cli.cmd_correlate_mark_alert(argparse.Namespace(alert_id="1", status="known"))
    assert rc == 0

    with Database(cfg.database_path()) as db:
        events = list_events(db.conn)
        alerts = list_correlation_alerts(db.conn)

    assert alerts[0].known is True
    review_events = [e for e in events if e.category == "alert_review_change"]
    assert len(review_events) == 1
    assert "2-module cluster" in review_events[0].message
    assert "correlation_alerts alert #1" in review_events[0].message
    assert "UNKNOWN -> KNOWN" in review_events[0].message


# ---------- `secure explain <source> <id>` (Stage 5) ----------


def test_cmd_explain_prints_confidence_and_recommended_action(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_persistence_alert(
            db.conn, "run1", "signing_changed", "high", "launch_agent", "com.example.x", "Example",
            "The executable behind 'Example' changed code-signing status since the last scan.",
        )

    rc, stdout = _run_capturing_stdout(
        cli.cmd_explain, argparse.Namespace(source="persistence", alert_id="1")
    )
    assert rc == 0
    assert "Severity:     high" in stdout
    assert "Confidence:   confirmed" in stdout
    assert "Recommended action: INVESTIGATE_NOW" in stdout


def test_cmd_explain_unknown_source(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(cli.cmd_explain, argparse.Namespace(source="not_a_source", alert_id="1"))
    assert rc == 1
    assert "Unknown source" in stdout


def test_cmd_explain_alert_not_found(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()):
        pass
    rc, stdout = _run_capturing_stdout(cli.cmd_explain, argparse.Namespace(source="arpwatch", alert_id="999"))
    assert rc == 1
    assert "No arpwatch alert found with id 999" in stdout


def test_cmd_explain_does_not_write_any_history_or_mutate_state(tmp_path: Path, monkeypatch):
    # Read-only: explaining an alert must never itself count as a
    # review-state change or write to the events table.
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_arp_alert(db.conn, "run1", "mac_changed", "low", "10.0.0.5", "aa:aa", "bb:bb", "MAC changed")

    _run_capturing_stdout(cli.cmd_explain, argparse.Namespace(source="arpwatch", alert_id="1"))

    with Database(cfg.database_path()) as db:
        assert count_events(db.conn) == 0
        assert list_arp_alerts(db.conn)[0].known is False
