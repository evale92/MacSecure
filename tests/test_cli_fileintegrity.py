"""
Tests for the `secure fileintegrity` CLI command group
(scan/watch-add/watch-list/watch-remove/files/mark-file/events/alerts/
mark-alert), defined in secure/cli/fileintegrity.py.

Why this file exists: before it, all nine `cmd_fileintegrity_*`
handlers had zero test call sites. `tests/test_fileintegrity.py` tests
the *engine* under `secure/fileintegrity/`, not this module, and
`tests/test_cli_alert_history.py` reaches `_record_alert_review_change`
directly rather than through `cmd_fileintegrity_mark_alert`. Verified
by inserting an undefined-name marker as the first statement of each of
the nine handlers: the whole `tests/test_cli*.py` set — which is what
`secure.agent.tiers.targeted_test_files()` maps `secure/cli/*.py` onto
— passed unchanged, so nothing executed a single one of them.

Follows the same isolated-temp-app-dir pattern as
tests/test_cli_baseline.py: every cmd_* reads the real
~/.secure/config.json via _bootstrap() by default, so
`secure.cli.load_config` is monkeypatched to a temp app_dir and nothing
here touches the operator's home directory.

`cmd_fileintegrity_scan` is the one handler whose engine call is
stubbed. scan_file_integrity() seeds the real default watch paths and
walks them, which would read outside the working directory; the CLI
module's own job is presentation and the exit code, and that is what is
asserted here. The engine itself is covered by
tests/test_fileintegrity.py.

Run with:  pytest
"""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path

from secure import cli
from secure.cli import fileintegrity as cli_fileintegrity
from secure.config import load_config
from secure.fileintegrity.scanner import FileIntegrityAlert, FileIntegrityScanResult
from secure.storage.database import Database
from secure.storage.models import (
    add_file_change_event,
    add_file_integrity_alert,
    add_watch_path,
    find_file_integrity_alert_by_id,
    find_watch_path_by_id,
    insert_file_entry,
    list_events,
)


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


def _scan_result(alerts=None) -> FileIntegrityScanResult:
    return FileIntegrityScanResult(
        run_id="run-abc123",
        scanned_at="2026-09-12T00:00:00+00:00",
        duration_seconds=1.5,
        watch_paths_attempted=["/tmp/a", "/tmp/b"],
        watch_paths_completed=["/tmp/a"],
        watch_paths_incomplete=[{"path": "/tmp/b", "reasons": {"/tmp/b/x": "permission denied"}}],
        files_visited=10,
        files_hashed=4,
        files_skipped_unchanged=3,
        files_skipped_too_large=1,
        files_skipped_excluded=1,
        files_unreadable=1,
        alerts=list(alerts or []),
    )


# ---------- scan ----------


def test_fileintegrity_scan_with_no_alerts_exits_zero(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    monkeypatch.setattr(cli_fileintegrity, "scan_file_integrity", lambda conn: _scan_result())

    rc, stdout = _run_capturing_stdout(cli_fileintegrity.cmd_fileintegrity_scan, _ns())

    assert rc == 0
    assert "No alert-worthy file integrity changes this scan." in stdout
    assert "run id: run-abc123" in stdout


def test_fileintegrity_scan_reports_incomplete_watch_paths(tmp_path: Path, monkeypatch):
    # An incomplete watch path is an honest-absence signal (AGENTS.md
    # rule 7): the scan did not cover everything it was asked to, and
    # the operator has to be told which path and why.
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    monkeypatch.setattr(cli_fileintegrity, "scan_file_integrity", lambda conn: _scan_result())

    _, stdout = _run_capturing_stdout(cli_fileintegrity.cmd_fileintegrity_scan, _ns())

    assert "1 fully scanned, 1 incomplete (of 2 attempted)" in stdout
    assert "INCOMPLETE: /tmp/b" in stdout
    assert "permission denied" in stdout


def test_fileintegrity_scan_with_persisted_alerts_exits_one(tmp_path: Path, monkeypatch):
    # The exit code is the whole point: a scan that found alert-worthy
    # changes must not report success to a caller that only checks $?.
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    alert = FileIntegrityAlert(
        kind="content_changed", severity="high", path="/etc/hosts",
        message="Content hash changed", context_notes="outside an update window", id=7,
    )
    monkeypatch.setattr(
        cli_fileintegrity, "scan_file_integrity", lambda conn: _scan_result([alert])
    )

    rc, stdout = _run_capturing_stdout(cli_fileintegrity.cmd_fileintegrity_scan, _ns())

    assert rc == 1
    assert "ALERTS (1):" in stdout
    assert "#7 [HIGH] content_changed — /etc/hosts" in stdout
    assert "Context: outside an update window" in stdout


def test_fileintegrity_scan_counts_only_persisted_alerts_for_its_exit_code(
    tmp_path: Path, monkeypatch
):
    # An alert with id None was never persisted (low severity, history
    # only). It must not raise the exit code, and the operator must
    # still be told it exists rather than it vanishing silently.
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    unpersisted = FileIntegrityAlert(
        kind="mtime_changed", severity="low", path="/tmp/a/f", message="mtime moved", id=None,
    )
    monkeypatch.setattr(
        cli_fileintegrity, "scan_file_integrity", lambda conn: _scan_result([unpersisted])
    )

    rc, stdout = _run_capturing_stdout(cli_fileintegrity.cmd_fileintegrity_scan, _ns())

    assert rc == 0
    assert "No alert-worthy file integrity changes this scan." in stdout
    assert "1 additional low-severity change(s) recorded in history" in stdout


# ---------- watch-add / watch-list / watch-remove ----------


def test_fileintegrity_watch_add_registers_a_new_path(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    target = tmp_path / "watched"
    target.mkdir()

    rc, stdout = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_watch_add,
        _ns(path=str(target), no_recursive=False, sensitivity="startup"),
    )

    assert rc == 0
    assert "Added watch path #" in stdout
    assert "sensitivity: startup" in stdout
    with Database(cfg.database_path()) as db:
        record = find_watch_path_by_id(db.conn, 1)
    assert record is not None
    assert record.recursive is True
    assert record.sensitivity == "startup"


def test_fileintegrity_watch_add_is_idempotent_on_the_same_path(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    target = tmp_path / "watched"
    target.mkdir()
    args = _ns(path=str(target), no_recursive=True, sensitivity="normal")

    rc_first, _ = _run_capturing_stdout(cli_fileintegrity.cmd_fileintegrity_watch_add, args)
    rc_second, second = _run_capturing_stdout(cli_fileintegrity.cmd_fileintegrity_watch_add, args)

    assert rc_first == 0 and rc_second == 0
    assert "already registered as #1" in second


def test_fileintegrity_watch_list_empty_points_at_how_to_populate_it(
    tmp_path: Path, monkeypatch
):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(cli_fileintegrity.cmd_fileintegrity_watch_list, _ns())
    assert rc == 0
    assert "No watch paths registered yet." in stdout


def test_fileintegrity_watch_list_shows_registered_paths(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_watch_path(db.conn, path="/etc/hosts", recursive=False, sensitivity="normal")

    rc, stdout = _run_capturing_stdout(cli_fileintegrity.cmd_fileintegrity_watch_list, _ns())

    assert rc == 0
    assert "/etc/hosts" in stdout
    assert "enabled" in stdout
    assert "never scanned" in stdout


def test_fileintegrity_watch_remove_unknown_id_returns_one(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_watch_remove, _ns(watch_path_id=999)
    )
    assert rc == 1
    assert "No watch path found with id 999" in stdout


def test_fileintegrity_watch_remove_disables_rather_than_deletes(tmp_path: Path, monkeypatch):
    # "Its recorded history is kept" is the command's own promise; the
    # row must survive, disabled, not disappear.
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        record, _ = add_watch_path(db.conn, path="/etc/hosts")

    rc, stdout = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_watch_remove, _ns(watch_path_id=record.id)
    )

    assert rc == 0
    assert "Disabled watch path #" in stdout
    with Database(cfg.database_path()) as db:
        still_there = find_watch_path_by_id(db.conn, record.id)
    assert still_there is not None
    assert still_there.enabled is False


# ---------- files / mark-file ----------


_METADATA = {
    "hash": "abc123", "size": 42, "mode": "0644",
    "is_executable": False, "is_symlink": False, "unreadable": False,
}


def _seed_entry(conn, path: str = "/etc/hosts") -> int:
    record, _ = add_watch_path(conn, path=path)
    return record.id


def test_fileintegrity_files_empty_says_so(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_files, _ns(limit=200)
    )
    assert rc == 0
    assert "No files recorded yet." in stdout


def test_fileintegrity_files_lists_entries_with_their_review_state(
    tmp_path: Path, monkeypatch
):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        wp_id = _seed_entry(db.conn)
        insert_file_entry(
            db.conn, watch_path_id=wp_id, path="/etc/hosts",
            metadata=_METADATA, known=False,
        )

    rc, stdout = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_files, _ns(limit=200)
    )

    assert rc == 0
    assert "[UNKNOWN]" in stdout
    assert "/etc/hosts" in stdout
    assert "abc123" in stdout


def test_fileintegrity_mark_file_unknown_id_returns_one(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_mark_file, _ns(entry_id=999, status="known")
    )
    assert rc == 1
    assert "No file entry found with id 999" in stdout


def test_fileintegrity_mark_file_flips_the_known_flag(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        wp_id = _seed_entry(db.conn)
        entry_id = insert_file_entry(
            db.conn, watch_path_id=wp_id, path="/etc/hosts",
            metadata=_METADATA, known=False,
        ).id

    rc, stdout = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_mark_file, _ns(entry_id=entry_id, status="known")
    )
    assert rc == 0
    assert "as known." in stdout

    _, listing = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_files, _ns(limit=200)
    )
    assert "[KNOWN  ]" in listing

    rc, _ = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_mark_file, _ns(entry_id=entry_id, status="unknown")
    )
    assert rc == 0
    _, listing = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_files, _ns(limit=200)
    )
    assert "[UNKNOWN]" in listing


# ---------- events ----------


def test_fileintegrity_events_empty_says_so(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_events, _ns(path=None, limit=200)
    )
    assert rc == 0
    assert "No file change events recorded yet." in stdout


def test_fileintegrity_events_path_filter_actually_bounds_the_listing(
    tmp_path: Path, monkeypatch
):
    # The --path filter has to exclude something. Without a second,
    # non-matching event this assertion would hold even if `path` were
    # dropped on the floor.
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        wp_id = _seed_entry(db.conn)
        add_file_change_event(
            db.conn, run_id="r1", watch_path_id=wp_id, path="/etc/hosts",
            change_type="content_changed", details={"reasons": ["hash changed"]},
        )
        add_file_change_event(
            db.conn, run_id="r1", watch_path_id=wp_id, path="/etc/passwd",
            change_type="content_changed", details={"reasons": ["hash changed"]},
        )

    _, unfiltered = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_events, _ns(path=None, limit=200)
    )
    assert "/etc/hosts" in unfiltered and "/etc/passwd" in unfiltered

    rc, filtered = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_events, _ns(path="/etc/hosts", limit=200)
    )
    assert rc == 0
    assert "/etc/hosts" in filtered
    assert "/etc/passwd" not in filtered
    assert "hash changed" in filtered


def test_fileintegrity_events_shows_the_old_path_of_a_rename(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        wp_id = _seed_entry(db.conn)
        add_file_change_event(
            db.conn, run_id="r1", watch_path_id=wp_id, path="/etc/hosts.new",
            change_type="renamed", details={}, old_path="/etc/hosts",
        )

    _, stdout = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_events, _ns(path=None, limit=200)
    )
    assert "/etc/hosts.new (from /etc/hosts)" in stdout


# ---------- alerts / mark-alert ----------


def test_fileintegrity_alerts_empty_says_so(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(cli_fileintegrity.cmd_fileintegrity_alerts, _ns())
    assert rc == 0
    assert "No file integrity alerts recorded yet." in stdout


def test_fileintegrity_alerts_lists_recorded_alerts(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_file_integrity_alert(
            db.conn, run_id="r1", kind="content_changed", severity="high",
            path="/etc/hosts", message="Content hash changed", context_notes="no update window",
        )

    rc, stdout = _run_capturing_stdout(cli_fileintegrity.cmd_fileintegrity_alerts, _ns())

    assert rc == 0
    assert "[UNKNOWN]" in stdout
    assert "[HIGH  ]" in stdout
    assert "Content hash changed" in stdout
    assert "Context: no update window" in stdout


def test_fileintegrity_mark_alert_unknown_id_returns_one(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_mark_alert, _ns(alert_id=999, status="known")
    )
    assert rc == 1
    assert "No file integrity alert found with id 999" in stdout


def test_fileintegrity_mark_alert_writes_the_review_audit_trail(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        alert_id = add_file_integrity_alert(
            db.conn, run_id="r1", kind="content_changed", severity="high",
            path="/etc/hosts", message="Content hash changed",
        )

    rc, stdout = _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_mark_alert, _ns(alert_id=alert_id, status="known")
    )

    assert rc == 0
    assert "as known." in stdout
    with Database(cfg.database_path()) as db:
        assert find_file_integrity_alert_by_id(db.conn, alert_id).known is True
        events = [e for e in list_events(db.conn, limit=100) if e.category == "alert_review_change"]
    assert len(events) == 1
    assert "file_integrity_alerts alert #%d" % alert_id in events[0].message
    assert "UNKNOWN -> KNOWN" in events[0].message
    assert "severity=high" in events[0].message
    # The concise subject, not the alert's full message text.
    assert "/etc/hosts" in events[0].message
    assert "Content hash changed" not in events[0].message


def test_fileintegrity_mark_alert_records_nothing_when_the_state_does_not_change(
    tmp_path: Path, monkeypatch
):
    # _record_alert_review_change's docstring: "Callers are expected to
    # only invoke this when was_known != now_known". Re-marking an
    # already-known alert must not pile up a second transition row.
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        alert_id = add_file_integrity_alert(
            db.conn, run_id="r1", kind="content_changed", severity="high",
            path="/etc/hosts", message="Content hash changed",
        )
    args = _ns(alert_id=alert_id, status="known")

    _run_capturing_stdout(cli_fileintegrity.cmd_fileintegrity_mark_alert, args)
    rc, _ = _run_capturing_stdout(cli_fileintegrity.cmd_fileintegrity_mark_alert, args)

    assert rc == 0
    with Database(cfg.database_path()) as db:
        events = [e for e in list_events(db.conn, limit=100) if e.category == "alert_review_change"]
    assert len(events) == 1

    # Positive control: a real transition does append a second row.
    _run_capturing_stdout(
        cli_fileintegrity.cmd_fileintegrity_mark_alert, _ns(alert_id=alert_id, status="unknown")
    )
    with Database(cfg.database_path()) as db:
        events = [e for e in list_events(db.conn, limit=100) if e.category == "alert_review_change"]
    assert len(events) == 2
    # list_events() is newest-first (ORDER BY id DESC).
    assert "KNOWN -> UNKNOWN" in events[0].message
    assert "UNKNOWN -> KNOWN" in events[1].message
