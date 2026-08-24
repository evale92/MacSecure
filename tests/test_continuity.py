"""
Tests for secure/continuity.py (the "Snapshot" / Continuity feature).

Run with:  pytest
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.checks.models import CheckResult, CheckStatus
from secure.continuity import (
    FileChange,
    _find_recent_files,
    find_recent_launch_items,
    take_snapshot,
)
from secure.storage.database import Database
from secure.storage.models import list_recent_posture_results, list_recent_snapshots


def _touch(path: Path, when: datetime) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("content")
    ts = when.timestamp()
    os.utime(path, (ts, ts))


# ---------- _find_recent_files ----------


def test_find_recent_files_filters_by_time(tmp_path: Path):
    now = datetime.now(timezone.utc)
    old_file = tmp_path / "old.txt"
    new_file = tmp_path / "new.txt"
    _touch(old_file, now - timedelta(hours=2))
    _touch(new_file, now - timedelta(minutes=1))

    since = now - timedelta(minutes=15)
    changes, truncated = _find_recent_files(tmp_path, since)

    paths = {c.path for c in changes}
    assert "new.txt" in paths
    assert "old.txt" not in paths
    assert truncated is False


def test_find_recent_files_excludes_dirs_and_names(tmp_path: Path):
    now = datetime.now(timezone.utc)
    _touch(tmp_path / ".venv" / "lib" / "thing.py", now)
    _touch(tmp_path / "secure.db", now)
    _touch(tmp_path / "keep.py", now)

    since = now - timedelta(minutes=15)
    changes, _ = _find_recent_files(
        tmp_path,
        since,
        exclude_dir_names=frozenset({".venv"}),
        exclude_file_names=frozenset({"secure.db"}),
    )

    paths = {c.path for c in changes}
    assert paths == {"keep.py"}


def test_find_recent_files_truncates(tmp_path: Path):
    now = datetime.now(timezone.utc)
    for i in range(5):
        _touch(tmp_path / f"f{i}.txt", now)

    changes, truncated = _find_recent_files(
        tmp_path, now - timedelta(minutes=1), limit=3
    )

    assert len(changes) == 3
    assert truncated is True


def test_find_recent_files_missing_root_returns_empty(tmp_path: Path):
    missing = tmp_path / "does-not-exist"
    changes, truncated = _find_recent_files(missing, datetime.now(timezone.utc))
    assert changes == []
    assert truncated is False


# ---------- find_recent_launch_items ----------


def test_find_recent_launch_items(tmp_path: Path):
    now = datetime.now(timezone.utc)
    fake_dir = tmp_path / "LaunchAgents"
    fake_dir.mkdir()
    recent_plist = fake_dir / "com.example.recent.plist"
    old_plist = fake_dir / "com.example.old.plist"
    not_a_plist = fake_dir / "readme.txt"
    _touch(recent_plist, now)
    _touch(old_plist, now - timedelta(hours=5))
    _touch(not_a_plist, now)

    since = now - timedelta(minutes=15)
    changes = find_recent_launch_items(since, directories=[fake_dir])

    paths = {Path(c.path).name for c in changes}
    assert paths == {"com.example.recent.plist"}


def test_find_recent_launch_items_missing_dir_is_skipped(tmp_path: Path):
    missing = tmp_path / "nope"
    changes = find_recent_launch_items(
        datetime.now(timezone.utc) - timedelta(minutes=15), directories=[missing]
    )
    assert changes == []


# ---------- take_snapshot (end-to-end) ----------


def _fake_results(firewall_status: CheckStatus) -> list[CheckResult]:
    return [
        CheckResult("FileVault", CheckStatus.PASS, "FileVault is On.", ""),
        CheckResult("Firewall", firewall_status, "firewall message", "fix it"),
    ]


def test_take_snapshot_first_run_has_no_baseline(tmp_path: Path, monkeypatch):
    import secure.continuity as continuity

    monkeypatch.setattr(
        continuity, "run_all_checks", lambda include_pending_updates=True: _fake_results(CheckStatus.PASS)
    )

    project_root = tmp_path / "project"
    app_dir = tmp_path / "home" / ".secure"
    project_root.mkdir(parents=True)
    app_dir.mkdir(parents=True)
    _touch(project_root / "changed.py", datetime.now(timezone.utc))

    db_path = app_dir / "secure.db"
    with Database(db_path) as db:
        snapshot = take_snapshot(
            db.conn, app_dir=app_dir, window_minutes=15, project_root=project_root
        )

        assert snapshot.posture_baseline_at is None
        assert snapshot.posture_diffs == []
        assert any(c.path == "changed.py" for c in snapshot.project_file_changes)
        assert snapshot.db_id is not None

        stored_snapshots = list_recent_snapshots(db.conn, limit=10)
        stored_posture = list_recent_posture_results(db.conn, limit=10)

    assert len(stored_snapshots) == 1
    assert len(stored_posture) == 2  # FileVault + Firewall from _fake_results

    assert snapshot.json_path is not None
    saved = json.loads(Path(snapshot.json_path).read_text())
    assert saved["window_minutes"] == 15
    assert any(c["path"] == "changed.py" for c in saved["project_file_changes"])


def test_take_snapshot_detects_posture_change(tmp_path: Path, monkeypatch):
    import secure.continuity as continuity

    project_root = tmp_path / "project"
    app_dir = tmp_path / "home" / ".secure"
    project_root.mkdir(parents=True)
    app_dir.mkdir(parents=True)

    db_path = app_dir / "secure.db"
    with Database(db_path) as db:
        # First run: firewall PASS (becomes the baseline for the next run).
        monkeypatch.setattr(
            continuity,
            "run_all_checks",
            lambda include_pending_updates=True: _fake_results(CheckStatus.PASS),
        )
        first = take_snapshot(
            db.conn, app_dir=app_dir, window_minutes=15, project_root=project_root
        )
        assert first.posture_diffs == []

        # Second run: firewall now FAIL — should show up as a diff
        # against the first run's results.
        monkeypatch.setattr(
            continuity,
            "run_all_checks",
            lambda include_pending_updates=True: _fake_results(CheckStatus.FAIL),
        )
        second = take_snapshot(
            db.conn, app_dir=app_dir, window_minutes=15, project_root=project_root
        )

    # baseline_at comes from the stored posture row's own timestamp,
    # not snapshot.taken_at (they're captured a beat apart) — just
    # confirm a baseline was found at all, and focus on the diff.
    assert second.posture_baseline_at is not None
    assert len(second.posture_diffs) == 1
    diff = second.posture_diffs[0]
    assert diff.check_name == "Firewall"
    assert diff.previous_status == "PASS"
    assert diff.current_status == "FAIL"


def test_take_snapshot_excludes_own_db_and_log(tmp_path: Path, monkeypatch):
    import secure.continuity as continuity

    monkeypatch.setattr(
        continuity, "run_all_checks", lambda include_pending_updates=True: _fake_results(CheckStatus.PASS)
    )

    project_root = tmp_path / "project"
    app_dir = tmp_path / "home" / ".secure"
    project_root.mkdir(parents=True)
    app_dir.mkdir(parents=True)

    db_path = app_dir / "secure.db"
    with Database(db_path) as db:
        # secure.db now exists (just created) and will get written to
        # by this very call — it must not show up as an "app state
        # change" or every snapshot would trivially report itself.
        snapshot = take_snapshot(
            db.conn, app_dir=app_dir, window_minutes=15, project_root=project_root
        )

    names = {c.path for c in snapshot.app_state_changes}
    assert "secure.db" not in names
    assert "secure.log" not in names


def test_take_snapshot_json_files_dont_collide_within_same_second(tmp_path: Path, monkeypatch):
    """Two snapshots taken back-to-back must not overwrite each other's JSON file."""
    import secure.continuity as continuity

    monkeypatch.setattr(
        continuity, "run_all_checks", lambda include_pending_updates=True: _fake_results(CheckStatus.PASS)
    )

    project_root = tmp_path / "project"
    app_dir = tmp_path / "home" / ".secure"
    project_root.mkdir(parents=True)
    app_dir.mkdir(parents=True)

    db_path = app_dir / "secure.db"
    with Database(db_path) as db:
        first = take_snapshot(db.conn, app_dir=app_dir, window_minutes=15, project_root=project_root)
        second = take_snapshot(db.conn, app_dir=app_dir, window_minutes=15, project_root=project_root)

    assert first.json_path != second.json_path
    assert Path(first.json_path).exists()
    assert Path(second.json_path).exists()
