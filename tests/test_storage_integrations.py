"""
Tests for the `since` lookback filter in
secure/storage/models/integrations.py's list_integration_observations().

Phase 17 added `since` for secure/integrations/sigma/scanner.py's
lookback window, and secure/integrations/zeek/dedup.py took it up too.
Both call sites pass it on every scan, so the clause runs constantly —
but nothing asserted what it does: with `created_at >= ?` removed
entirely, tests/test_integrations_{sigma,zeek,suricata,osquery}.py,
test_storage.py and test_detect_*.py all stayed green (287 passed).
An unbounded lookback is not a quiet defect in a detection engine: a
Sigma rule would keep re-firing on telemetry from weeks ago, so an
alert never ages out.

Named test_storage_integrations.py because targeted_test_files() maps
secure/storage/... to tests/test_storage*.py.

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from secure.storage.database import Database
from secure.storage.models import (
    add_integration_observations,
    list_integration_observations,
)

# Three fixed ingestion instants: one before the cutoff, the cutoff
# itself, and one after it. No wall-clock reads anywhere in this file.
BEFORE = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
CUTOFF = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
AFTER = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)


class _FrozenClock:
    """Stands in for the module's `datetime`, so add_integration_
    observations() stamps a created_at we choose. It is the module's own
    `datetime.now(tz)` seam, not a global patch."""

    def __init__(self, moment: datetime):
        self.moment = moment

    def now(self, tz=None) -> datetime:
        return self.moment


def _add_at(monkeypatch, conn, moment: datetime, *, integration: str, kind: str, key: str):
    """Insert one observation whose created_at is exactly `moment`."""
    import secure.storage.models.integrations as integrations_model

    monkeypatch.setattr(integrations_model, "datetime", _FrozenClock(moment))
    return add_integration_observations(
        conn,
        run_id=f"run-{key}",
        integration=integration,
        rows=[(kind, key, {"k": key}, "SELECT 1", moment.isoformat())],
    )


def test_frozen_clock_stamps_the_created_at_it_is_given(tmp_path: Path, monkeypatch):
    """Positive control for the seam every other test here relies on: if
    this fails, the `since` tests below prove nothing about `since`."""
    with Database(tmp_path / "test.db") as db:
        _add_at(monkeypatch, db.conn, BEFORE, integration="sigma", kind="processes", key="old")
        rows = list_integration_observations(db.conn)
        assert [r.created_at for r in rows] == [BEFORE.isoformat()]


def test_list_integration_observations_without_since_returns_every_row(tmp_path: Path, monkeypatch):
    """Positive control for the exclusion test: both rows really are
    stored, so an empty result there means `since` filtered them, not
    that the inserts silently failed."""
    with Database(tmp_path / "test.db") as db:
        _add_at(monkeypatch, db.conn, BEFORE, integration="sigma", kind="processes", key="old")
        _add_at(monkeypatch, db.conn, AFTER, integration="sigma", kind="processes", key="new")

        rows = list_integration_observations(db.conn)
        assert sorted(r.identity_key for r in rows) == ["new", "old"]


def test_list_integration_observations_since_excludes_rows_older_than_the_cutoff(
    tmp_path: Path, monkeypatch
):
    with Database(tmp_path / "test.db") as db:
        _add_at(monkeypatch, db.conn, BEFORE, integration="sigma", kind="processes", key="old")
        _add_at(monkeypatch, db.conn, AFTER, integration="sigma", kind="processes", key="new")

        rows = list_integration_observations(db.conn, since=CUTOFF.isoformat())
        assert [r.identity_key for r in rows] == ["new"]


def test_list_integration_observations_since_is_inclusive_of_its_own_boundary(
    tmp_path: Path, monkeypatch
):
    """The docstring calls `since` inclusive; assert the behaviour, so a
    silent `>` for `>=` drops the row sitting exactly on the cutoff."""
    with Database(tmp_path / "test.db") as db:
        _add_at(monkeypatch, db.conn, CUTOFF, integration="sigma", kind="processes", key="edge")

        rows = list_integration_observations(db.conn, since=CUTOFF.isoformat())
        assert [r.identity_key for r in rows] == ["edge"]


def test_list_integration_observations_since_is_ANDed_with_integration_and_kind(
    tmp_path: Path, monkeypatch
):
    """Four rows spanning both sides of the cutoff and two
    integration/kind pairs: only the row satisfying all three filters
    comes back, so a `since` that replaced the other clauses (or was
    ORed with them) fails here rather than passing quietly."""
    with Database(tmp_path / "test.db") as db:
        _add_at(monkeypatch, db.conn, BEFORE, integration="sigma", kind="processes", key="old-match")
        _add_at(monkeypatch, db.conn, AFTER, integration="zeek", kind="processes", key="new-other-integration")
        _add_at(monkeypatch, db.conn, AFTER, integration="sigma", kind="conn_log", key="new-other-kind")
        _add_at(monkeypatch, db.conn, AFTER, integration="sigma", kind="processes", key="wanted")

        rows = list_integration_observations(
            db.conn, integration="sigma", kind="processes", since=CUTOFF.isoformat()
        )
        assert [r.identity_key for r in rows] == ["wanted"]
