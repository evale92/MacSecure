"""
Tests for the `since` lookback filter in
secure/storage/models/connections.py's list_recent_connection_events().

Phase 18 added `since` so secure/integrations/suricata/correlate.py
could bound its search for native connections to a window around an
alert's own timestamp; secure/integrations/zeek/dedup.py took it up
too. Both call sites pass it on every run
(suricata/correlate.py:105, zeek/dedup.py:135, each
`since=since, limit=2000`), so the clause executes constantly — and
nothing asserted what it does. Measured 2026-09-12: with the
`created_at >= ?` branch made inert, tests/test_storage.py,
test_connections.py, test_connection_events_provenance.py,
test_integrations_suricata.py, test_integrations_zeek.py,
test_baseline_process_destination.py and test_investigate_resolve.py
all stayed green (241 passed). Across the whole suite there were
exactly three `since=` call sites in tests/, all of them for
list_integration_observations() — the sibling filter closed by
tests/test_storage_integrations.py. This one, the other half of the
same pair, had none.

An unbounded lookback here is not a quiet defect. Suricata
correlation would tie an alert to a connection observed arbitrarily
far in the past, and zeek dedup would suppress a native event as a
duplicate of something it never coincided with — both of which read,
downstream, as a confident finding rather than as a missing bound.

Named test_storage_models_connections.py because targeted_test_files()
maps secure/storage/... to tests/test_storage*.py.

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from secure.storage.database import Database
from secure.storage.models import (
    add_connection_events,
    list_recent_connection_events,
)

# Three fixed observation instants: one before the cutoff, the cutoff
# itself, and one after it. No wall-clock reads anywhere in this file.
BEFORE = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
CUTOFF = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
AFTER = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)


class _FrozenClock:
    """Stands in for the module's `datetime`, so add_connection_events()
    stamps a created_at we choose. It is the module's own
    `datetime.now(tz)` seam, not a global patch."""

    def __init__(self, moment: datetime):
        self.moment = moment

    def now(self, tz=None) -> datetime:
        return self.moment


def _add_at(monkeypatch, conn, moment: datetime, *, process_name: str, port: int = 443):
    """Insert one connection event whose created_at is exactly `moment`.

    One call is one batch, because add_connection_events() stamps a
    single created_at across the whole batch it is given.
    """
    import secure.storage.models.connections as connections_model

    monkeypatch.setattr(connections_model, "datetime", _FrozenClock(moment))
    return add_connection_events(
        conn,
        run_id=f"run-{process_name}",
        rows=[("tcp", "192.168.1.10", 51000, "203.0.113.5", port, "ESTABLISHED", 501, process_name)],
    )


def test_frozen_clock_stamps_the_created_at_it_is_given(tmp_path: Path, monkeypatch):
    """Positive control for the seam every other test here relies on: if
    this fails, the `since` tests below prove nothing about `since`."""
    with Database(tmp_path / "test.db") as db:
        _add_at(monkeypatch, db.conn, BEFORE, process_name="old")
        rows = list_recent_connection_events(db.conn)
        assert [r.created_at for r in rows] == [BEFORE.isoformat()]


def test_list_recent_connection_events_without_since_returns_every_row(
    tmp_path: Path, monkeypatch
):
    """Positive control for the exclusion test: both rows really are
    stored, so a short result there means `since` filtered them, not
    that the inserts silently failed."""
    with Database(tmp_path / "test.db") as db:
        _add_at(monkeypatch, db.conn, BEFORE, process_name="old")
        _add_at(monkeypatch, db.conn, AFTER, process_name="new")

        rows = list_recent_connection_events(db.conn)
        assert sorted(r.process_name for r in rows) == ["new", "old"]


def test_list_recent_connection_events_since_excludes_rows_older_than_the_cutoff(
    tmp_path: Path, monkeypatch
):
    with Database(tmp_path / "test.db") as db:
        _add_at(monkeypatch, db.conn, BEFORE, process_name="old")
        _add_at(monkeypatch, db.conn, AFTER, process_name="new")

        rows = list_recent_connection_events(db.conn, since=CUTOFF.isoformat())
        assert [r.process_name for r in rows] == ["new"]


def test_list_recent_connection_events_since_is_inclusive_of_its_own_boundary(
    tmp_path: Path, monkeypatch
):
    """The docstring calls `since` inclusive (`created_at >= since`);
    assert the behaviour, so a silent `>` for `>=` drops the row sitting
    exactly on the cutoff instead of returning it."""
    with Database(tmp_path / "test.db") as db:
        _add_at(monkeypatch, db.conn, CUTOFF, process_name="edge")

        rows = list_recent_connection_events(db.conn, since=CUTOFF.isoformat())
        assert [r.process_name for r in rows] == ["edge"]


def test_list_recent_connection_events_since_still_honours_limit_and_ordering(
    tmp_path: Path, monkeypatch
):
    """The `since` branch is a second, separate SELECT that binds
    `(since, limit)`. Four rows — one below the cutoff, three above —
    with since=CUTOFF and limit=2: the two newest above the cutoff come
    back, newest first, and the row below it never appears. A swapped
    binding, a dropped LIMIT, or a lost ORDER BY in that branch fails
    here rather than passing quietly.
    """
    with Database(tmp_path / "test.db") as db:
        _add_at(monkeypatch, db.conn, BEFORE, process_name="old", port=1)
        _add_at(monkeypatch, db.conn, AFTER, process_name="new-1", port=2)
        _add_at(monkeypatch, db.conn, AFTER, process_name="new-2", port=3)
        _add_at(monkeypatch, db.conn, AFTER, process_name="new-3", port=4)

        rows = list_recent_connection_events(db.conn, limit=2, since=CUTOFF.isoformat())
        assert [r.process_name for r in rows] == ["new-3", "new-2"]
