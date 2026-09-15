"""
Every optional `since` lookback filter under secure/storage/models/ must
be called with `since=` by some test (J-0269).

A `since` filter is easy to leave unasserted: every caller that omits it
still passes, and a filter on a column the module stamps itself with
datetime.now() gives a test no natural way to build the "before" row.
Measured at 6ada6d4 with the clause made a no-op, across the 162 tests
that reach these readers:

  * list_baseline_activity / list_baseline_feature_activity: survived.
    Neither had a production caller that passed `since` either, so the
    branch was removed rather than pinned.
  * list_anomaly_events: killed only by tests/test_cli_anomalies.py, and
    `observed_at >= ?` -> `>` survived. Pinned directly below.
  * list_integration_observations / list_recent_connection_events:
    already pinned by tests/test_storage_integrations.py and
    tests/test_storage_models_connections.py.

The sweep below is what keeps the next `since` from arriving untested.

Named test_storage_models_since.py because targeted_test_files() maps
secure/storage/... to tests/test_storage*.py.

Run with:  pytest
"""

from __future__ import annotations

import ast
from pathlib import Path

from secure.storage.database import Database
from secure.storage.models import add_anomaly_event, list_anomaly_events

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "secure" / "storage" / "models"
TESTS_DIR = ROOT / "tests"


def since_filters(sources: "dict[str, str]") -> "set[str]":
    """Names of top-level functions that take a `since` parameter."""
    found = set()
    for source in sources.values():
        for node in ast.parse(source).body:
            if isinstance(node, ast.FunctionDef):
                params = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                if any(p.arg == "since" for p in params):
                    found.add(node.name)
    return found


def names_called_with_since(sources: "dict[str, str]") -> "set[str]":
    """Names called as `name(..., since=...)` or `obj.name(..., since=...)`.

    A monkeypatch.setattr naming the function is a call to `setattr`, not
    to the function, so stubbing a reader out never counts as testing it.
    """
    called = set()
    for source in sources.values():
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Call):
                continue
            if not any(k.arg == "since" for k in node.keywords):
                continue
            if isinstance(node.func, ast.Name):
                called.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called.add(node.func.attr)
    return called


def unasserted_since_filters(models: "dict[str, str]", tests: "dict[str, str]") -> "list[str]":
    return sorted(since_filters(models) - names_called_with_since(tests))


def _read(paths) -> "dict[str, str]":
    return {str(p): p.read_text(encoding="utf-8") for p in paths}


def test_every_storage_since_filter_is_called_with_since_by_a_test():
    models = _read(sorted(MODELS_DIR.glob("*.py")))
    tests = _read(sorted(TESTS_DIR.glob("test_*.py")))
    assert unasserted_since_filters(models, tests) == []


def test_sweep_discovers_the_known_since_filters():
    """Discovery guard: a sweep that found nothing would pass the test
    above over an empty set."""
    models = _read(sorted(MODELS_DIR.glob("*.py")))
    assert since_filters(models) == {
        "list_anomaly_events",
        "list_integration_observations",
        "list_recent_connection_events",
    }


def test_sweep_flags_a_since_filter_no_test_passes_since_to():
    """Positive control: the sweep reports the gap it exists to find, and
    neither a call without `since` nor a monkeypatch counts as a test."""
    models = {"m.py": "def list_x(conn, since=None):\n    pass\n"}
    tests = {
        "t.py": (
            "def test_a(monkeypatch):\n"
            "    list_x(conn)\n"
            "    monkeypatch.setattr(models, 'list_x', lambda *a, since=None: [])\n"
        )
    }
    assert unasserted_since_filters(models, tests) == ["list_x"]

    tests["t.py"] += "    models.list_x(conn, since='2026-01-01')\n"
    assert unasserted_since_filters(models, tests) == []


# Three fixed observation instants: before the cutoff, on it, after it.
# `observed_at` is caller-supplied, so no clock is involved.
BEFORE = "2026-01-01T00:00:00+00:00"
CUTOFF = "2026-01-01T12:00:00+00:00"
AFTER = "2026-01-02T00:00:00+00:00"


def _add_event(conn, key: str, observed_at: str) -> None:
    add_anomaly_event(
        conn, run_id=f"run-{key}", entity_type="process", entity_key=key,
        feature_name="signing_status", observed_value="unsigned",
        observed_at=observed_at, expected_summary="No prior observations.",
        score_breakdown={"rarity": 10}, anomaly_score=10, anomaly_tier="low",
        maturity_state_at_time="learning", eligible_weight_total_at_time=0.0,
        eligible_distinct_days_at_time=0,
    )


def test_list_anomaly_events_without_since_returns_every_row(tmp_path: Path):
    """Positive control for the tests below: all three rows are stored."""
    with Database(tmp_path / "test.db") as db:
        for key, at in (("old", BEFORE), ("edge", CUTOFF), ("new", AFTER)):
            _add_event(db.conn, key, at)
        assert sorted(e.entity_key for e in list_anomaly_events(db.conn)) == ["edge", "new", "old"]


def test_list_anomaly_events_since_excludes_older_rows_and_keeps_its_boundary(tmp_path: Path):
    """The docstring calls `since` a lower bound on `observed_at`; the row
    sitting exactly on the cutoff is inside it, so `>=` -> `>` fails here."""
    with Database(tmp_path / "test.db") as db:
        for key, at in (("old", BEFORE), ("edge", CUTOFF), ("new", AFTER)):
            _add_event(db.conn, key, at)
        rows = list_anomaly_events(db.conn, since=CUTOFF)
        assert sorted(e.entity_key for e in rows) == ["edge", "new"]


def test_list_anomaly_events_since_is_anded_with_entity_type(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        _add_event(db.conn, "new-process", AFTER)
        _add_event(db.conn, "old-process", BEFORE)
        rows = list_anomaly_events(db.conn, entity_type="listening", since=CUTOFF)
        assert rows == []
        rows = list_anomaly_events(db.conn, entity_type="process", since=CUTOFF)
        assert [e.entity_key for e in rows] == ["new-process"]
