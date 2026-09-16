"""
Tests for the Baseline & Anomalies window's two text formatters,
`format_baseline_overview_text` and `format_anomaly_evidence_text` in
secure_gui/data_access.py.

Why this file exists
--------------------
Both functions used to live in secure_gui/baseline_view.py as
`_format_overview_text` / `_format_evidence_panel_text`. That module
does `import tkinter` at the top, and the interpreter this suite runs
under has no `_tkinter`, so no test could import them — not "no test
happened to", but no test *could*, which is the untestable-by-
construction case baseline_view.py's own docstring warns against
("Keep genuinely testable logic in secure_gui/data_access.py
instead"). They are pure text over BaselineOverview / AnomalyRow and
touch no widget, so data_access.py is where they belong.

How the inputs are built
------------------------
Through the real pipeline, never by hand-constructing the dataclasses:
a temp database seeded with secure.baseline.engine and
secure.storage.models, then `fetch_baseline_overview()` /
`list_all_anomalies()`. That is the same "seed a real temp DB" pattern
tests/test_gui_components.py uses, and it means a change to how an
AnomalyRow is assembled shows up here rather than being papered over by
a fixture that was written once and then drifted.

What is asserted
----------------
The figures the operator reads off the screen, not the exact prose: a
count that is wrong on the header is a wrong answer from a security
tool, whereas a reworded label is not. Two branch pairs are covered on
both sides, because that is where a formatter can silently lie:

  * `latest_run is None` -> "No baseline runs recorded yet." vs. a real
    run's status/started_at.
  * `row.source_table` set -> "Source: <table>#<id>" vs. the honest
    "(none recorded)" line. Invariant 5: a missing provenance record
    must say so, never render as a blank or a plausible-looking id.

Run with:  pytest tests/test_gui_baseline_formatters.py
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from secure.baseline import engine
from secure.baseline.entities import (
    LISTENING,
    PERSISTENCE,
    PROCESS,
    listening_key,
    persistence_key,
    process_key,
)
from secure.baseline.history import record_gap_observation
from secure.storage.database import Database
from secure.storage.models import (
    add_baseline_run,
    find_baseline_entity,
    set_baseline_entity_excluded,
)
from secure_gui.data_access import (
    fetch_baseline_overview,
    format_anomaly_evidence_text,
    format_baseline_overview_text,
    list_all_anomalies,
)

NOW = "2026-08-19T12:00:00+00:00"


def _seed_one_anomaly(conn) -> None:
    engine.evaluate_and_record_feature_observation(
        conn, "run1", LISTENING, listening_key("sshd", "22", "TCP"),
        "bind_scope", "network", NOW, is_network_bind=True,
    )


# ---------- format_baseline_overview_text ----------


def test_overview_text_on_empty_db_reports_zeroes_and_no_runs(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        overview = fetch_baseline_overview(db.conn)

    text = format_baseline_overview_text(overview)
    lines = text.splitlines()

    assert "Entities: 0" in lines
    # maturity_counts is empty on a fresh database, and the "By
    # maturity:" line is conditional on it — an empty dict must drop the
    # line entirely rather than render "By maturity: ".
    assert not any(line.startswith("By maturity:") for line in lines)
    assert "Excluded: 0   Frozen: 0" in lines
    assert "Anomalies: 0 total (0 unreviewed) — critical=0, high=0, medium=0, low=0" in lines
    assert "No baseline runs recorded yet." in lines


def test_overview_text_carries_the_real_counts(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        record_gap_observation(db.conn, "run1", PROCESS, process_key("/usr/bin/curl"), NOW)
        engine.evaluate_and_record_feature_observation(
            db.conn, "run2", PERSISTENCE,
            persistence_key("login_item", "/Applications/Dropbox.app"),
            "signing_status", "unsigned", NOW, is_unsigned=True,
        )
        overview = fetch_baseline_overview(db.conn)

    text = format_baseline_overview_text(overview)
    lines = text.splitlines()

    assert f"Entities: {overview.total_entities}" in lines
    assert "By maturity: learning=1" in lines
    assert f"Anomalies: {overview.total_anomalies} total " \
           f"({overview.unreviewed_anomalies} unreviewed) — " \
           f"critical={overview.tier_counts.get('critical', 0)}, " \
           f"high={overview.tier_counts.get('high', 0)}, " \
           f"medium={overview.tier_counts.get('medium', 0)}, " \
           f"low={overview.tier_counts.get('low', 0)}" in lines


def test_overview_text_reports_an_excluded_entity(tmp_path: Path):
    # Excluded/frozen counts share one line, so a formatter that read the
    # wrong field would still look well-formed. Pin the real numbers.
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        record_gap_observation(db.conn, "run1", PROCESS, process_key("/usr/bin/curl"), NOW)
        entity = find_baseline_entity(db.conn, PROCESS, process_key("/usr/bin/curl"))
        set_baseline_entity_excluded(db.conn, entity.id, True)
        overview = fetch_baseline_overview(db.conn)

    assert overview.excluded_count == 1
    assert "Excluded: 1   Frozen: 0" in format_baseline_overview_text(overview).splitlines()


def test_overview_text_names_the_latest_run(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_baseline_run(db.conn, "run1", NOW, NOW, 1.5, status="success")
        add_baseline_run(db.conn, "run2", NOW, NOW, 2.5, status="partial")
        overview = fetch_baseline_overview(db.conn)

    text = format_baseline_overview_text(overview)

    assert "No baseline runs recorded yet." not in text
    assert f"Latest run: {overview.latest_run.status} at {overview.latest_run.started_at} " \
           f"(2 total, 1 partial, 0 failed)" in text.splitlines()


# ---------- format_anomaly_evidence_text ----------


def test_evidence_text_carries_every_score_component_and_the_total(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _seed_one_anomaly(db.conn)
        row = list_all_anomalies(db.conn, limit=50)[0]

    text = format_anomaly_evidence_text(row)

    assert f"Expected: {row.expected_summary}" in text.splitlines()
    assert row.score_breakdown, "seed produced no score breakdown to format"
    for component, points in row.score_breakdown.items():
        assert f"  {component:18} {points}" in text.splitlines()
    assert f"  {'total':18} {row.anomaly_score}" in text.splitlines()


def test_evidence_text_carries_the_maturity_context_as_recorded(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _seed_one_anomaly(db.conn)
        row = list_all_anomalies(db.conn, limit=50)[0]

    lines = format_anomaly_evidence_text(row).splitlines()

    assert f"Maturity at time of observation: {row.maturity_state_at_time}" in lines
    assert f"Eligible weight at time: {row.eligible_weight_total_at_time:g} " \
           f"({row.eligible_distinct_days_at_time} distinct days)" in lines


def test_evidence_text_says_so_when_no_source_row_was_recorded(tmp_path: Path):
    # Invariant 5, no silent clean pass: an anomaly with no provenance
    # must SAY it has none. A blank "Source:" or an invented id would be
    # the failure this project refuses.
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _seed_one_anomaly(db.conn)
        row = list_all_anomalies(db.conn, limit=50)[0]

    assert row.source_table is None, "seed unexpectedly produced a source row"
    lines = format_anomaly_evidence_text(row).splitlines()

    assert "Source: (none recorded — see PROJECT_NOTES.md's provenance notes)" in lines
    assert not any(line.startswith("Source: None") for line in lines)


def test_evidence_text_cites_the_source_row_when_there_is_one(tmp_path: Path):
    # The other side of the branch above, so "says (none recorded)" is
    # not passing merely because the function always prints it.
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _seed_one_anomaly(db.conn)
        row = list_all_anomalies(db.conn, limit=50)[0]

    cited = replace(row, source_table="listening_ports", source_id=7)
    lines = format_anomaly_evidence_text(cited).splitlines()

    assert "Source: listening_ports#7" in lines
    assert not any(line.startswith("Source: (none recorded") for line in lines)


def test_evidence_text_lists_caveats_only_when_there_are_any(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        _seed_one_anomaly(db.conn)
        plain = list_all_anomalies(db.conn, limit=50)[0]

    # A feature-only entity type gets the "no entity-level record"
    # caveat from _anomaly_caveats(); assert against whatever the real
    # pipeline produced rather than assuming which branch fired.
    lines = format_anomaly_evidence_text(plain).splitlines()
    if plain.caveats:
        assert "Caveats:" in lines
        for caveat in plain.caveats:
            assert f"  - {caveat}" in lines
    else:
        assert "Caveats:" not in lines

    none_left = replace(plain, caveats=())
    assert "Caveats:" not in format_anomaly_evidence_text(none_left).splitlines()


# ---------- the boundary this move exists to hold ----------


def test_baseline_view_delegates_both_formatters_instead_of_redefining_them(tmp_path: Path):
    # baseline_view.py cannot be imported here (no _tkinter), so read it
    # as source: the point of the move is that the view holds no copy.
    # A second copy would drift silently, since only this one is tested.
    import ast

    source = Path(__file__).resolve().parent.parent / "secure_gui" / "baseline_view.py"
    tree = ast.parse(source.read_text())

    defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "_format_overview_text" not in defined
    assert "_format_evidence_panel_text" not in defined

    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "secure_gui.data_access"
        for alias in node.names
    }
    assert {"format_baseline_overview_text", "format_anomaly_evidence_text"} <= imported

    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert {"format_baseline_overview_text", "format_anomaly_evidence_text"} <= called
