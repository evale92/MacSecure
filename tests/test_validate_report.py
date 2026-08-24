"""
Tests for secure/validate/report.py — Phase 27 Stage 7. This module's
one job is honest, complete formatting: every scenario a run recorded
must appear, no aggregate percentage/score may ever be computed, and
MISS/PARTIAL rows must be impossible to miss.

Run with:  pytest
"""

from __future__ import annotations

import json
from pathlib import Path

from secure.storage.database import Database
from secure.storage.models.validate import ValidationRunRecord, ValidationScenarioResultRecord
from secure.validate.report import generate_json_report, generate_markdown_report, write_report
from secure.validate.runner import run_validation_suite

_RUN = ValidationRunRecord(
    id=1,
    run_id="test-run-1",
    started_at="2026-01-01T00:00:00+00:00",
    completed_at="2026-01-01T00:00:05+00:00",
    secure_version="0.1.0",
    scenario_count=2,
    detail="PASS=1, MISS=1",
)


def _result(**overrides) -> ValidationScenarioResultRecord:
    base = dict(
        id=1,
        run_id="test-run-1",
        scenario_id="fake_scenario",
        technique_id="T1234",
        technique_name="Fake Technique",
        category="persistence_creation",
        description="A fake scenario for report-generator tests.",
        expected_result="Something should happen.",
        sensors_observed=["persistence"],
        findings=[{"table": "persistence_alerts", "id": 1, "severity": "high"}],
        correlation_result=None,
        explanation_checklist={"has_severity": True},
        dedup_result=None,
        latency_ms=12.3,
        outcome="PASS",
        notes="",
        started_at="2026-01-01T00:00:00+00:00",
        completed_at="2026-01-01T00:00:01+00:00",
    )
    base.update(overrides)
    return ValidationScenarioResultRecord(**base)


# ---------- markdown honesty properties ----------


def test_markdown_report_never_contains_a_percent_sign():
    # Governing instruction: "Never calculate a misleading overall
    # 'security percentage'." A literal '%' anywhere in the rendered
    # report would mean something snuck an aggregate score in.
    results = [_result(scenario_id="a", outcome="PASS"), _result(scenario_id="b", outcome="MISS")]
    md = generate_markdown_report(_RUN, results)
    assert "%" not in md


def test_markdown_report_includes_every_outcome_count_even_zero():
    results = [_result(scenario_id="only_pass", outcome="PASS")]
    md = generate_markdown_report(_RUN, results)
    for outcome in ("PASS", "PARTIAL", "MISS", "NOT_EVALUABLE", "SENSOR_UNAVAILABLE"):
        assert f"**{outcome}:**" in md


def test_markdown_report_never_omits_a_miss_scenario():
    miss = _result(
        scenario_id="a_real_miss", outcome="MISS", notes="Expected alert did not fire — this is a genuine gap."
    )
    md = generate_markdown_report(_RUN, [_result(scenario_id="a_pass"), miss])
    assert "a_real_miss" in md
    assert "a genuine gap" in md
    # Must appear in BOTH the "Failures and Gaps" highlight section and
    # the full per-scenario detail — never filtered out of either.
    assert md.count("a_real_miss") >= 2


def test_markdown_report_failures_section_says_no_failures_only_when_true():
    md_clean = generate_markdown_report(_RUN, [_result(outcome="PASS")])
    assert "No MISS or PARTIAL outcomes" in md_clean

    md_dirty = generate_markdown_report(_RUN, [_result(outcome="MISS")])
    assert "No MISS or PARTIAL outcomes" not in md_dirty


def test_markdown_report_includes_not_evaluable_and_sensor_unavailable_rows():
    results = [
        _result(scenario_id="ne", outcome="NOT_EVALUABLE", notes="documented capability gap"),
        _result(scenario_id="su", outcome="SENSOR_UNAVAILABLE", notes="tool not installed"),
    ]
    md = generate_markdown_report(_RUN, results)
    assert "ne" in md and "documented capability gap" in md
    assert "su" in md and "tool not installed" in md


# ---------- JSON report ----------


def test_json_report_scenario_count_matches_input_and_is_unfiltered():
    results = [_result(scenario_id=f"s{i}", outcome="PASS" if i % 2 == 0 else "MISS") for i in range(6)]
    report = generate_json_report(_RUN, results)
    assert report["total_scenarios"] == 6
    assert len(report["scenarios"]) == 6
    assert sum(report["outcome_counts"].values()) == 6
    assert report["outcome_counts"]["MISS"] == 3


def test_json_report_has_no_aggregate_score_field():
    report = generate_json_report(_RUN, [_result()])
    # No key anywhere in the top-level report should represent a single
    # reduced score — only the per-outcome counts breakdown.
    assert "score" not in report
    assert "percentage" not in report
    assert "grade" not in report
    assert json.dumps(report)  # round-trips cleanly through json


# ---------- write_report (file I/O + DB wiring) ----------


def _raises(fn, exc_type) -> bool:
    """House style for this sandbox: no real pytest is installed, so
    every raise-assertion uses this helper instead of pytest.raises
    (see tests/test_integrations_sigma.py's own _raises())."""
    try:
        fn()
    except exc_type:
        return True
    return False


def test_write_report_raises_when_no_run_exists(tmp_path: Path):
    with Database(tmp_path / "empty.db") as db:
        assert _raises(lambda: write_report(db.conn, output_dir=tmp_path / "out"), ValueError)


def test_write_report_writes_both_markdown_and_json_by_default(tmp_path: Path):
    with Database(tmp_path / "real.db") as db:
        run_validation_suite(db.conn)
        md_path, json_path = write_report(db.conn, output_dir=tmp_path / "out")

    assert md_path.exists()
    assert json_path is not None
    assert json_path.exists()
    assert md_path.name == "VALIDATION_REPORT.md"
    assert json_path.name == "validation_report.json"

    data = json.loads(json_path.read_text())
    assert data["total_scenarios"] > 0
    assert "%" not in md_path.read_text()


def test_write_report_no_json_flag_skips_json_file(tmp_path: Path):
    with Database(tmp_path / "real.db") as db:
        run_validation_suite(db.conn)
        md_path, json_path = write_report(db.conn, output_dir=tmp_path / "out", write_json=False)

    assert md_path.exists()
    assert json_path is None
    assert not (tmp_path / "out" / "validation_report.json").exists()


def test_write_report_targets_a_specific_run_id(tmp_path: Path):
    with Database(tmp_path / "real.db") as db:
        first = run_validation_suite(db.conn)
        run_validation_suite(db.conn)  # a second, later run
        md_path, _ = write_report(db.conn, run_id=first.run_id, output_dir=tmp_path / "out")

    assert first.run_id in md_path.read_text()
