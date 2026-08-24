"""
Tests for secure/validate/scenarios/*.py — Phase 27 Stage 7. Each
scenario function is exercised end to end against a fresh sandbox
(secure/validate/sandbox.py), calling Secure's own real scanner/
correlate/explain code unchanged — these tests check the SCENARIO
HARNESS behaves correctly (deterministic, well-formed, unique ids,
valid outcomes), not the underlying detection logic itself (which
already has its own dedicated unit tests elsewhere).

Expected outcomes here mirror exactly what each scenario module's own
docstring/comments document, so a real behavior regression in Secure
itself (not just this harness) would also be caught here.

Run with:  pytest
"""

from __future__ import annotations

from secure.validate import VALID_OUTCOMES
from secure.validate.runner import all_scenario_functions
from secure.validate.sandbox import sandbox
from secure.validate.scenario import ScenarioResult
from secure.validate.scenarios import connections, crosssensor, detections, fileintegrity, listening, persistence

_EXPECTED_OUTCOMES = {
    "persistence_new_launch_daemon_unsigned": "PASS",
    "persistence_new_launch_daemon_signed_benign": "PASS",
    "persistence_unusual_unsigned_process": "PASS",
    "persistence_process_sensor_unavailable": "SENSOR_UNAVAILABLE",
    "persistence_background_items_not_evaluable": "NOT_EVALUABLE",
    "fileintegrity_content_modified_detected": "PASS",
    "fileintegrity_unchanged_file_no_alert": "PASS",
    "connections_new_outbound_endpoint": "PASS",
    "connections_known_endpoint_not_reflagged": "PASS",
    "connections_lsof_sensor_unavailable": "SENSOR_UNAVAILABLE",
    "listening_new_listener_nonstandard_port": "PASS",
    "listening_known_listener_not_reflagged": "PASS",
    "listening_lsof_sensor_unavailable": "SENSOR_UNAVAILABLE",
    "detections_sigma_rule_fixtures_pass": "PASS",
    "detections_sigma_rule_not_evaluable": "NOT_EVALUABLE",
    "detections_yarax_ruleset_fixtures_pass": "PASS",
    "detections_yarax_engine_unavailable": "SENSOR_UNAVAILABLE",
    "detections_suricata_eve_parser_fixtures_pass": "PASS",
    "crosssensor_cross_module_cluster_fires": "PASS",
    "crosssensor_single_module_signal_does_not_cluster": "PASS",
    "crosssensor_persistence_process_deduplication": "PASS",
}

_MODULES = (persistence, fileintegrity, connections, listening, detections, crosssensor)


def _run(fn) -> ScenarioResult:
    with sandbox() as sb:
        return fn(sb)


# ---------- catalog-wide invariants ----------


def test_every_registered_scenario_has_a_documented_expected_outcome():
    scenario_ids = set()
    for module in _MODULES:
        for fn in module.SCENARIOS:
            result = _run(fn)
            scenario_ids.add(result.scenario_id)
    assert scenario_ids == set(_EXPECTED_OUTCOMES.keys())


def test_all_scenario_ids_are_globally_unique():
    seen = []
    for module in _MODULES:
        for fn in module.SCENARIOS:
            result = _run(fn)
            seen.append(result.scenario_id)
    assert len(seen) == len(set(seen))


def test_every_scenario_outcome_is_one_of_the_five_valid_outcomes():
    for module in _MODULES:
        for fn in module.SCENARIOS:
            result = _run(fn)
            assert result.outcome in VALID_OUTCOMES


def test_every_scenario_matches_its_documented_expected_outcome():
    mismatches = []
    for module in _MODULES:
        for fn in module.SCENARIOS:
            result = _run(fn)
            expected = _EXPECTED_OUTCOMES[result.scenario_id]
            if result.outcome != expected:
                mismatches.append((result.scenario_id, expected, result.outcome, result.notes))
    assert mismatches == [], mismatches


def test_every_scenario_result_has_required_fields_populated():
    for module in _MODULES:
        for fn in module.SCENARIOS:
            result = _run(fn)
            assert result.scenario_id
            assert result.category
            assert result.description
            assert result.expected_result
            assert result.started_at
            assert result.completed_at
            assert result.latency_ms is not None  # timed() always fills this in, never None


def test_all_scenario_functions_matches_the_six_category_modules_combined():
    combined = []
    for module in _MODULES:
        combined.extend(module.SCENARIOS)
    assert all_scenario_functions() == combined


# ---------- determinism ----------


def test_scenarios_are_deterministic_across_two_independent_runs():
    """The governing instruction requires 'two runs against the same
    build and fixtures produce equivalent results' — verified here by
    literally running every scenario twice, each against its own fresh
    sandbox, and comparing outcomes.
    """
    for module in _MODULES:
        for fn in module.SCENARIOS:
            first = _run(fn)
            second = _run(fn)
            assert first.outcome == second.outcome
            assert first.scenario_id == second.scenario_id


# ---------- specific scenario shape checks ----------


def test_not_evaluable_scenarios_carry_explanatory_notes():
    for module in _MODULES:
        for fn in module.SCENARIOS:
            result = _run(fn)
            if result.outcome == "NOT_EVALUABLE":
                assert result.notes.strip() != ""


def test_lsof_and_ps_backed_sensor_unavailable_scenarios_report_no_sensors_observed():
    # The lsof/ps-backed scenarios (persistence/connections/listening)
    # report a total absence of observation when their tool fails
    # entirely. detections_yarax_engine_unavailable is a DIFFERENT
    # shape deliberately: the yarax family itself is still cataloged
    # and "observed" as a rule, just not capability-evaluable — see
    # secure/validate/scenarios/detections.py's own scenario, which
    # is excluded here on purpose.
    tool_backed_ids = {
        "persistence_process_sensor_unavailable",
        "connections_lsof_sensor_unavailable",
        "listening_lsof_sensor_unavailable",
    }
    for module in _MODULES:
        for fn in module.SCENARIOS:
            result = _run(fn)
            if result.scenario_id in tool_backed_ids:
                assert result.outcome == "SENSOR_UNAVAILABLE"
                assert result.sensors_observed == []


def test_persistence_passing_scenarios_carry_a_nonempty_explanation_checklist():
    # The two scenarios that fire a real HIGH-severity alert route it
    # through secure/explain/ — the checklist must reflect a real,
    # non-empty rubric score, not an empty {} placeholder.
    for fn in (persistence.scenario_new_launch_daemon_unsigned, persistence.scenario_unusual_unsigned_process):
        result = _run(fn)
        assert result.explanation_checklist  # non-empty dict
        assert all(isinstance(v, bool) for v in result.explanation_checklist.values())
