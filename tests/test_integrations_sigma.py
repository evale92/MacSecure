"""
Tests for secure/integrations/sigma/ (Phase 17: Sigma detection layer).

Unlike yara_x (Phase 16, never installed in that sandbox), PyYAML is
genuinely available here, so these tests exercise the real `yaml`
library end to end through real, deterministic fixture rule files
under tests/fixtures/sigma/rules/ — no bundled/real-world Sigma
content, no EICAR-style signatures, just synthetic marker strings and
made-up ports, safe to keep on disk.

Sections mirror the package's own module split: rules.py (loading),
capability.py (the NOT_EVALUABLE-vs-EVALUABLE adapter — the phase's
central requirement), condition.py (the bounded boolean grammar +
field matching), evaluator.py, analysis.py (severity), availability.py,
scanner.py (end-to-end DB persistence), then correlate/explain wiring.

Run with:  pytest
"""

from __future__ import annotations

import sys
from pathlib import Path

from secure.config import AppConfig
from secure.correlate.analysis import MEANINGFUL_MODULE_PAIRS
from secure.correlate.signals import _classify_integration_signal_strength, _collect_integrations
from secure.correlate.strength import MEDIUM, STRONG, WEAK, classify_sigma_finding_strength
from secure.explain.dispatch import explain
from secure.integrations.base import STATUS_ERROR, STATUS_OK, STATUS_UNAVAILABLE
from secure.integrations.sigma import analysis as analysis_module
from secure.integrations.sigma import availability as availability_module
from secure.integrations.sigma import capability as capability_module
from secure.integrations.sigma import condition as condition_module
from secure.integrations.sigma import evaluator as evaluator_module
from secure.integrations.sigma import rules as rules_module
from secure.integrations.sigma import scanner as scanner_module
from secure.storage.database import Database
from secure.storage.models import (
    IntegrationObservationRecord,
    add_integration_observations,
    list_integration_alerts,
    list_integration_observations,
    list_integration_runs,
)

FIXTURES = Path(__file__).parent / "fixtures" / "sigma"
RULES_DIR = FIXTURES / "rules"

NOW = "2026-08-21T00:00:00+00:00"


def _load_fixture_rule(filename: str) -> rules_module.SigmaRule:
    rules, errors = rules_module.load_rules(RULES_DIR)
    assert errors == [] or all(Path(e.source_path).name != filename for e in errors)
    for rule in rules:
        if Path(rule.source_path).name == filename:
            return rule
    raise AssertionError(f"fixture rule {filename!r} not found among loaded rules")


def _make_observation(
    obs_id: int, fields: dict, kind: str = "processes", identity_key: str = "k1"
) -> IntegrationObservationRecord:
    import json

    return IntegrationObservationRecord(
        id=obs_id,
        created_at=NOW,
        run_id="r1",
        integration="osquery",
        kind=kind,
        identity_key=identity_key,
        fields_json=json.dumps(fields),
        source_query="q",
        collected_at=NOW,
    )


# ---------- rules.py ----------


def test_discover_rule_files_only_yml_yaml_extensions():
    found = rules_module.discover_rule_files(RULES_DIR)
    names = {p.name for p in found}
    assert names == {
        "process_creation_match.yml",
        "network_connection_match.yml",
        "quantifier_grammar.yml",
        "unsupported_category.yml",
        "unsupported_field.yml",
        "windows_only.yml",
        "malformed.yml",
        "missing_condition.yml",
    }


def test_discover_rule_files_missing_dir_returns_empty(tmp_path: Path):
    assert rules_module.discover_rule_files(tmp_path / "does_not_exist") == []


def test_load_rules_loads_every_valid_fixture():
    rules, errors = rules_module.load_rules(RULES_DIR)
    assert len(rules) == 6  # 8 files - malformed.yml - missing_condition.yml
    ids = {r.rule_id for r in rules}
    assert "11111111-1111-1111-1111-111111111111" in ids


def test_load_rules_isolates_malformed_file_without_aborting_batch():
    rules, errors = rules_module.load_rules(RULES_DIR)
    error_names = {Path(e.source_path).name for e in errors}
    assert "malformed.yml" in error_names
    # The other 6 valid files still loaded despite one bad file.
    assert len(rules) == 6


def test_load_rules_rejects_missing_condition():
    rules, errors = rules_module.load_rules(RULES_DIR)
    error_names = {Path(e.source_path).name for e in errors}
    assert "missing_condition.yml" in error_names
    assert not any(r.rule_id == "77777777-7777-7777-7777-777777777777" for r in rules)


def test_rule_source_hash_is_sha256_and_version_label_format():
    rule = _load_fixture_rule("process_creation_match.yml")
    assert len(rule.source_hash) == 64
    assert rule.version_label == f"{rule.rule_id}@{rule.source_hash[:12]}"


def test_load_rules_rejects_non_mapping_document(tmp_path: Path):
    (tmp_path / "not_a_mapping.yml").write_text("- just\n- a\n- list\n")
    rules, errors = rules_module.load_rules(tmp_path)
    assert rules == []
    assert len(errors) == 1
    assert "not a mapping" in errors[0].detail


def test_load_rules_rejects_missing_id_and_title(tmp_path: Path):
    (tmp_path / "no_id.yml").write_text(
        "title: x\nlogsource:\n  category: process_creation\n"
        "detection:\n  sel:\n    Image: /bin/ls\n  condition: sel\n"
    )
    (tmp_path / "no_title.yml").write_text(
        "id: aaaa\nlogsource:\n  category: process_creation\n"
        "detection:\n  sel:\n    Image: /bin/ls\n  condition: sel\n"
    )
    rules, errors = rules_module.load_rules(tmp_path)
    assert rules == []
    assert len(errors) == 2


# ---------- capability.py ----------


def test_check_capability_process_creation_evaluable():
    rule = _load_fixture_rule("process_creation_match.yml")
    result = capability_module.check_capability(rule)
    assert result.status == capability_module.EvaluationStatus.EVALUABLE
    assert result.evaluable is True
    assert result.category_support.observation_kind == "processes"


def test_check_capability_network_connection_evaluable():
    rule = _load_fixture_rule("network_connection_match.yml")
    result = capability_module.check_capability(rule)
    assert result.evaluable is True
    assert result.category_support.observation_kind == "process_open_sockets"


def test_check_capability_unsupported_category_is_not_evaluable():
    rule = _load_fixture_rule("unsupported_category.yml")
    result = capability_module.check_capability(rule)
    assert result.status == capability_module.EvaluationStatus.NOT_EVALUABLE
    assert result.category_support is None
    assert "registry_event" in result.reason


def test_check_capability_unsupported_field_is_not_evaluable():
    rule = _load_fixture_rule("unsupported_field.yml")
    result = capability_module.check_capability(rule)
    assert result.status == capability_module.EvaluationStatus.NOT_EVALUABLE
    assert "ParentImage" in result.reason
    # Category support IS known (process_creation) even though the rule
    # isn't evaluable — the reason is field-specific, not category-wide.
    assert result.category_support is not None


def test_check_capability_windows_product_is_not_evaluable_even_with_supported_fields():
    rule = _load_fixture_rule("windows_only.yml")
    result = capability_module.check_capability(rule)
    assert result.status == capability_module.EvaluationStatus.NOT_EVALUABLE
    assert "windows" in result.reason


def test_check_capability_undeclared_product_is_not_held_against_a_rule():
    rule = _load_fixture_rule("process_creation_match.yml")
    # This fixture rule DOES declare product: macos; build one that
    # omits it entirely and confirm that omission alone isn't penalized.
    stripped = rules_module.SigmaRule(
        rule_id=rule.rule_id, title=rule.title, level=rule.level,
        description=rule.description, sigma_status=rule.sigma_status, tags=rule.tags,
        logsource={"category": "process_creation"},  # no product key at all
        detection=rule.detection, source_path=rule.source_path, source_hash=rule.source_hash,
    )
    result = capability_module.check_capability(stripped)
    assert result.evaluable is True


def test_check_capability_never_raises_on_missing_category():
    rule = rules_module.SigmaRule(
        rule_id="x", title="x", level=None, description=None, sigma_status=None,
        tags=(), logsource={}, detection={"sel": {"Image": "/bin/ls"}, "condition": "sel"},
        source_path="x", source_hash="x",
    )
    result = capability_module.check_capability(rule)
    assert result.status == capability_module.EvaluationStatus.NOT_EVALUABLE


# ---------- condition.py: grammar ----------


def test_parse_and_evaluate_and_or_not_parens():
    cases = [
        ("sel1 and sel2", {"sel1": True, "sel2": True}, True),
        ("sel1 and sel2", {"sel1": True, "sel2": False}, False),
        ("sel1 or sel2", {"sel1": False, "sel2": True}, True),
        ("not sel1", {"sel1": True}, False),
        ("not sel1", {"sel1": False}, True),
        ("(sel1 or sel2) and not sel3", {"sel1": False, "sel2": True, "sel3": False}, True),
        ("(sel1 or sel2) and not sel3", {"sel1": False, "sel2": True, "sel3": True}, False),
    ]
    for text, values, expected in cases:
        ast = condition_module.parse_condition(text)
        assert condition_module.evaluate_condition(ast, values) is expected, text


def test_parse_and_evaluate_quantifiers():
    assert condition_module.evaluate_condition(
        condition_module.parse_condition("1 of selection*"),
        {"selection_a": False, "selection_b": True},
    ) is True
    assert condition_module.evaluate_condition(
        condition_module.parse_condition("all of selection*"),
        {"selection_a": True, "selection_b": False},
    ) is False
    assert condition_module.evaluate_condition(
        condition_module.parse_condition("1 of them"), {"a": False, "b": False}
    ) is False
    assert condition_module.evaluate_condition(
        condition_module.parse_condition("all of them"), {"a": True, "b": True}
    ) is True


def test_quantifier_with_zero_matching_names_is_false_not_vacuously_true():
    ast = condition_module.parse_condition("1 of nomatch*")
    assert condition_module.evaluate_condition(ast, {"selection_a": True}) is False


def _raises(fn, exc_type) -> bool:
    """House style for asserting a call raises: this sandbox's test
    runner has no real pytest installed, so every raise-assertion in
    this file uses this small helper rather than pytest.raises (see
    tests/test_baseline_engine.py's own try/except/raised-flag pattern,
    which this generalizes into one place).
    """
    try:
        fn()
    except exc_type:
        return True
    return False


def test_parse_condition_rejects_unsupported_grammar():
    assert _raises(lambda: condition_module.parse_condition("sel1 xor sel2"), condition_module.ConditionError)


def test_parse_condition_rejects_empty_string():
    assert _raises(lambda: condition_module.parse_condition(""), condition_module.ConditionError)


def test_evaluate_condition_rejects_unknown_selection_reference():
    ast = condition_module.parse_condition("nonexistent_selection")
    assert _raises(
        lambda: condition_module.evaluate_condition(ast, {"sel1": True}), condition_module.ConditionError
    )


# ---------- condition.py: field-value matching ----------


def test_match_field_values_plain_wildcard():
    assert condition_module.match_field_values("/usr/bin/curl", "*/curl", None) is True
    assert condition_module.match_field_values("/usr/bin/curl", "*/wget", None) is False


def test_match_field_values_case_insensitive_by_default():
    assert condition_module.match_field_values("/usr/bin/CURL", "*/curl", None) is True


def test_match_field_values_contains_startswith_endswith():
    assert condition_module.match_field_values("curl -s https://x/y", "pastebin", "contains") is False
    assert condition_module.match_field_values("curl -s https://pastebin/y", "pastebin", "contains") is True
    assert condition_module.match_field_values("/usr/bin/curl", "/usr", "startswith") is True
    assert condition_module.match_field_values("/usr/bin/curl", "/curl", "endswith") is True


def test_match_field_values_regex():
    assert condition_module.match_field_values("port 4444 open", r"\b4444\b", "re") is True
    assert condition_module.match_field_values("port 5555 open", r"\b4444\b", "re") is False


def test_match_field_values_list_is_or_by_default():
    assert condition_module.match_field_values("bash", ["zsh", "bash"], None) is True
    assert condition_module.match_field_values("fish", ["zsh", "bash"], None) is False


def test_match_field_values_all_modifier_is_and():
    # A bare `|all` (no other modifier chained — chaining isn't
    # supported, see condition.py's module docstring) does exact/
    # wildcard matching per value, same as no modifier at all — it just
    # requires EVERY value in the list to match rather than ANY.
    assert condition_module.match_field_values("bash", ["bash", "*ash"], "all") is True
    assert condition_module.match_field_values("bash", ["bash", "zsh"], "all") is False


def test_match_field_values_none_actual_treated_as_empty_string():
    assert condition_module.match_field_values(None, "*", None) is True
    assert condition_module.match_field_values(None, "something", "contains") is False


def test_match_field_values_unsupported_modifier_raises():
    assert _raises(
        lambda: condition_module.match_field_values("x", "y", "base64offset"), condition_module.ConditionError
    )


def test_match_selection_mapping_and_list_or():
    field_map = {"Image": "path", "CommandLine": "cmdline"}
    event = {"path": "/usr/bin/curl", "cmdline": "curl -s https://x/secure-test-pastebin-marker"}

    mapping_sel = {"Image|endswith": "/curl", "CommandLine|contains": "secure-test-pastebin-marker"}
    assert condition_module.match_selection(mapping_sel, event, field_map) is True

    list_sel = [{"Image": "/bin/bash"}, {"CommandLine|contains": "secure-test-pastebin-marker"}]
    assert condition_module.match_selection(list_sel, event, field_map) is True

    list_sel_no_match = [{"Image": "/bin/bash"}, {"CommandLine|contains": "nope"}]
    assert condition_module.match_selection(list_sel_no_match, event, field_map) is False


def test_match_selection_rejects_plain_keyword_list():
    assert _raises(
        lambda: condition_module.match_selection(["just", "a", "list"], {}, {}), condition_module.ConditionError
    )


def test_match_selection_unmapped_field_raises():
    assert _raises(
        lambda: condition_module.match_selection({"ParentImage": "/bin/bash"}, {}, {"Image": "path"}),
        condition_module.ConditionError,
    )


# ---------- evaluator.py ----------


def test_evaluate_rule_finds_match_and_bounds_evidence():
    rule = _load_fixture_rule("process_creation_match.yml")
    support = capability_module.SUPPORTED_CATEGORIES[capability_module.CATEGORY_PROCESS_CREATION]

    matching = _make_observation(
        1, {"path": "/usr/bin/curl", "cmdline": "curl -s https://x/secure-test-pastebin-marker"}
    )
    nonmatching = _make_observation(2, {"path": "/bin/ls", "cmdline": "ls -la"})

    result = evaluator_module.evaluate_rule(rule, support, [matching, nonmatching])
    assert result.matched is True
    assert result.observations_checked == 2
    assert len(result.matches) == 1
    assert result.matches[0].observation_id == 1
    assert result.truncated is False
    assert result.error is None


def test_evaluate_rule_no_match_when_nothing_satisfies_condition():
    rule = _load_fixture_rule("process_creation_match.yml")
    support = capability_module.SUPPORTED_CATEGORIES[capability_module.CATEGORY_PROCESS_CREATION]
    nonmatching = _make_observation(1, {"path": "/bin/ls", "cmdline": "ls -la"})
    result = evaluator_module.evaluate_rule(rule, support, [nonmatching])
    assert result.matched is False
    assert result.matches == []


def test_evaluate_rule_quantifier_grammar_end_to_end():
    rule = _load_fixture_rule("quantifier_grammar.yml")
    support = capability_module.SUPPORTED_CATEGORIES[capability_module.CATEGORY_PROCESS_CREATION]
    matching = _make_observation(1, {"path": "/opt/nonexistent-b", "cmdline": ""})
    nonmatching = _make_observation(2, {"path": "/bin/ls", "cmdline": ""})
    result = evaluator_module.evaluate_rule(rule, support, [matching, nonmatching])
    assert result.matched is True
    assert len(result.matches) == 1
    assert result.matches[0].observation_id == 1


def test_evaluate_rule_truncates_evidence_at_max():
    rule = _load_fixture_rule("process_creation_match.yml")
    support = capability_module.SUPPORTED_CATEGORIES[capability_module.CATEGORY_PROCESS_CREATION]
    observations = [
        _make_observation(
            i, {"path": "/usr/bin/curl", "cmdline": "curl -s https://x/secure-test-pastebin-marker"}
        )
        for i in range(evaluator_module.MAX_MATCHED_EVIDENCE + 10)
    ]
    result = evaluator_module.evaluate_rule(rule, support, observations)
    assert result.matched is True
    assert len(result.matches) == evaluator_module.MAX_MATCHED_EVIDENCE
    assert result.truncated is True


def test_evaluate_rule_reports_condition_error_without_crashing():
    support = capability_module.SUPPORTED_CATEGORIES[capability_module.CATEGORY_PROCESS_CREATION]
    bad_rule = rules_module.SigmaRule(
        rule_id="x", title="bad condition", level=None, description=None, sigma_status=None,
        tags=(), logsource={"category": "process_creation"},
        detection={"sel": {"Image": "/bin/ls"}, "condition": "sel xor sel"},
        source_path="x", source_hash="x",
    )
    result = evaluator_module.evaluate_rule(bad_rule, support, [_make_observation(1, {"path": "/bin/ls"})])
    assert result.matched is False
    assert result.error is not None
    assert "condition parse error" in result.error


# ---------- analysis.py ----------


def test_classify_sigma_match_severity_recognized_levels():
    assert analysis_module.classify_sigma_match_severity("critical") == analysis_module.HIGH
    assert analysis_module.classify_sigma_match_severity("high") == analysis_module.HIGH
    assert analysis_module.classify_sigma_match_severity("medium") == analysis_module.MEDIUM
    assert analysis_module.classify_sigma_match_severity("low") == analysis_module.LOW
    assert analysis_module.classify_sigma_match_severity("informational") == analysis_module.LOW


def test_classify_sigma_match_severity_defaults_when_absent_or_unrecognized():
    assert analysis_module.classify_sigma_match_severity(None) == analysis_module.DEFAULT_SEVERITY
    assert analysis_module.classify_sigma_match_severity("extremely bad") == analysis_module.DEFAULT_SEVERITY
    assert analysis_module.DEFAULT_SEVERITY == analysis_module.LOW


def test_level_is_recognized():
    assert analysis_module.level_is_recognized("high") is True
    assert analysis_module.level_is_recognized(None) is False
    assert analysis_module.level_is_recognized("nonsense") is False


def test_match_interpretation_note_mentions_non_committal_default_when_unrecognized():
    note = analysis_module.match_interpretation_note("My Rule", None, False, None)
    assert "non-committal default" in note
    assert "not an independent" in note or "not, by itself" in note or "not an independent malware" in note


# ---------- availability.py ----------


def test_check_availability_ok_for_real_pyyaml_install():
    health = availability_module.check_availability()
    assert health.status == STATUS_OK
    assert health.tool_version is not None


def test_check_availability_unavailable_when_yaml_cannot_be_imported():
    # Setting sys.modules["yaml"] = None makes a subsequent `import yaml`
    # raise ImportError (a documented CPython import-system behavior) —
    # this sandbox's test runner has no monkeypatch.setitem, so this
    # restores sys.modules by hand in a try/finally instead.
    had_module = "yaml" in sys.modules
    old = sys.modules.get("yaml")
    sys.modules["yaml"] = None
    try:
        health = availability_module.check_availability()
        assert health.status == STATUS_UNAVAILABLE
        assert health.tool_version is None
    finally:
        if had_module:
            sys.modules["yaml"] = old
        else:
            del sys.modules["yaml"]


def test_check_availability_error_when_smoke_test_parse_is_wrong_shape(monkeypatch):
    monkeypatch.setattr(availability_module, "parse_yaml", lambda text: {"wrong": "shape"})
    health = availability_module.check_availability()
    assert health.status == STATUS_ERROR


def test_check_availability_error_when_smoke_test_raises(monkeypatch):
    def boom(text):
        raise RuntimeError("boom")

    monkeypatch.setattr(availability_module, "parse_yaml", boom)
    health = availability_module.check_availability()
    assert health.status == STATUS_ERROR


# ---------- scanner.py: end-to-end persistence ----------


def _cfg_for(tmp_path: Path) -> AppConfig:
    cfg = AppConfig(app_dir=str(tmp_path))
    cfg.sigma_rules_dir = str(RULES_DIR)
    return cfg


def test_scan_sigma_persists_one_observation_per_rule_every_pass(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_sigma(db.conn, _cfg_for(tmp_path))
        assert result.available is True
        assert len(result.rules_loaded) == 6

        observations = list_integration_observations(db.conn, integration="sigma")
        # One sigma_rule_result row per loaded rule, regardless of
        # evaluation status or match outcome.
        assert len(observations) == 6
        assert all(o.kind == "sigma_rule_result" for o in observations)


def test_scan_sigma_not_evaluable_rule_never_produces_an_alert(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        scanner_module.scan_sigma(db.conn, _cfg_for(tmp_path))
        alerts = list_integration_alerts(db.conn, integration="sigma")
        matched_ids = {a.identity_key for a in alerts}
        # unsupported_category / unsupported_field / windows_only are
        # never evaluable, so their rule_ids must never appear as alerts.
        assert "44444444-4444-4444-4444-444444444444" not in matched_ids
        assert "55555555-5555-5555-5555-555555555555" not in matched_ids
        assert "66666666-6666-6666-6666-666666666666" not in matched_ids


def test_scan_sigma_not_evaluable_observation_reports_status_explicitly(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        scanner_module.scan_sigma(db.conn, _cfg_for(tmp_path))
        observations = list_integration_observations(db.conn, integration="sigma")
        by_rule_id = {o.fields["rule_id"]: o for o in observations}
        not_evaluable = by_rule_id["44444444-4444-4444-4444-444444444444"]
        assert not_evaluable.fields["evaluation_status"] == "not_evaluable"
        assert not_evaluable.fields["matched"] is False
        assert not_evaluable.fields["required_telemetry"]  # always populated, never blank


def test_scan_sigma_produces_match_alert_with_correct_severity_and_provenance(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_integration_observations(
            db.conn, run_id="seed", integration="osquery",
            rows=[
                (
                    "processes", "proc:1",
                    {"pid": 1, "path": "/usr/bin/curl", "cmdline": "curl -s https://x/secure-test-pastebin-marker"},
                    "q", NOW,
                ),
            ],
        )
        result = scanner_module.scan_sigma(db.conn, _cfg_for(tmp_path))

        matched = [o for o in result.outcomes if o.matched]
        assert len(matched) == 1
        assert matched[0].rule.rule_id == "11111111-1111-1111-1111-111111111111"

        alerts = list_integration_alerts(db.conn, integration="sigma")
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.kind == "process_creation"
        assert alert.discrepancy == "match"
        assert alert.severity == "high"  # from the fixture rule's own `level: high`
        assert alert.identity_key == "11111111-1111-1111-1111-111111111111"
        assert alert.source_observation_id is not None

        # source_observation_id must point at THIS rule's own
        # sigma_rule_result row, not the raw osquery observation.
        sigma_obs = [
            o for o in list_integration_observations(db.conn, integration="sigma")
            if o.id == alert.source_observation_id
        ]
        assert len(sigma_obs) == 1
        assert sigma_obs[0].fields["rule_id"] == "11111111-1111-1111-1111-111111111111"
        assert sigma_obs[0].fields["matched"] is True


def test_scan_sigma_network_connection_category_uses_correct_observation_kind(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_integration_observations(
            db.conn, run_id="seed", integration="osquery",
            rows=[
                (
                    "process_open_sockets", "sock:1",
                    {"pid": 1, "remote_address": "1.2.3.4", "remote_port": 44440, "proto": "tcp", "process_name": "evil"},
                    "q", NOW,
                ),
            ],
        )
        result = scanner_module.scan_sigma(db.conn, _cfg_for(tmp_path))
        matched_titles = {o.rule.title for o in result.outcomes if o.matched}
        assert "Secure test - outbound to fixture C2 port" in matched_titles


def test_scan_sigma_records_run_with_correct_counts(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_integration_observations(
            db.conn, run_id="seed", integration="osquery",
            rows=[
                (
                    "processes", "proc:1",
                    {"pid": 1, "path": "/usr/bin/curl", "cmdline": "curl -s https://x/secure-test-pastebin-marker"},
                    "q", NOW,
                ),
            ],
        )
        result = scanner_module.scan_sigma(db.conn, _cfg_for(tmp_path))
        runs = list_integration_runs(db.conn, integration="sigma")
        assert len(runs) == 1
        assert runs[0].observations_collected == 6
        assert runs[0].alerts_generated == 1
        assert runs[0].run_id == result.run_id


def test_scan_sigma_unavailable_short_circuits_with_no_observations(tmp_path: Path, monkeypatch):
    from secure.integrations.base import STATUS_UNAVAILABLE as _UNAVAILABLE
    from secure.integrations.base import IntegrationHealth

    monkeypatch.setattr(
        scanner_module,
        "check_availability",
        lambda: IntegrationHealth(status=_UNAVAILABLE, detail="PyYAML is not installed.", collected_at=NOW),
    )
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_sigma(db.conn, _cfg_for(tmp_path))
        assert result.available is False
        assert list_integration_observations(db.conn, integration="sigma") == []
        runs = list_integration_runs(db.conn, integration="sigma")
        assert len(runs) == 1
        assert runs[0].status == "unavailable"


def test_scan_sigma_empty_rules_dir_is_a_clean_no_op(tmp_path: Path):
    cfg = AppConfig(app_dir=str(tmp_path))
    cfg.sigma_rules_dir = str(tmp_path / "no_such_dir")
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_sigma(db.conn, cfg)
        assert result.available is True
        assert result.rules_loaded == []
        assert list_integration_observations(db.conn, integration="sigma") == []


# ---------- correlate wiring ----------


def test_classify_sigma_finding_strength():
    assert classify_sigma_finding_strength("high") == STRONG
    assert classify_sigma_finding_strength("medium") == MEDIUM
    assert classify_sigma_finding_strength("low") == WEAK


def test_classify_integration_signal_strength_dispatches_sigma_by_severity():
    assert _classify_integration_signal_strength("sigma", "match", "high") == STRONG
    assert _classify_integration_signal_strength("sigma", "match", "medium") == MEDIUM
    assert _classify_integration_signal_strength("sigma", "match", "low") == WEAK


def test_collect_integrations_reads_sigma_alert_not_flat_strong(tmp_path: Path):
    from secure.storage.models import add_integration_alert

    with Database(tmp_path / "test.db") as db:
        add_integration_alert(
            db.conn, run_id="r1", integration="sigma", kind="process_creation", discrepancy="match",
            severity="medium", identity_key="rule-1", label="A Sigma rule",
            message="A Sigma rule matched.",
        )
        signals = _collect_integrations(db.conn, "2000-01-01T00:00:00+00:00")
        assert len(signals) == 1
        assert signals[0].strength == MEDIUM
        assert signals[0].kind == "process_creation"  # not suffixed the way osquery's discrepancy is
        assert signals[0].module == "integrations"


def test_collect_integrations_never_reads_sigma_rule_result_observations(tmp_path: Path):
    """The double-counting-prevention guarantee: a sigma_rule_result
    observation (evaluable-no-match OR not_evaluable) must never itself
    become a correlation signal — only a genuine integration_alerts row
    can. Seed observations only (no alert) and confirm zero signals.
    """
    with Database(tmp_path / "test.db") as db:
        add_integration_observations(
            db.conn, run_id="r1", integration="sigma",
            rows=[("sigma_rule_result", "rule-1", {"matched": False, "evaluation_status": "evaluable"}, "q", NOW)],
        )
        signals = _collect_integrations(db.conn, "2000-01-01T00:00:00+00:00")
        assert signals == []


def test_sigma_integrations_process_and_connections_are_meaningful_pairs():
    assert frozenset({"integrations", "process"}) in MEANINGFUL_MODULE_PAIRS
    assert frozenset({"integrations", "connections"}) in MEANINGFUL_MODULE_PAIRS


# ---------- explain wiring ----------


def test_explain_integration_alert_sigma_process_creation_uses_inspect_process(tmp_path: Path):
    from secure.storage.models import IntegrationAlertRecord

    record = IntegrationAlertRecord(
        id=1, created_at=NOW, run_id="r1", integration="sigma", kind="process_creation",
        discrepancy="match", severity="high", identity_key="rule-1", label="Suspicious curl",
        message="A Sigma rule matched.", source_observation_id=1, known=False,
    )
    exp = explain(record, "integration_alerts")
    assert exp.degraded is False
    assert exp.severity == "high"  # verbatim passthrough
    assert exp.recommended_action == "INSPECT_PROCESS"
    assert "NOT EVALUABLE" in exp.significance or "not evaluable" in exp.significance.lower()


def test_explain_integration_alert_sigma_network_connection_uses_review_network_destination(tmp_path: Path):
    from secure.storage.models import IntegrationAlertRecord

    record = IntegrationAlertRecord(
        id=2, created_at=NOW, run_id="r1", integration="sigma", kind="network_connection",
        discrepancy="match", severity="medium", identity_key="rule-2", label="Outbound to C2",
        message="A Sigma rule matched.", source_observation_id=1, known=False,
    )
    exp = explain(record, "integration_alerts")
    assert exp.recommended_action == "REVIEW_NETWORK_DESTINATION"


def test_explain_integration_alert_sigma_never_claims_confirmed_intrusion(tmp_path: Path):
    from secure.storage.models import IntegrationAlertRecord

    record = IntegrationAlertRecord(
        id=3, created_at=NOW, run_id="r1", integration="sigma", kind="process_creation",
        discrepancy="match", severity="high", identity_key="rule-1", label="Suspicious curl",
        message="A Sigma rule matched.", source_observation_id=1, known=False,
    )
    exp = explain(record, "integration_alerts")
    assert any("not an intrusion verdict" in u or "not, by itself" in u for u in exp.uncertainty)


def test_explain_integration_alert_yarax_and_osquery_still_work_after_sigma_added(tmp_path: Path):
    from secure.storage.models import IntegrationAlertRecord

    yarax_record = IntegrationAlertRecord(
        id=4, created_at=NOW, run_id="r1", integration="yarax", kind="yara_match",
        discrepancy="match", severity="high", identity_key="abc", label="rule",
        message="A YARA rule matched.", source_observation_id=1, known=False,
    )
    assert explain(yarax_record, "integration_alerts").recommended_action == "INSPECT_FILE"

    osquery_record = IntegrationAlertRecord(
        id=5, created_at=NOW, run_id="r1", integration="osquery", kind="listening_port",
        discrepancy="osquery_only", severity="high", identity_key="tcp:4444", label="evil",
        message="osquery saw a port native did not.", source_observation_id=1, known=False,
    )
    assert explain(osquery_record, "integration_alerts").degraded is False
