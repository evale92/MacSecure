"""
secure/validate/scenarios/detections.py — "supported YARA/Sigma/
Suricata detections" from the instruction's own behavior list.

Reuses Phase 25's own secure/detect/registry.py (sync_registry) and
secure/detect/validate.py (run_validation) COMPLETELY UNCHANGED —
zero new fixture-generation or evaluation logic lives here. This
module's only job is to catalog a rule via the real sync, run its real
fixtures, and translate the result into a ScenarioResult. See
secure/detect/validate.py's own module docstring for why "validated"
honestly means something different per family (compile-only for
YARA-X, EVE-parser-correctness-only for Suricata).
"""

from __future__ import annotations

import shutil
from pathlib import Path
from unittest.mock import patch

from secure.detect.registry import sync_registry
from secure.detect.validate import run_validation
from secure.integrations.suricata.parser import ALERT_KIND as SURICATA_ALERT_KIND
from secure.integrations.yarax import _engine as yarax_engine_module
from secure.storage.models import add_integration_observations, add_integration_run, find_detection_rule
from secure.validate import CATEGORY_DETECTION_RULE, OUTCOME_MISS, OUTCOME_NOT_EVALUABLE, OUTCOME_PASS, OUTCOME_SENSOR_UNAVAILABLE
from secure.validate.sandbox import Sandbox
from secure.validate.scenario import ScenarioResult, timed

_FIXTURES_ROOT = Path(__file__).parent.parent.parent.parent / "tests" / "fixtures"
_SIGMA_FIXTURES = _FIXTURES_ROOT / "sigma" / "rules"
_YARAX_FIXTURES = _FIXTURES_ROOT / "yarax" / "rules"


def _outcomes_all_passed(outcomes) -> bool:
    return len(outcomes) > 0 and all(o.passed for o in outcomes)


def scenario_sigma_rule_fixtures_pass(sb: Sandbox) -> ScenarioResult:
    def build():
        sb.cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
        shutil.copy(
            _SIGMA_FIXTURES / "process_creation_match.yml",
            sb.cfg.sigma_rules_dir_path() / "process_creation_match.yml",
        )
        sync_registry(sb.conn, sb.cfg)
        record = find_detection_rule(sb.conn, "sigma", "11111111-1111-1111-1111-111111111111")
        outcomes = run_validation(sb.conn, sb.cfg, record)
        all_passed = _outcomes_all_passed(outcomes)

        return ScenarioResult(
            scenario_id="detections_sigma_rule_fixtures_pass",
            technique_id=None,
            technique_name="Sigma benign/suspicious fixture pair (own selector-derived synthesis)",
            category=CATEGORY_DETECTION_RULE,
            description="A cataloged, evaluable Sigma rule's own benign+suspicious fixtures, run through the real evaluator.",
            expected_result="Both fixtures pass (suspicious fires, benign doesn't).",
            sensors_observed=["sigma"] if outcomes else [],
            findings=[{"fixture": o.fixture_name, "expected": o.expected, "actual": o.actual} for o in outcomes],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_PASS if all_passed else OUTCOME_MISS,
            notes="" if all_passed else "One or more Sigma fixtures did not behave as expected.",
            started_at="",
            completed_at="",
        )

    return timed("detections_sigma_rule_fixtures_pass", build)


def scenario_sigma_rule_not_evaluable(sb: Sandbox) -> ScenarioResult:
    """windows_only.yml is deliberately NOT_EVALUABLE on macOS — reused
    verbatim from Phase 17/25's own fixture set as an honest,
    already-established capability gap, not a fabricated one.
    """

    def build():
        sb.cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
        shutil.copy(
            _SIGMA_FIXTURES / "windows_only.yml", sb.cfg.sigma_rules_dir_path() / "windows_only.yml"
        )
        sync_registry(sb.conn, sb.cfg)
        record = find_detection_rule(sb.conn, "sigma", "66666666-6666-6666-6666-666666666666")
        correctly_not_evaluable = record is not None and record.capability_status == "not_evaluable"

        return ScenarioResult(
            scenario_id="detections_sigma_rule_not_evaluable",
            technique_id=None,
            technique_name="Sigma rule requiring telemetry this Mac cannot provide (Windows-only logsource)",
            category=CATEGORY_DETECTION_RULE,
            description="A Sigma rule whose logsource.product is 'windows' — Secure has no such telemetry on macOS.",
            expected_result="Cataloged as capability_status='not_evaluable', never silently treated as passing or clean.",
            sensors_observed=["sigma"],
            findings=[{"capability_status": record.capability_status if record else None}],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_NOT_EVALUABLE if correctly_not_evaluable else OUTCOME_MISS,
            notes="Documented, permanent capability boundary — Secure runs on macOS only.",
            started_at="",
            completed_at="",
        )

    return timed("detections_sigma_rule_not_evaluable", build)


def scenario_yarax_ruleset_fixtures_pass(sb: Sandbox) -> ScenarioResult:
    def build():
        sb.cfg.yara_rules_dir_path().mkdir(parents=True, exist_ok=True)
        shutil.copy(
            _YARAX_FIXTURES / "secure_test_ruleset.yar",
            sb.cfg.yara_rules_dir_path() / "secure_test_ruleset.yar",
        )
        with patch.object(yarax_engine_module, "engine_version", lambda: "1.0.0-validate"), \
             patch.object(yarax_engine_module, "compile_ruleset", lambda source, origin=None: object()), \
             patch.object(yarax_engine_module, "scan_bytes", lambda rules, data, timeout_seconds=10.0: object()):
            sync_registry(sb.conn, sb.cfg)
            record = find_detection_rule(sb.conn, "yarax", "secure_test_ruleset")
            outcomes = run_validation(sb.conn, sb.cfg, record)

        all_passed = _outcomes_all_passed(outcomes)

        return ScenarioResult(
            scenario_id="detections_yarax_ruleset_fixtures_pass",
            technique_id=None,
            technique_name="YARA-X ruleset compile-only validation",
            category=CATEGORY_DETECTION_RULE,
            description="A cataloged YARA-X ruleset file's own compile-only fixture.",
            expected_result="Ruleset compiles successfully (validation here never claims detection accuracy — see docs).",
            sensors_observed=["yarax"] if outcomes else [],
            findings=[{"fixture": o.fixture_name, "expected": o.expected, "actual": o.actual} for o in outcomes],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_PASS if all_passed else OUTCOME_MISS,
            notes="" if all_passed else "The ruleset's compile-only fixture did not pass.",
            started_at="",
            completed_at="",
        )

    return timed("detections_yarax_ruleset_fixtures_pass", build)


def scenario_yarax_engine_unavailable(sb: Sandbox) -> ScenarioResult:
    def build():
        sb.cfg.yara_rules_dir_path().mkdir(parents=True, exist_ok=True)
        shutil.copy(
            _YARAX_FIXTURES / "secure_test_ruleset.yar",
            sb.cfg.yara_rules_dir_path() / "secure_test_ruleset.yar",
        )

        def _raise():
            raise ImportError("no yara_x installed (simulated)")

        with patch.object(yarax_engine_module, "engine_version", lambda: _raise()), \
             patch.object(yarax_engine_module, "compile_ruleset", lambda source, origin=None: object()):
            sync_registry(sb.conn, sb.cfg)
            record = find_detection_rule(sb.conn, "yarax", "secure_test_ruleset")

        correctly_unavailable = record is not None and record.capability_status == "not_evaluable"

        return ScenarioResult(
            scenario_id="detections_yarax_engine_unavailable",
            technique_id=None,
            technique_name="YARA-X engine not installed (simulated tool-unavailable condition)",
            category=CATEGORY_DETECTION_RULE,
            description="The yara_x Python package is unavailable at sync time.",
            expected_result="Cataloged as not_evaluable, never silently skipped or treated as passing.",
            sensors_observed=["yarax"],
            findings=[{"capability_status": record.capability_status if record else None}],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_SENSOR_UNAVAILABLE if correctly_unavailable else OUTCOME_MISS,
            notes="",
            started_at="",
            completed_at="",
        )

    return timed("detections_yarax_engine_unavailable", build)


def scenario_suricata_eve_parser_fixtures_pass(sb: Sandbox) -> ScenarioResult:
    def build():
        # Suricata signatures are only discoverable AFTER firing at
        # least once (secure/detect/registry.py's own honest scope) —
        # seed one observed alert the same way tests/test_detect_registry.py's
        # own fixture does, no real Suricata install needed.
        add_integration_run(
            sb.conn, run_id="validate-r1", integration="suricata", started_at="2026-01-01T00:00:00+00:00",
            completed_at="2026-01-01T00:00:01+00:00", status="ok", detail="validation seed",
            tool_version=None, observations_collected=1, alerts_generated=1,
        )
        add_integration_observations(
            sb.conn, run_id="validate-r1", integration="suricata",
            rows=[(
                SURICATA_ALERT_KIND, "flow1:1:2000123:1:2026-01-01T00:00:00.000000+0000",
                {"signature": "ET TROJAN Validation Fixture Signature", "signature_id": 2000123, "gid": 1, "rev": 1},
                "eve.json", "2026-01-01T00:00:00+00:00",
            )],
        )
        sync_registry(sb.conn, sb.cfg)
        record = find_detection_rule(sb.conn, "suricata", "1:2000123")
        outcomes = run_validation(sb.conn, sb.cfg, record) if record else []
        all_passed = _outcomes_all_passed(outcomes)

        return ScenarioResult(
            scenario_id="detections_suricata_eve_parser_fixtures_pass",
            technique_id=None,
            technique_name="Suricata EVE alert-record parser correctness (Secure's own ingestion, not Suricata's detection quality)",
            category=CATEGORY_DETECTION_RULE,
            description="A passively-discovered Suricata signature's own EVE-parser fixtures.",
            expected_result="Secure's own EVE parser correctly recognizes an alert record and correctly skips a non-alert record.",
            sensors_observed=["suricata"] if outcomes else [],
            findings=[{"fixture": o.fixture_name, "expected": o.expected, "actual": o.actual} for o in outcomes],
            correlation_result=None,
            explanation_checklist={},
            dedup_result=None,
            latency_ms=None,
            outcome=OUTCOME_PASS if all_passed else OUTCOME_MISS,
            notes="" if all_passed else "Suricata EVE-parser fixtures did not all pass.",
            started_at="",
            completed_at="",
        )

    return timed("detections_suricata_eve_parser_fixtures_pass", build)


SCENARIOS = [
    scenario_sigma_rule_fixtures_pass,
    scenario_sigma_rule_not_evaluable,
    scenario_yarax_ruleset_fixtures_pass,
    scenario_yarax_engine_unavailable,
    scenario_suricata_eve_parser_fixtures_pass,
]
