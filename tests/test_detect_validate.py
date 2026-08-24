"""
Tests for secure/detect/validate.py (Phase 25 Stage 3: deterministic
benign/suspicious fixtures + validation runner).

Run with:  pytest
"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path

from secure.config import AppConfig
from secure.detect import validate as validate_module
from secure.detect.registry import FAMILY_CORRELATE, FAMILY_SIGMA, FAMILY_SURICATA, FAMILY_YARAX
from secure.integrations.yarax import _engine as engine_module
from secure.storage.database import Database
from secure.storage.models import DetectionRuleRecord, list_detection_rule_test_runs, upsert_detection_rule

SIGMA_FIXTURES = Path(__file__).parent / "fixtures" / "sigma" / "rules"
YARAX_FIXTURES = Path(__file__).parent / "fixtures" / "yarax" / "rules"


def _cfg(tmp_path: Path) -> AppConfig:
    return AppConfig(app_dir=str(tmp_path))


def _record(**overrides) -> DetectionRuleRecord:
    now = datetime.now(timezone.utc).isoformat()
    base = dict(
        id=1, family="sigma", rule_key="x", title="t", source="s", version_label="v",
        enabled=True, required_telemetry="t", capability_status="evaluable", capability_reason="r",
        validation_status="unvalidated", last_tested_at=None, false_positive_notes="",
        first_seen_at=now, updated_at=now,
    )
    base.update(overrides)
    return DetectionRuleRecord(**base)


def _patch_yarax_engine(monkeypatch, version="1.0.0-test"):
    def fake_compile(source, origin=None):
        if "SECURE_DETECT_TEST_MALFORMED" in source:
            raise SyntaxError("deliberately malformed fixture")
        return object()

    monkeypatch.setattr(engine_module, "engine_version", lambda: version)
    monkeypatch.setattr(engine_module, "compile_ruleset", fake_compile)


# ---------- sigma ----------


def test_sigma_evaluable_rule_passes_both_fixtures(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(SIGMA_FIXTURES / "process_creation_match.yml", cfg.sigma_rules_dir_path() / "process_creation_match.yml")

    record = _record(family=FAMILY_SIGMA, rule_key="11111111-1111-1111-1111-111111111111")
    outcomes = validate_module.run_validation(None, cfg, record)
    assert len(outcomes) == 2
    suspicious = next(o for o in outcomes if o.fixture_name == "suspicious")
    benign = next(o for o in outcomes if o.fixture_name == "benign")
    assert suspicious.actual == "fire"
    assert suspicious.passed is True
    assert benign.actual == "no_fire"
    assert benign.passed is True


def test_sigma_not_evaluable_rule_fails_honestly(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(SIGMA_FIXTURES / "windows_only.yml", cfg.sigma_rules_dir_path() / "windows_only.yml")

    # windows_only.yml's own rule id — read it to avoid hardcoding a
    # wrong guess; any of this fixture's real id is fine since we only
    # need SOME evaluable-check-failing rule.
    import yaml as _y  # only for reading the fixture's own id in this test, not production code
    data = _y.safe_load((SIGMA_FIXTURES / "windows_only.yml").read_text())

    record = _record(family=FAMILY_SIGMA, rule_key=data["id"])
    outcomes = validate_module.run_validation(None, cfg, record)
    assert all(o.actual == "not_evaluable" for o in outcomes)
    assert all(o.passed is False for o in outcomes)


def test_sigma_rule_missing_from_disk_errors(tmp_path: Path):
    cfg = _cfg(tmp_path)
    record = _record(family=FAMILY_SIGMA, rule_key="does-not-exist")
    outcomes = validate_module.run_validation(None, cfg, record)
    assert all(o.actual == "error" for o in outcomes)


# ---------- yarax ----------


def test_yarax_ruleset_compiles_passes(tmp_path: Path, monkeypatch):
    _patch_yarax_engine(monkeypatch)
    cfg = _cfg(tmp_path)
    cfg.yara_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(YARAX_FIXTURES / "secure_test_ruleset.yar", cfg.yara_rules_dir_path() / "secure_test_ruleset.yar")

    record = _record(family=FAMILY_YARAX, rule_key="secure_test_ruleset")
    outcomes = validate_module.run_validation(None, cfg, record)
    assert len(outcomes) == 1
    assert outcomes[0].actual == "compiles"
    assert outcomes[0].passed is True


def test_yarax_ruleset_compile_error_fails(tmp_path: Path, monkeypatch):
    _patch_yarax_engine(monkeypatch)
    cfg = _cfg(tmp_path)
    cfg.yara_rules_dir_path().mkdir(parents=True, exist_ok=True)
    (cfg.yara_rules_dir_path() / "broken.yar").write_text("SECURE_DETECT_TEST_MALFORMED not real yara syntax")

    record = _record(family=FAMILY_YARAX, rule_key="broken")
    outcomes = validate_module.run_validation(None, cfg, record)
    assert outcomes[0].actual == "compile_error"
    assert outcomes[0].passed is False


# ---------- suricata ----------


def test_suricata_fixtures_pass(tmp_path: Path):
    cfg = _cfg(tmp_path)
    record = _record(family=FAMILY_SURICATA, rule_key="1:2000123", title="ET TROJAN Test Signature")
    outcomes = validate_module.run_validation(None, cfg, record)
    assert len(outcomes) == 2
    assert all(o.passed for o in outcomes)
    suspicious = next(o for o in outcomes if "suspicious" in o.fixture_name)
    benign = next(o for o in outcomes if "benign" in o.fixture_name)
    assert suspicious.actual == "fire"
    assert benign.actual == "no_fire"


# ---------- correlate ----------


def test_correlate_temporal_clustering_fixtures_pass(tmp_path: Path):
    cfg = _cfg(tmp_path)
    record = _record(family=FAMILY_CORRELATE, rule_key="temporal_clustering")
    outcomes = validate_module.run_validation(None, cfg, record)
    assert len(outcomes) == 2
    assert all(o.passed for o in outcomes)


def test_correlate_chain_scoring_fixtures_pass(tmp_path: Path):
    cfg = _cfg(tmp_path)
    record = _record(family=FAMILY_CORRELATE, rule_key="chain_scoring")
    outcomes = validate_module.run_validation(None, cfg, record)
    assert len(outcomes) == 2
    assert all(o.passed for o in outcomes)


def test_correlate_chain_scoring_never_touches_a_real_database(tmp_path: Path):
    # The whole point of the throwaway temp-file DB: running this
    # fixture must leave the CALLER's real database completely
    # untouched — no fixture rows leaked into it.
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "real.db") as db:
        record = _record(family=FAMILY_CORRELATE, rule_key="chain_scoring")
        validate_module.run_validation(db.conn, cfg, record)
        count = db.conn.execute("SELECT COUNT(*) AS c FROM process_entries").fetchone()["c"]
        assert count == 0


# ---------- validate_and_record: end-to-end persistence ----------


def test_validate_and_record_persists_append_only_history_and_status(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "test.db") as db:
        record, _ = upsert_detection_rule(
            db.conn, family=FAMILY_CORRELATE, rule_key="temporal_clustering", title="t", source="s",
            version_label="v1", required_telemetry="rt", capability_status="evaluable", capability_reason="r",
        )
        updated, outcomes = validate_module.validate_and_record(db.conn, cfg, record)
        assert updated.validation_status == "passed"
        assert updated.last_tested_at is not None

        runs = list_detection_rule_test_runs(db.conn, record.id)
        assert len(runs) == len(outcomes)
        assert all(r.passed for r in runs)


def test_validate_and_record_overall_fails_if_any_fixture_fails(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "test.db") as db:
        record, _ = upsert_detection_rule(
            db.conn, family=FAMILY_SIGMA, rule_key="does-not-exist", title="t", source="s",
            version_label="v1", required_telemetry="rt", capability_status="evaluable", capability_reason="r",
        )
        updated, _ = validate_module.validate_and_record(db.conn, cfg, record)
        assert updated.validation_status == "failed"


def test_validate_and_record_repeated_runs_accumulate_history(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "test.db") as db:
        record, _ = upsert_detection_rule(
            db.conn, family=FAMILY_CORRELATE, rule_key="chain_scoring", title="t", source="s",
            version_label="v1", required_telemetry="rt", capability_status="evaluable", capability_reason="r",
        )
        validate_module.validate_and_record(db.conn, cfg, record)
        validate_module.validate_and_record(db.conn, cfg, record)
        runs = list_detection_rule_test_runs(db.conn, record.id)
        # Two fixtures per run, two runs -> 4 rows, never overwritten.
        assert len(runs) == 4
