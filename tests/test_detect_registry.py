"""
Tests for secure/detect/registry.py (Phase 25 Stage 2: per-family
discovery/sync into the detection_rules catalog).

Reuses the SAME deterministic fixture files
tests/test_integrations_sigma.py and tests/test_integrations_yarax.py
already rely on (tests/fixtures/sigma/rules/,
tests/fixtures/yarax/rules/) — no new rule content invented here.
YARA-X's own engine is monkeypatched exactly like
test_integrations_yarax.py's own `_patch_engine_available()` does,
since no real yara_x install is assumed in this sandbox.

Run with:  pytest
"""

from __future__ import annotations

import shutil
from pathlib import Path

from secure.config import AppConfig
from secure.detect import registry as registry_module
from secure.integrations.suricata.parser import ALERT_KIND as SURICATA_ALERT_KIND
from secure.integrations.yarax import _engine as engine_module
from secure.integrations.yarax import availability as yarax_availability_module
from secure.storage.database import Database
from secure.storage.models import add_integration_observations, add_integration_run, list_detection_rules

SIGMA_FIXTURES = Path(__file__).parent / "fixtures" / "sigma" / "rules"
YARAX_FIXTURES = Path(__file__).parent / "fixtures" / "yarax" / "rules"


def _cfg(tmp_path: Path) -> AppConfig:
    return AppConfig(app_dir=str(tmp_path))


def _patch_yarax_engine(monkeypatch, version="1.0.0-test"):
    monkeypatch.setattr(engine_module, "engine_version", lambda: version)
    monkeypatch.setattr(engine_module, "compile_ruleset", lambda source, origin=None: object())
    monkeypatch.setattr(engine_module, "scan_bytes", lambda rules, data, timeout_seconds=10.0: object())


# ---------- sigma ----------


def test_sync_sigma_catalogs_evaluable_rule(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(SIGMA_FIXTURES / "process_creation_match.yml", cfg.sigma_rules_dir_path() / "process_creation_match.yml")

    with Database(tmp_path / "test.db") as db:
        result = registry_module.sync_registry(db.conn, cfg)
        assert len(result.sigma) == 1
        record, created = result.sigma[0]
        assert created is True
        assert record.family == "sigma"
        assert record.rule_key == "11111111-1111-1111-1111-111111111111"
        assert record.capability_status == "evaluable"
        assert "osquery" in record.required_telemetry


def test_sync_sigma_not_evaluable_rule_still_cataloged(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(SIGMA_FIXTURES / "windows_only.yml", cfg.sigma_rules_dir_path() / "windows_only.yml")

    with Database(tmp_path / "test.db") as db:
        result = registry_module.sync_registry(db.conn, cfg)
        assert len(result.sigma) == 1
        record, _ = result.sigma[0]
        assert record.capability_status == "not_evaluable"


def test_sync_sigma_malformed_rule_not_cataloged_but_reported(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(SIGMA_FIXTURES / "malformed.yml", cfg.sigma_rules_dir_path() / "malformed.yml")

    with Database(tmp_path / "test.db") as db:
        result = registry_module.sync_registry(db.conn, cfg)
        assert result.sigma == []
        assert any("sigma" in m for m in result.messages)


def test_sync_sigma_resync_updates_not_duplicates(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(SIGMA_FIXTURES / "process_creation_match.yml", cfg.sigma_rules_dir_path() / "process_creation_match.yml")

    with Database(tmp_path / "test.db") as db:
        registry_module.sync_registry(db.conn, cfg)
        registry_module.sync_registry(db.conn, cfg)
        rows = list_detection_rules(db.conn, family="sigma")
        assert len(rows) == 1


# ---------- yarax ----------


def test_sync_yarax_catalogs_ruleset_file_granularity(tmp_path: Path, monkeypatch):
    _patch_yarax_engine(monkeypatch)
    cfg = _cfg(tmp_path)
    cfg.yara_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(YARAX_FIXTURES / "secure_test_ruleset.yar", cfg.yara_rules_dir_path() / "secure_test_ruleset.yar")

    with Database(tmp_path / "test.db") as db:
        result = registry_module.sync_registry(db.conn, cfg)
        # One catalog row per FILE, not per named rule inside it — the
        # fixture file has two rules (secure_test_marker_high,
        # secure_test_marker_default), but ruleset-file granularity was
        # the explicitly approved design.
        assert len(result.yarax) == 1
        record, created = result.yarax[0]
        assert created is True
        assert record.family == "yarax"
        assert record.rule_key == "secure_test_ruleset"
        assert record.capability_status == "evaluable"


def test_sync_yarax_engine_unavailable_marks_not_evaluable(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(engine_module, "engine_version", lambda: (_ for _ in ()).throw(ImportError("no yara_x")))
    monkeypatch.setattr(engine_module, "compile_ruleset", lambda source, origin=None: object())
    cfg = _cfg(tmp_path)
    cfg.yara_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(YARAX_FIXTURES / "secure_test_ruleset.yar", cfg.yara_rules_dir_path() / "secure_test_ruleset.yar")

    with Database(tmp_path / "test.db") as db:
        result = registry_module.sync_registry(db.conn, cfg)
        record, _ = result.yarax[0]
        assert record.capability_status == "not_evaluable"


# ---------- suricata ----------


def test_sync_suricata_no_alerts_yet_catalogs_nothing(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "test.db") as db:
        result = registry_module.sync_registry(db.conn, cfg)
        assert result.suricata == []


def test_sync_suricata_catalogs_observed_signature(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "test.db") as db:
        add_integration_run(
            db.conn, run_id="r1", integration="suricata", started_at="2026-01-01T00:00:00+00:00",
            completed_at="2026-01-01T00:00:01+00:00", status="ok", detail="d", tool_version=None,
            observations_collected=1, alerts_generated=1,
        )
        add_integration_observations(
            db.conn, run_id="r1", integration="suricata",
            rows=[(
                SURICATA_ALERT_KIND, "flow1:1:2000123:1:2026-01-01T00:00:00.000000+0000",
                {"signature": "ET TROJAN Test Signature", "signature_id": 2000123, "gid": 1, "rev": 3, "severity": 1},
                "eve.json", "2026-01-01T00:00:00+00:00",
            )],
        )

        result = registry_module.sync_registry(db.conn, cfg)
        assert len(result.suricata) == 1
        record, created = result.suricata[0]
        assert created is True
        assert record.rule_key == "1:2000123"
        assert record.title == "ET TROJAN Test Signature"
        assert record.version_label == "rev=3"
        assert "external" in record.source.lower()


def test_sync_suricata_deduplicates_repeat_firings(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "test.db") as db:
        add_integration_run(
            db.conn, run_id="r1", integration="suricata", started_at="2026-01-01T00:00:00+00:00",
            completed_at="2026-01-01T00:00:01+00:00", status="ok", detail="d", tool_version=None,
            observations_collected=2, alerts_generated=2,
        )
        add_integration_observations(
            db.conn, run_id="r1", integration="suricata",
            rows=[
                (SURICATA_ALERT_KIND, "flow1:1:2000123:1:t1",
                 {"signature": "ET TROJAN Test Signature", "signature_id": 2000123, "gid": 1, "rev": 3}, "eve.json", "2026-01-01T00:00:00+00:00"),
                (SURICATA_ALERT_KIND, "flow2:1:2000123:1:t2",
                 {"signature": "ET TROJAN Test Signature", "signature_id": 2000123, "gid": 1, "rev": 3}, "eve.json", "2026-01-01T00:00:01+00:00"),
            ],
        )
        result = registry_module.sync_registry(db.conn, cfg)
        assert len(result.suricata) == 1


# ---------- correlate ----------


def test_sync_correlate_always_registers_exactly_two_static_engines(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "test.db") as db:
        result = registry_module.sync_registry(db.conn, cfg)
        keys = {r.rule_key for r, _ in result.correlate}
        assert keys == {"temporal_clustering", "chain_scoring"}
        assert all(r.capability_status == "evaluable" for r, _ in result.correlate)


def test_sync_correlate_idempotent_on_resync(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "test.db") as db:
        registry_module.sync_registry(db.conn, cfg)
        registry_module.sync_registry(db.conn, cfg)
        rows = list_detection_rules(db.conn, family="correlate")
        assert len(rows) == 2


# ---------- refresh_capability (live re-check) ----------


def test_refresh_capability_sigma_rule_no_longer_on_disk(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(SIGMA_FIXTURES / "process_creation_match.yml", cfg.sigma_rules_dir_path() / "process_creation_match.yml")

    with Database(tmp_path / "test.db") as db:
        result = registry_module.sync_registry(db.conn, cfg)
        record, _ = result.sigma[0]

        (cfg.sigma_rules_dir_path() / "process_creation_match.yml").unlink()
        status, reason = registry_module.refresh_capability(db.conn, cfg, record)
        assert status == "unknown"
        assert "no longer found" in reason


def test_refresh_capability_correlate_is_always_evaluable(tmp_path: Path):
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "test.db") as db:
        result = registry_module.sync_registry(db.conn, cfg)
        record = next(r for r, _ in result.correlate if r.rule_key == "chain_scoring")
        status, _ = registry_module.refresh_capability(db.conn, cfg, record)
        assert status == "evaluable"
