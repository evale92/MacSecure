"""
Phase 25 Stage 6: adversarial coverage for the Detection Engineering
Workbench's central safety claims — not "does the feature work" (that's
tests/test_detect_registry.py, test_detect_validate.py,
test_detect_firing_history.py, tests/test_cli_detect.py) but "can the
feature's own stated guarantees be caught lying":

  1. Enforcement is INERT by default. A deployment that has never run
     `secure detect sync`, or has synced but disabled nothing, gets
     byte-for-byte identical sigma/yarax scan behavior to before Phase
     25 existed.
  2. Enforcement is REAL for sigma/yarax once explicitly disabled — a
     disabled rule/ruleset is skipped BEFORE capability-check/
     evaluation, and disabling one rule never affects an unrelated one.
  3. Enforcement is HONESTLY ABSENT for suricata/correlate — `enabled`
     is recorded but a static whole-repo guard proves no scanner or
     correlation engine for those two families ever reads it, mirroring
     the ast-based guard style tests/test_dfir_adversarial.py already
     established for Phase 24.
  4. Validation status is never fabricated — a freshly synced/never-
     tested rule reads "unvalidated", never silently "passed".

Run with:  pytest
"""

from __future__ import annotations

import ast
import shutil
from pathlib import Path

from secure.config import AppConfig
from secure.correlate.chains import score_chain
from secure.evidence.model import EvidenceLink, ObservationRef, RELATIONSHIP_DERIVED_EVIDENCE
from secure.evidence.record import record_link
from secure.detect.registry import sync_registry
from secure.integrations.sigma.scanner import scan_sigma
from secure.integrations.yarax import _engine as engine_module
from secure.integrations.yarax.scanner import scan_paths
from secure.storage.database import Database
from secure.storage.models import (
    find_detection_rule,
    list_detection_rules,
    set_detection_rule_enabled,
    upsert_process_entry,
)

SIGMA_FIXTURES = Path(__file__).parent / "fixtures" / "sigma" / "rules"
YARAX_FIXTURES = Path(__file__).parent / "fixtures" / "yarax" / "rules"

REPO_ROOT = Path(__file__).parent.parent


def _cfg(tmp_path: Path) -> AppConfig:
    return AppConfig(app_dir=str(tmp_path))


def _patch_yarax_engine(monkeypatch, version="1.0.0-test"):
    monkeypatch.setattr(engine_module, "engine_version", lambda: version)
    monkeypatch.setattr(engine_module, "compile_ruleset", lambda source, origin=None: object())
    monkeypatch.setattr(engine_module, "scan_bytes", lambda rules, data, timeout_seconds=10.0: object())


# ---------- sigma: inert by default, real once disabled ----------


def test_sigma_scan_unaffected_before_any_sync(tmp_path: Path):
    """No detection_rules rows exist at all — the query the scanner
    makes must come back empty and every rule must still load/evaluate
    exactly as it did before Phase 25."""
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(
        SIGMA_FIXTURES / "process_creation_match.yml",
        cfg.sigma_rules_dir_path() / "process_creation_match.yml",
    )
    with Database(tmp_path / "test.db") as db:
        result = scan_sigma(db.conn, cfg)
        assert len(result.rules_loaded) == 1
        assert result.evaluable_count == 1


def test_sigma_scan_unaffected_after_sync_with_nothing_disabled(tmp_path: Path):
    """Sync has run (rows now exist, all default enabled=True) but
    nothing was ever disabled — output must still be identical."""
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(
        SIGMA_FIXTURES / "process_creation_match.yml",
        cfg.sigma_rules_dir_path() / "process_creation_match.yml",
    )
    with Database(tmp_path / "test.db") as db:
        sync_registry(db.conn, cfg)
        result = scan_sigma(db.conn, cfg)
        assert len(result.rules_loaded) == 1
        assert result.evaluable_count == 1


def test_sigma_disabled_rule_skipped_before_evaluation(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(
        SIGMA_FIXTURES / "process_creation_match.yml",
        cfg.sigma_rules_dir_path() / "process_creation_match.yml",
    )
    with Database(tmp_path / "test.db") as db:
        sync_registry(db.conn, cfg)
        record = find_detection_rule(db.conn, "sigma", "11111111-1111-1111-1111-111111111111")
        set_detection_rule_enabled(db.conn, record.id, False)

        result = scan_sigma(db.conn, cfg)
        assert result.rules_loaded == []
        assert result.evaluable_count == 0
        # Not just "not evaluated" — skipped so early it never even
        # gets a sigma_rule_result observation row.
        assert result.outcomes == []


def test_sigma_disabling_one_rule_never_affects_an_unrelated_rule(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(
        SIGMA_FIXTURES / "process_creation_match.yml",
        cfg.sigma_rules_dir_path() / "process_creation_match.yml",
    )
    shutil.copy(
        SIGMA_FIXTURES / "windows_only.yml",
        cfg.sigma_rules_dir_path() / "windows_only.yml",
    )
    with Database(tmp_path / "test.db") as db:
        sync_registry(db.conn, cfg)
        disabled = find_detection_rule(db.conn, "sigma", "11111111-1111-1111-1111-111111111111")
        set_detection_rule_enabled(db.conn, disabled.id, False)

        result = scan_sigma(db.conn, cfg)
        remaining_ids = {r.rule_id for r in result.rules_loaded}
        assert remaining_ids == {"66666666-6666-6666-6666-666666666666"}


def test_sigma_re_enabling_restores_evaluation(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(
        SIGMA_FIXTURES / "process_creation_match.yml",
        cfg.sigma_rules_dir_path() / "process_creation_match.yml",
    )
    with Database(tmp_path / "test.db") as db:
        sync_registry(db.conn, cfg)
        record = find_detection_rule(db.conn, "sigma", "11111111-1111-1111-1111-111111111111")
        set_detection_rule_enabled(db.conn, record.id, False)
        assert scan_sigma(db.conn, cfg).rules_loaded == []

        set_detection_rule_enabled(db.conn, record.id, True)
        result = scan_sigma(db.conn, cfg)
        assert len(result.rules_loaded) == 1


# ---------- yarax: inert by default, real once disabled ----------


def test_yarax_scan_unaffected_before_any_sync(tmp_path: Path, monkeypatch):
    _patch_yarax_engine(monkeypatch)
    cfg = _cfg(tmp_path)
    cfg.yara_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(
        YARAX_FIXTURES / "secure_test_ruleset.yar",
        cfg.yara_rules_dir_path() / "secure_test_ruleset.yar",
    )
    with Database(tmp_path / "test.db") as db:
        result = scan_paths(db.conn, cfg, paths=[])
        assert len(result.rulesets_loaded) == 1


def test_yarax_disabled_ruleset_skipped_before_scan(tmp_path: Path, monkeypatch):
    _patch_yarax_engine(monkeypatch)
    cfg = _cfg(tmp_path)
    cfg.yara_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(
        YARAX_FIXTURES / "secure_test_ruleset.yar",
        cfg.yara_rules_dir_path() / "secure_test_ruleset.yar",
    )
    with Database(tmp_path / "test.db") as db:
        sync_registry(db.conn, cfg)
        record = find_detection_rule(db.conn, "yarax", "secure_test_ruleset")
        set_detection_rule_enabled(db.conn, record.id, False)

        result = scan_paths(db.conn, cfg, paths=[])
        assert len(result.rulesets_loaded) == 0


def test_yarax_scan_unaffected_after_sync_with_nothing_disabled(tmp_path: Path, monkeypatch):
    _patch_yarax_engine(monkeypatch)
    cfg = _cfg(tmp_path)
    cfg.yara_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(
        YARAX_FIXTURES / "secure_test_ruleset.yar",
        cfg.yara_rules_dir_path() / "secure_test_ruleset.yar",
    )
    with Database(tmp_path / "test.db") as db:
        sync_registry(db.conn, cfg)
        result = scan_paths(db.conn, cfg, paths=[])
        assert len(result.rulesets_loaded) == 1


# ---------- suricata / correlate: enabled is honestly non-enforced ----------


def test_disabling_a_correlate_engine_does_not_change_chain_scoring_output(tmp_path: Path):
    """chain_scoring is tracking-only: score_chain() must produce the
    identical score whether or not its catalog row is disabled, proving
    the CLI's "tracking-only" claim (secure/cli/detect.py's own note)
    is actually true and not just documented."""
    cfg = _cfg(tmp_path)
    with Database(tmp_path / "test.db") as db:
        conn = db.conn
        sync_registry(conn, cfg)

        upsert_process_entry(conn, "/usr/bin/fixture_proc", "fixture_proc", "root", "unsigned")
        proc_row = conn.execute(
            "SELECT id FROM process_entries WHERE executable_path = ?", ("/usr/bin/fixture_proc",)
        ).fetchone()
        conn.execute(
            "INSERT INTO persistence_alerts (created_at, run_id, kind, severity, target_type, "
            "identifier, label, message, known) VALUES (?, 'r1', 'unusual_unsigned_process', 'high', "
            "'process', ?, 'fixture', 'fixture', 0)",
            ("2026-01-01T00:00:00+00:00", "/usr/bin/fixture_proc"),
        )
        conn.commit()
        alert_row = conn.execute(
            "SELECT id FROM persistence_alerts WHERE identifier = ?", ("/usr/bin/fixture_proc",)
        ).fetchone()
        record_link(
            conn,
            EvidenceLink(
                from_ref=ObservationRef(source_table="process_entries", source_id=proc_row["id"]),
                to_ref=ObservationRef(source_table="persistence_alerts", source_id=alert_row["id"]),
                relationship=RELATIONSHIP_DERIVED_EVIDENCE, match_basis="test", detail="test link",
                created_by="test",
            ),
        )

        ref = ObservationRef(source_table="process_entries", source_id=proc_row["id"])
        score_while_enabled = score_chain(conn, ref, boot_time=None, boot_time_resolved=True)

        engine = find_detection_rule(conn, "correlate", "chain_scoring")
        set_detection_rule_enabled(conn, engine.id, False)

        score_while_disabled = score_chain(conn, ref, boot_time=None, boot_time_resolved=True)

        assert score_while_enabled.confidence == score_while_disabled.confidence
        assert score_while_enabled.score == score_while_disabled.score


def test_no_scanner_or_correlation_module_reads_detection_rules_enabled_state_except_sigma_and_yarax():
    """Static whole-repo guard (mirrors tests/test_dfir_adversarial.py's
    ast-based guard for Phase 24): confirms the "tracking-only for
    suricata/correlate" claim isn't just a comment — those modules'
    source literally never calls list_detection_rules at all, so there
    is no code path by which disabling one of their catalog rows could
    ever suppress anything.
    """
    must_not_reference = [
        REPO_ROOT / "secure" / "integrations" / "suricata" / "scanner.py",
        REPO_ROOT / "secure" / "integrations" / "suricata" / "correlate.py",
        REPO_ROOT / "secure" / "correlate" / "scanner.py",
        REPO_ROOT / "secure" / "correlate" / "chain_scanner.py",
        REPO_ROOT / "secure" / "correlate" / "chains.py",
        REPO_ROOT / "secure" / "correlate" / "analysis.py",
        REPO_ROOT / "secure" / "correlate" / "signals.py",
    ]
    offenders = []
    for path in must_not_reference:
        assert path.exists(), f"expected file not found: {path}"
        source = path.read_text()
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "list_detection_rules":
                offenders.append(str(path))
            if isinstance(node, ast.Attribute) and node.attr == "list_detection_rules":
                offenders.append(str(path))
    assert offenders == [], (
        f"these modules must never consult detection_rules.enabled (tracking-only "
        f"families): {offenders}"
    )


def test_only_sigma_and_yarax_scanners_enforce_the_enabled_flag():
    """Positive counterpart of the guard above: confirms the two
    families that DO claim real enforcement actually call
    list_detection_rules — a regression guard against someone quietly
    removing the enforcement lines while leaving the CLI's claims and
    docs untouched."""
    must_reference = [
        REPO_ROOT / "secure" / "integrations" / "sigma" / "scanner.py",
        REPO_ROOT / "secure" / "integrations" / "yarax" / "scanner.py",
    ]
    for path in must_reference:
        source = path.read_text()
        tree = ast.parse(source, filename=str(path))
        found = any(
            (isinstance(node, ast.Name) and node.id == "list_detection_rules")
            or (isinstance(node, ast.Attribute) and node.attr == "list_detection_rules")
            for node in ast.walk(tree)
        )
        assert found, f"{path} was expected to enforce detection_rules.enabled but does not"


# ---------- validation status is never fabricated ----------


def test_freshly_synced_rule_is_unvalidated_never_fabricated_passed(tmp_path: Path):
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(
        SIGMA_FIXTURES / "process_creation_match.yml",
        cfg.sigma_rules_dir_path() / "process_creation_match.yml",
    )
    with Database(tmp_path / "test.db") as db:
        sync_registry(db.conn, cfg)
        rows = list_detection_rules(db.conn, family="sigma")
        assert len(rows) == 1
        assert rows[0].validation_status == "unvalidated"
        assert rows[0].last_tested_at is None


def test_resync_never_fabricates_validation_status_for_an_untested_rule(tmp_path: Path):
    """Even after several resyncs (which refresh discovered facts like
    title/telemetry/capability), a rule nobody has ever run
    `secure detect test` against must still read unvalidated."""
    cfg = _cfg(tmp_path)
    cfg.sigma_rules_dir_path().mkdir(parents=True, exist_ok=True)
    shutil.copy(
        SIGMA_FIXTURES / "process_creation_match.yml",
        cfg.sigma_rules_dir_path() / "process_creation_match.yml",
    )
    with Database(tmp_path / "test.db") as db:
        sync_registry(db.conn, cfg)
        sync_registry(db.conn, cfg)
        sync_registry(db.conn, cfg)
        record = find_detection_rule(db.conn, "sigma", "11111111-1111-1111-1111-111111111111")
        assert record.validation_status == "unvalidated"
        assert record.last_tested_at is None
