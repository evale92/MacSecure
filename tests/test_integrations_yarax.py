"""
Tests for secure/integrations/yarax/ (Phase 16: YARA-X integration).

Uses real, deterministic fixture files under tests/fixtures/yarax/
(rules/secure_test_ruleset.yar, samples/*.bin) — synthetic marker
strings, never a real detection signature (e.g. EICAR), so these are
safe to keep on disk without tripping any real antivirus tooling. The
actual `yara_x` engine calls are mocked at the `_engine.py` seam
(engine_version/compile_ruleset/scan_bytes), the same "patch the small
wrapper, not the real library" pattern secure/bluetooth/ble/scanner.py
already uses for `bleak` — this environment has no yara_x installed,
and the mocked scan_bytes() is driven by REAL file content (checking
for the fixture's marker strings), so these tests exercise real
hashing, real ruleset-file reading, and real DB persistence end to end,
with only the pattern-matching step itself simulated.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.config import default_config
from secure.correlate.signals import _collect_integrations
from secure.correlate.strength import MEDIUM, STRONG, WEAK, classify_yarax_finding_strength
from secure.explain.dispatch import explain
from secure.integrations.base import STATUS_DEGRADED, STATUS_ERROR, STATUS_OK, STATUS_UNAVAILABLE
from secure.integrations.yarax import analysis, parser, rulesets, targets
from secure.integrations.yarax import _engine as engine_module
from secure.integrations.yarax import availability as availability_module
from secure.integrations.yarax import scanner as scanner_module
from secure.storage.database import Database
from secure.storage.models import (
    add_file_integrity_alert,
    add_persistence_alert,
    list_integration_alerts,
    list_integration_observations,
    list_integration_runs,
)

FIXTURES = Path(__file__).parent / "fixtures" / "yarax"
RULES_DIR = FIXTURES / "rules"
SAMPLES_DIR = FIXTURES / "samples"

NOW = "2026-08-21T00:00:00+00:00"


# ---------- fake yara_x object shapes (duck-typed, mirror the real API) ----------


class FakeMatch:
    def __init__(self, offset, length):
        self.offset = offset
        self.length = length


class FakePattern:
    def __init__(self, identifier, matches):
        self.identifier = identifier
        self.matches = matches


class FakeRule:
    def __init__(self, identifier, namespace="default", tags=None, metadata=None, patterns=None):
        self.identifier = identifier
        self.namespace = namespace
        self.tags = tags or []
        self.metadata = metadata or {}
        self.patterns = patterns or []


class FakeScanResults:
    def __init__(self, matching_rules):
        self.matching_rules = matching_rules


def _fake_scan_bytes_by_marker(rules, data: bytes, timeout_seconds: float):
    """Deterministic stand-in for _engine.scan_bytes(): inspects the
    REAL bytes handed to it and returns matches for whichever synthetic
    markers from the fixture ruleset are actually present — same
    marker strings tests/fixtures/yarax/rules/secure_test_ruleset.yar
    defines, kept in sync deliberately.
    """
    matches = []
    if b"SECURE_TEST_MARKER_HIGH" in data:
        matches.append(
            FakeRule(
                "secure_test_marker_high",
                metadata={"description": "high severity fixture rule", "severity": "high"},
                patterns=[FakePattern("$marker", [FakeMatch(offset=26, length=24)])],
            )
        )
    if b"SECURE_TEST_MARKER_DEFAULT" in data:
        matches.append(
            FakeRule(
                "secure_test_marker_default",
                metadata={"description": "no declared severity"},
                patterns=[FakePattern("$marker", [FakeMatch(offset=26, length=27)])],
            )
        )
    return FakeScanResults(matches)


def _patch_engine_available(monkeypatch, version="1.0.0-test"):
    monkeypatch.setattr(engine_module, "engine_version", lambda: version)
    monkeypatch.setattr(engine_module, "compile_ruleset", lambda source, origin=None: object())
    monkeypatch.setattr(engine_module, "scan_bytes", _fake_scan_bytes_by_marker)


# ---------- availability.py ----------


def test_check_availability_unavailable_on_import_error(monkeypatch):
    def raise_import_error():
        raise ImportError("No module named 'yara_x'")

    monkeypatch.setattr(engine_module, "engine_version", raise_import_error)
    health = availability_module.check_availability()
    assert health.status == STATUS_UNAVAILABLE
    assert health.tool_version is None


def test_check_availability_error_when_smoke_test_fails(monkeypatch):
    monkeypatch.setattr(engine_module, "engine_version", lambda: "1.0.0")
    monkeypatch.setattr(
        engine_module, "compile_ruleset", lambda source, origin=None: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    health = availability_module.check_availability()
    assert health.status == STATUS_ERROR
    assert health.tool_version == "1.0.0"


def test_check_availability_ok_when_smoke_test_passes(monkeypatch):
    _patch_engine_available(monkeypatch)
    health = availability_module.check_availability()
    assert health.status == STATUS_OK
    assert health.tool_version == "1.0.0-test"


# ---------- rulesets.py ----------


def test_discover_ruleset_files_only_yar_extensions():
    found = rulesets.discover_ruleset_files(RULES_DIR)
    assert [p.name for p in found] == ["secure_test_ruleset.yar"]


def test_discover_ruleset_files_missing_dir_returns_empty(tmp_path: Path):
    assert rulesets.discover_ruleset_files(tmp_path / "does_not_exist") == []


def test_load_rulesets_success(monkeypatch):
    monkeypatch.setattr(engine_module, "compile_ruleset", lambda source, origin=None: object())
    compiled, errors = rulesets.load_rulesets(RULES_DIR)
    assert len(compiled) == 1
    assert errors == []
    assert compiled[0].info.name == "secure_test_ruleset"
    assert len(compiled[0].info.source_hash) == 64  # sha256 hex


def test_load_rulesets_records_compile_error_without_aborting(monkeypatch):
    monkeypatch.setattr(
        engine_module, "compile_ruleset", lambda source, origin=None: (_ for _ in ()).throw(SyntaxError("bad rule"))
    )
    compiled, errors = rulesets.load_rulesets(RULES_DIR)
    assert compiled == []
    assert len(errors) == 1
    assert "bad rule" in errors[0].detail


def test_ruleset_info_version_label_format(monkeypatch):
    monkeypatch.setattr(engine_module, "compile_ruleset", lambda source, origin=None: object())
    compiled, _ = rulesets.load_rulesets(RULES_DIR)
    label = compiled[0].info.version_label
    assert label.startswith("secure_test_ruleset@")
    assert len(label.split("@")[1]) == 12


# ---------- analysis.py ----------


def test_classify_yara_match_severity_recognized_keys():
    assert analysis.classify_yara_match_severity({"severity": "high"}) == "high"
    assert analysis.classify_yara_match_severity({"severity": "HIGH"}) == "high"
    assert analysis.classify_yara_match_severity({"Severity": "medium"}) == "medium"
    assert analysis.classify_yara_match_severity({"threat_level": "critical"}) == "high"
    assert analysis.classify_yara_match_severity({"threat_level": "1"}) == "low"


def test_classify_yara_match_severity_defaults_when_absent():
    assert analysis.classify_yara_match_severity({}) == analysis.DEFAULT_SEVERITY
    assert analysis.classify_yara_match_severity({"author": "someone"}) == analysis.DEFAULT_SEVERITY


def test_classify_yara_match_severity_defaults_when_unrecognized_value():
    assert analysis.classify_yara_match_severity({"severity": "extremely bad"}) == analysis.DEFAULT_SEVERITY


def test_rule_meta_has_recognized_severity():
    assert analysis.rule_meta_has_recognized_severity({"severity": "high"}) is True
    assert analysis.rule_meta_has_recognized_severity({}) is False
    assert analysis.rule_meta_has_recognized_severity({"severity": "nonsense"}) is False


def test_match_interpretation_note_always_includes_no_verdict_language():
    note = analysis.match_interpretation_note({}, had_recognized_severity=True)
    assert "not, by itself, a malware determination" in note or "not a malware determination" in note


def test_match_interpretation_note_flags_default_when_unrecognized():
    note = analysis.match_interpretation_note({}, had_recognized_severity=False)
    assert "non-committal default" in note


def test_match_interpretation_note_includes_description_and_author():
    note = analysis.match_interpretation_note(
        {"description": "test desc", "author": "test author"}, had_recognized_severity=True
    )
    assert "test desc" in note
    assert "test author" in note


# ---------- parser.py ----------


def test_parse_scan_results_empty_matching_rules_returns_empty_list():
    ruleset_info = rulesets.RulesetInfo(name="r", source_path="/x/r.yar", source_hash="a" * 64)
    result = parser.parse_scan_results(
        FakeScanResults([]), file_path="/x/f.bin", file_hash="deadbeef", ruleset_info=ruleset_info, collected_at=NOW
    )
    assert result == []


def test_parse_scan_results_normalizes_one_match():
    ruleset_info = rulesets.RulesetInfo(name="myruleset", source_path="/x/r.yar", source_hash="a" * 64)
    fake_results = FakeScanResults(
        [
            FakeRule(
                "my_rule", namespace="ns1", tags=["tag1"], metadata={"severity": "high"},
                patterns=[FakePattern("$a", [FakeMatch(offset=5, length=3)])],
            )
        ]
    )
    observations = parser.parse_scan_results(
        fake_results, file_path="/x/f.bin", file_hash="deadbeef", ruleset_info=ruleset_info, collected_at=NOW
    )
    assert len(observations) == 1
    obs = observations[0]
    assert obs.kind == "yara_match"
    assert obs.identity_key == "deadbeef:myruleset:ns1.my_rule"
    assert obs.fields["rule_name"] == "my_rule"
    assert obs.fields["rule_namespace"] == "ns1"
    assert obs.fields["rule_meta"] == {"severity": "high"}
    assert obs.fields["matched_patterns"][0]["identifier"] == "$a"
    assert obs.fields["matched_patterns"][0]["match_count"] == 1
    assert "myruleset@" in obs.source_query


def test_parse_scan_results_identity_key_falls_back_to_path_without_hash():
    ruleset_info = rulesets.RulesetInfo(name="r", source_path="/x/r.yar", source_hash="a" * 64)
    fake_results = FakeScanResults([FakeRule("my_rule")])
    observations = parser.parse_scan_results(
        fake_results, file_path="/x/f.bin", file_hash=None, ruleset_info=ruleset_info, collected_at=NOW
    )
    assert observations[0].identity_key.startswith("path:/x/f.bin:")


def test_normalize_metadata_handles_list_of_tuples():
    assert parser.normalize_metadata([("severity", "high"), ("author", "x")]) == {
        "severity": "high", "author": "x",
    }


def test_normalize_metadata_handles_none():
    assert parser.normalize_metadata(None) == {}


# ---------- scanner.py end-to-end ----------


def test_scan_paths_unavailable_never_looks_clean(tmp_path: Path, monkeypatch):
    def raise_import_error():
        raise ImportError("no yara_x")

    monkeypatch.setattr(engine_module, "engine_version", raise_import_error)

    cfg = default_config()
    cfg.app_dir = str(tmp_path)
    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_paths(db.conn, cfg, [str(SAMPLES_DIR / "marker_high.bin")])
        assert result.health.status == STATUS_UNAVAILABLE
        assert result.available is False
        assert result.observations == []
        assert result.findings == []

        runs = list_integration_runs(db.conn, integration="yarax")
        assert len(runs) == 1
        assert runs[0].status == STATUS_UNAVAILABLE
        assert runs[0].observations_collected == 0
        assert runs[0].alerts_generated == 0


def test_scan_paths_full_pass_with_high_severity_match(tmp_path: Path, monkeypatch):
    _patch_engine_available(monkeypatch)
    cfg = default_config()
    cfg.app_dir = str(tmp_path)
    (tmp_path / "yara_rules").mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy(RULES_DIR / "secure_test_ruleset.yar", tmp_path / "yara_rules" / "secure_test_ruleset.yar")

    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_paths(db.conn, cfg, [str(SAMPLES_DIR / "marker_high.bin")])

        assert result.health.status == STATUS_OK
        assert len(result.observations) == 1
        assert len(result.findings) == 1
        assert result.findings[0].severity == "high"
        assert result.findings[0].rule_name == "secure_test_marker_high"

        alerts = list_integration_alerts(db.conn, integration="yarax")
        assert len(alerts) == 1
        assert alerts[0].severity == "high"
        assert alerts[0].discrepancy == "match"
        assert alerts[0].source_observation_id is not None

        observations = list_integration_observations(db.conn, integration="yarax")
        assert len(observations) == 1
        assert alerts[0].source_observation_id == observations[0].id
        assert observations[0].fields["file_hash"] is not None


def test_scan_fim_alerts_match_records_evidence_link(tmp_path: Path, monkeypatch):
    """Phase 22 Stage 1 (additive): a finding on a file that was scanned
    BECAUSE of an existing file_integrity_alerts row now also gets a
    formal derived_evidence evidence_links row back to that alert —
    previously targets.py computed this exact relationship and then
    discarded it.
    """
    from secure.evidence.model import RELATIONSHIP_DERIVED_EVIDENCE
    from secure.storage.models import list_evidence_links_for

    _patch_engine_available(monkeypatch)
    cfg = default_config()
    cfg.app_dir = str(tmp_path)
    (tmp_path / "yara_rules").mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy(RULES_DIR / "secure_test_ruleset.yar", tmp_path / "yara_rules" / "secure_test_ruleset.yar")

    marker_path = str(SAMPLES_DIR / "marker_high.bin")

    with Database(tmp_path / "test.db") as db:
        fim_alert_id = add_file_integrity_alert(
            db.conn, run_id="fim-run-1", kind="modified", severity="high",
            path=marker_path, message="test fixture alert",
        )
        target_list, result = scanner_module.scan_fim_alerts(db.conn, cfg)

        assert len(target_list) == 1
        assert result.evidence_links_recorded == 1
        alerts = list_integration_alerts(db.conn, integration="yarax")
        assert len(alerts) == 1

        links = list_evidence_links_for(db.conn, "file_integrity_alerts", fim_alert_id)
        assert len(links) == 1
        assert links[0].relationship == RELATIONSHIP_DERIVED_EVIDENCE
        assert links[0].created_by == "yarax_scan_target"
        assert links[0].from_source_table == "integration_alerts"
        assert links[0].from_source_id == alerts[0].id
        assert links[0].to_source_table == "file_integrity_alerts"
        assert links[0].to_source_id == fim_alert_id


def test_scan_paths_manual_trigger_records_no_evidence_link(tmp_path: Path, monkeypatch):
    """A directly user-requested path (no `targets` passed) has no
    "caused by" ancestor and correctly gets no evidence_links row —
    this must remain true for the pre-existing `scan_paths()` behavior
    every earlier test in this file already exercises.
    """
    from secure.storage.models import list_evidence_links_for

    _patch_engine_available(monkeypatch)
    cfg = default_config()
    cfg.app_dir = str(tmp_path)
    (tmp_path / "yara_rules").mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy(RULES_DIR / "secure_test_ruleset.yar", tmp_path / "yara_rules" / "secure_test_ruleset.yar")

    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_paths(db.conn, cfg, [str(SAMPLES_DIR / "marker_high.bin")])
        assert result.evidence_links_recorded == 0
        alerts = list_integration_alerts(db.conn, integration="yarax")
        assert list_evidence_links_for(db.conn, "integration_alerts", alerts[0].id) == []


def test_scan_paths_default_severity_match_never_auto_classified_high(tmp_path: Path, monkeypatch):
    _patch_engine_available(monkeypatch)
    cfg = default_config()
    cfg.app_dir = str(tmp_path)
    (tmp_path / "yara_rules").mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy(RULES_DIR / "secure_test_ruleset.yar", tmp_path / "yara_rules" / "secure_test_ruleset.yar")

    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_paths(db.conn, cfg, [str(SAMPLES_DIR / "marker_default.bin")])
        assert len(result.findings) == 1
        assert result.findings[0].severity == "medium"  # DEFAULT_SEVERITY, never assumed high
        assert "non-committal default" in result.findings[0].message


def test_scan_paths_clean_file_produces_zero_findings_but_run_still_recorded(tmp_path: Path, monkeypatch):
    _patch_engine_available(monkeypatch)
    cfg = default_config()
    cfg.app_dir = str(tmp_path)
    (tmp_path / "yara_rules").mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy(RULES_DIR / "secure_test_ruleset.yar", tmp_path / "yara_rules" / "secure_test_ruleset.yar")

    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_paths(db.conn, cfg, [str(SAMPLES_DIR / "clean.bin")])
        assert result.health.status == STATUS_OK
        assert result.observations == []
        assert result.findings == []
        assert result.files[0].scanned is True

        runs = list_integration_runs(db.conn, integration="yarax")
        assert runs[0].status == STATUS_OK
        assert runs[0].observations_collected == 0


def test_scan_paths_never_expands_a_directory(tmp_path: Path, monkeypatch):
    _patch_engine_available(monkeypatch)
    cfg = default_config()
    cfg.app_dir = str(tmp_path)

    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_paths(db.conn, cfg, [str(SAMPLES_DIR)])
        assert result.files[0].scanned is False
        assert result.files[0].skip_reason == "is_a_directory"
        assert result.observations == []


def test_scan_paths_skips_nonexistent_file(tmp_path: Path, monkeypatch):
    _patch_engine_available(monkeypatch)
    cfg = default_config()
    cfg.app_dir = str(tmp_path)

    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_paths(db.conn, cfg, ["/definitely/not/a/real/path.bin"])
        assert result.files[0].scanned is False
        assert result.files[0].skip_reason == "not_found"


def test_scan_paths_skips_too_large_file(tmp_path: Path, monkeypatch):
    _patch_engine_available(monkeypatch)
    cfg = default_config()
    cfg.app_dir = str(tmp_path)

    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_paths(
            db.conn, cfg, [str(SAMPLES_DIR / "marker_high.bin")], max_bytes=1
        )
        assert result.files[0].scanned is False
        assert result.files[0].skip_reason == "too_large"


def test_scan_paths_one_bad_ruleset_does_not_abort_others(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(engine_module, "engine_version", lambda: "1.0.0")

    def compile_ruleset(source, origin=None):
        # Match the file name, not the whole path: origin is absolute,
        # and pytest names tmp_path after this test, which contains "bad".
        if Path(origin).name == "bad.yar":
            raise SyntaxError("bad rule")
        return object()

    monkeypatch.setattr(engine_module, "compile_ruleset", compile_ruleset)
    monkeypatch.setattr(engine_module, "scan_bytes", _fake_scan_bytes_by_marker)

    cfg = default_config()
    cfg.app_dir = str(tmp_path)
    rules_dir = tmp_path / "yara_rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "bad.yar").write_text("this is not valid yara")
    import shutil
    shutil.copy(RULES_DIR / "secure_test_ruleset.yar", rules_dir / "secure_test_ruleset.yar")

    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_paths(db.conn, cfg, [str(SAMPLES_DIR / "marker_high.bin")])
        assert result.health.status == STATUS_DEGRADED
        assert len(result.ruleset_load_errors) == 1
        assert len(result.rulesets_loaded) == 1
        assert len(result.findings) == 1  # the good ruleset still ran


def test_scan_paths_per_file_ruleset_scan_error_does_not_abort_other_rulesets(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(engine_module, "engine_version", lambda: "1.0.0")
    monkeypatch.setattr(engine_module, "compile_ruleset", lambda source, origin=None: object())

    def scan_bytes(rules, data, timeout_seconds):
        # Only fail for real (non-empty) scan input — the availability
        # smoke test itself scans b"" and must keep succeeding, or this
        # whole pass would short-circuit as unavailable before it ever
        # reaches the file this test actually cares about.
        if data:
            raise RuntimeError("scan blew up")
        return FakeScanResults([])

    monkeypatch.setattr(engine_module, "scan_bytes", scan_bytes)

    cfg = default_config()
    cfg.app_dir = str(tmp_path)
    rules_dir = tmp_path / "yara_rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy(RULES_DIR / "secure_test_ruleset.yar", rules_dir / "secure_test_ruleset.yar")

    with Database(tmp_path / "test.db") as db:
        result = scanner_module.scan_paths(db.conn, cfg, [str(SAMPLES_DIR / "marker_high.bin")])
        assert result.files[0].scanned is True
        assert len(result.files[0].ruleset_errors) == 1
        assert "scan blew up" in result.files[0].ruleset_errors[0]
        assert result.observations == []


# ---------- targets.py ----------


def test_fim_alert_targets_includes_medium_high_scannable_kinds(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_file_integrity_alert(
            db.conn, run_id="r1", kind="modified", severity="high", path="/x/high.bin",
            message="m", context_notes=None,
        )
        add_file_integrity_alert(
            db.conn, run_id="r1", kind="modified", severity="low", path="/x/low.bin",
            message="m", context_notes=None,
        )
        add_file_integrity_alert(
            db.conn, run_id="r1", kind="deleted", severity="high", path="/x/deleted.bin",
            message="m", context_notes=None,
        )
        result = targets.fim_alert_targets(db.conn)
        paths = [t.path for t in result]
        assert "/x/high.bin" in paths
        assert "/x/low.bin" not in paths  # LOW excluded
        assert "/x/deleted.bin" not in paths  # nothing left to scan


def test_fim_alert_targets_excludes_already_reviewed_by_default(tmp_path: Path):
    from secure.storage.models import find_file_integrity_alert_by_id, set_file_integrity_alert_known

    with Database(tmp_path / "test.db") as db:
        alert_id = add_file_integrity_alert(
            db.conn, run_id="r1", kind="modified", severity="high", path="/x/high.bin",
            message="m", context_notes=None,
        )
        set_file_integrity_alert_known(db.conn, alert_id, True)
        result = targets.fim_alert_targets(db.conn)
        assert result == []
        result_incl = targets.fim_alert_targets(db.conn, include_reviewed=True)
        assert len(result_incl) == 1


def test_persistence_suspicious_targets_filters_kind_and_target_type(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_persistence_alert(
            db.conn, run_id="r1", kind="unusual_unsigned_process", severity="high",
            target_type="process", identifier="/tmp/evil", label="evil", message="m",
        )
        add_persistence_alert(
            db.conn, run_id="r1", kind="new_persistence_entry", severity="medium",
            target_type="launch_agent_user", identifier="/x/com.evil.plist", label="evil",
            message="m",
        )
        result = targets.persistence_suspicious_targets(db.conn)
        assert len(result) == 1
        assert result[0].path == "/tmp/evil"


# ---------- correlate wiring ----------


def test_classify_yarax_finding_strength():
    assert classify_yarax_finding_strength("high") == STRONG
    assert classify_yarax_finding_strength("medium") == MEDIUM
    assert classify_yarax_finding_strength("low") == WEAK


def test_collect_integrations_dispatches_yarax_by_severity_not_flat_strong(tmp_path: Path):
    from secure.storage.models import add_integration_alert

    with Database(tmp_path / "test.db") as db:
        add_integration_alert(
            db.conn, run_id="r1", integration="yarax", kind="yara_match", discrepancy="match",
            severity="medium", identity_key="abc:rs:ns.rule", label="rule",
            message="A YARA rule matched.",
        )
        signals = _collect_integrations(db.conn, "2000-01-01T00:00:00+00:00")
        assert len(signals) == 1
        assert signals[0].strength == MEDIUM  # not STRONG — no blanket "match = malware"
        assert signals[0].kind == "yara_match"  # not suffixed with "_match" the way osquery's discrepancy is
        assert signals[0].module == "integrations"


def test_collect_integrations_yarax_high_severity_is_strong(tmp_path: Path):
    from secure.storage.models import add_integration_alert

    with Database(tmp_path / "test.db") as db:
        add_integration_alert(
            db.conn, run_id="r1", integration="yarax", kind="yara_match", discrepancy="match",
            severity="high", identity_key="abc:rs:ns.rule", label="rule", message="m",
        )
        signals = _collect_integrations(db.conn, "2000-01-01T00:00:00+00:00")
        assert signals[0].strength == STRONG


# ---------- explain wiring ----------


def test_explain_integration_alert_yarax_never_claims_confirmed_malware(tmp_path: Path):
    from secure.storage.models import IntegrationAlertRecord

    record = IntegrationAlertRecord(
        id=1, created_at=NOW, run_id="r1", integration="yarax", kind="yara_match",
        discrepancy="match", severity="high", identity_key="abc:rs:ns.rule", label="rule",
        message="A YARA rule matched.", source_observation_id=1, known=False,
    )
    exp = explain(record, "integration_alerts")
    assert exp.degraded is False
    assert exp.severity == "high"  # verbatim passthrough
    assert exp.recommended_action == "INSPECT_FILE"
    assert "not, by itself" in exp.significance or "not a malware determination" in exp.significance
    assert any("not a malware verdict" in u for u in exp.uncertainty)


def test_explain_integration_alert_osquery_still_works(tmp_path: Path):
    from secure.storage.models import IntegrationAlertRecord

    record = IntegrationAlertRecord(
        id=2, created_at=NOW, run_id="r1", integration="osquery", kind="listening_port",
        discrepancy="osquery_only", severity="high", identity_key="tcp:4444", label="evil",
        message="osquery saw a port native did not.", source_observation_id=1, known=False,
    )
    exp = explain(record, "integration_alerts")
    assert exp.degraded is False
    assert exp.severity == "high"


def test_explain_integration_alert_unrecognized_integration_degrades_gracefully(tmp_path: Path):
    from secure.storage.models import IntegrationAlertRecord

    record = IntegrationAlertRecord(
        id=3, created_at=NOW, run_id="r1", integration="future_engine", kind="x",
        discrepancy="y", severity="low", identity_key="z", label=None, message="original message",
        source_observation_id=None, known=False,
    )
    exp = explain(record, "integration_alerts")
    assert exp.degraded is True
    assert exp.severity == "low"  # never hidden even when degraded
    assert exp.summary  # generic_explanation still produces something


# ---------- containers the rules cannot see into (J-0665) ----------


def test_container_note_names_encrypted_and_compressed_containers():
    note = scanner_module.container_note
    encrypted_zip = b"PK\x03\x04" + b"\x14\x00" + b"\x01\x00" + b"\x00" * 30
    plain_zip = b"PK\x03\x04" + b"\x14\x00" + b"\x00\x00" + b"\x00" * 30
    assert note(encrypted_zip) == "encrypted_zip"
    assert note(plain_zip) == "zip_archive"
    assert note(b"AES\x02\x00rest") == "aes_crypt_encrypted"
    assert note(b"\x1f\x8b\x08\x00") == "gzip_compressed"
    assert note(b"\xfd7zXZ\x00\x00") == "xz_compressed"
    assert note(b"\x00" * 600 + b"koly" + b"\x00" * 508) == "disk_image"
    assert note(b"#!/bin/sh\necho hi\n") is None
    assert note(b"") is None


def test_a_scanned_container_carries_its_note_and_the_run_detail_counts_it(tmp_path, monkeypatch):
    blob = tmp_path / "invoice.zip"
    blob.write_bytes(b"PK\x03\x04\x14\x00\x01\x00" + b"\x00" * 64)
    monkeypatch.setattr(scanner_module, "compute_sha256", lambda p, max_bytes: ("h", None))
    result = scanner_module._scan_one_file(str(blob), [], "2026-09-16T00:00:00+00:00", 5.0, 1 << 20)
    assert result.scanned and result.observations == [] and result.content_note == "encrypted_zip"
