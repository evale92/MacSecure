"""
secure/detect/validate.py — Phase 25 Stage 3: deterministic benign and
suspicious fixtures per family, run through each family's OWN existing
evaluator — never a new evaluation engine, per secure/detect/
__init__.py's own rule 2. `secure detect test` is the only caller that
persists results; the run_* functions below are pure/read-mostly and
never call collect_evidence-style external actions.

Honest scope note, stated once here rather than re-litigated per
family — what "validated" actually means differs by family, and this
module is explicit about that rather than pretending a uniform meaning
exists:

  - Sigma: a "suspicious" event is synthesized by literally
    instantiating every selector value referenced anywhere in the
    rule's own detection block (works cleanly for the common
    AND-of-literal-selectors shape most real rules use — including
    string modifiers like |contains/|endswith, since a value trivially
    contains/starts-with/ends-with itself); "benign" is an event with
    none of the rule's mapped fields set at all. A rule whose condition
    structurally depends on an ABSENT field (a `not` branch) may not
    get a fully faithful suspicious instantiation — evaluate_rule()
    itself, never this synthesis, remains the source of truth for
    whether the rule actually fired.
  - YARA-X (ruleset-file granularity): Secure cannot synthesize file
    content that satisfies an ARBITRARY operator-authored YARA pattern
    without parsing YARA's own string/regex/hex grammar — out of scope
    for this phase. Validation here means "does this ruleset still
    compile," never "does it correctly detect its intended threat."
  - Suricata: Secure never has signature content to test against at
    all (see secure/detect/registry.py's own scope note). Validation
    here means "does Secure's own EVE parser correctly recognize an
    alert-shaped record, and correctly skip a non-alert record" —
    Secure's OWN ingestion correctness, never Suricata's own detection
    quality.
  - Secure's two correlation engines: real, meaningful fixtures, since
    Secure owns this logic completely — a single-module signal set (or
    an evidence-links-free isolated node) that should never reach
    cross-module significance, and a genuine cross-module signal set
    (or a real derived_evidence chain) that should. Chain-scoring's own
    fixture runs against a throwaway, temp-file SQLite database
    (schema-initialized, discarded immediately after) — never the
    operator's real database — since score_chain() needs real rows to
    query and this module must never write synthetic security findings
    into an operator's actual data.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from secure.config import AppConfig
from secure.correlate.analysis import cluster_signals, distinct_modules
from secure.correlate.strength import STRONG, WEAK
from secure.detect.registry import FAMILY_CORRELATE, FAMILY_SIGMA, FAMILY_SURICATA, FAMILY_YARAX
from secure.evidence.model import EvidenceLink, ObservationRef, RELATIONSHIP_DERIVED_EVIDENCE
from secure.evidence.record import record_link
from secure.explain.vocab import CONFIRMED, LIKELY
from secure.integrations.sigma.capability import check_capability
from secure.integrations.sigma.evaluator import evaluate_rule
from secure.integrations.sigma.rules import load_rules
from secure.integrations.suricata.parser import parse_alert_record
from secure.integrations.yarax.rulesets import load_rulesets
from secure.storage.database import Database
from secure.storage.models import (
    DetectionRuleRecord,
    add_detection_rule_test_run,
    set_detection_rule_validation,
    upsert_process_entry,
)
from secure.storage.models.integrations import IntegrationObservationRecord

FIRE = "fire"
NO_FIRE = "no_fire"
ERROR = "error"
NOT_EVALUABLE = "not_evaluable"

VALIDATION_PASSED = "passed"
VALIDATION_FAILED = "failed"
VALIDATION_UNVALIDATED = "unvalidated"

_CORRELATE_TEMPORAL = "temporal_clustering"
_CORRELATE_CHAIN = "chain_scoring"


@dataclass(frozen=True)
class FixtureOutcome:
    fixture_name: str
    expected: str
    actual: str
    passed: bool
    detail: str


# ---------- sigma ----------


def _strip_modifier(field_name: str) -> str:
    if "|" in field_name:
        return field_name.split("|", 1)[0]
    return field_name


def _fill_selection(selection, field_map: Dict[str, str], event: dict) -> None:
    if isinstance(selection, dict):
        for raw_field, value in selection.items():
            secure_field = field_map.get(_strip_modifier(raw_field))
            if secure_field is None:
                continue
            literal = value[0] if isinstance(value, list) and value else value
            event[secure_field] = literal
    elif isinstance(selection, list):
        for item in selection:
            _fill_selection(item, field_map, event)


def _synthesize_sigma_suspicious_event(rule, field_map: Dict[str, str]) -> dict:
    event: dict = {}
    for key, selection in rule.detection.items():
        if key == "condition":
            continue
        _fill_selection(selection, field_map, event)
    return event


def _fake_observation(obs_id: int, kind: str, identity_key: str, fields: dict) -> IntegrationObservationRecord:
    now = datetime.now(timezone.utc).isoformat()
    return IntegrationObservationRecord(
        id=obs_id,
        created_at=now,
        run_id="detect_validate",
        integration="osquery",
        kind=kind,
        identity_key=identity_key,
        fields_json=json.dumps(fields),
        source_query="secure/detect fixture",
        collected_at=now,
    )


def _outcome_from_evaluation(name: str, expected: str, evaluation) -> FixtureOutcome:
    if evaluation.error:
        return FixtureOutcome(name, expected, ERROR, False, evaluation.error)
    actual = FIRE if evaluation.matched else NO_FIRE
    return FixtureOutcome(
        name, expected, actual, actual == expected,
        f"observations_checked={evaluation.observations_checked}, matches={len(evaluation.matches)}",
    )


def _run_sigma_fixtures(cfg: AppConfig, record: DetectionRuleRecord) -> "List[FixtureOutcome]":
    rules, _ = load_rules(cfg.sigma_rules_dir_path())
    rule = next((r for r in rules if r.rule_id == record.rule_key), None)
    if rule is None:
        detail = "rule no longer found in the configured Sigma rules directory"
        return [
            FixtureOutcome("suspicious", FIRE, ERROR, False, detail),
            FixtureOutcome("benign", NO_FIRE, ERROR, False, detail),
        ]

    capability = check_capability(rule)
    if not capability.evaluable:
        detail = f"rule is NOT_EVALUABLE: {capability.reason}"
        return [
            FixtureOutcome("suspicious", FIRE, NOT_EVALUABLE, False, detail),
            FixtureOutcome("benign", NO_FIRE, NOT_EVALUABLE, False, detail),
        ]

    support = capability.category_support
    suspicious_fields = _synthesize_sigma_suspicious_event(rule, support.field_map)
    suspicious_obs = [_fake_observation(1, support.observation_kind, "fixture:suspicious", suspicious_fields)]
    benign_obs = [_fake_observation(2, support.observation_kind, "fixture:benign", {})]

    suspicious_eval = evaluate_rule(rule, support, suspicious_obs)
    benign_eval = evaluate_rule(rule, support, benign_obs)

    return [
        _outcome_from_evaluation("suspicious", FIRE, suspicious_eval),
        _outcome_from_evaluation("benign", NO_FIRE, benign_eval),
    ]


# ---------- yarax ----------


def _run_yarax_fixtures(cfg: AppConfig, record: DetectionRuleRecord) -> "List[FixtureOutcome]":
    compiled, load_errors = load_rulesets(cfg.yara_rules_dir_path())
    for err in load_errors:
        if err.info.name == record.rule_key:
            return [FixtureOutcome("compile", "compiles", "compile_error", False, err.detail)]
    for ruleset in compiled:
        if ruleset.info.name == record.rule_key:
            return [FixtureOutcome("compile", "compiles", "compiles", True, "ruleset compiled successfully")]
    return [
        FixtureOutcome(
            "compile", "compiles", "error", False,
            "ruleset file no longer found in the configured YARA-X rules directory",
        )
    ]


# ---------- suricata ----------


def _run_suricata_fixtures(record: DetectionRuleRecord) -> "List[FixtureOutcome]":
    gid, _, signature_id = record.rule_key.partition(":")
    now = datetime.now(timezone.utc).isoformat()

    suspicious_record = {
        "timestamp": now,
        "event_type": "alert",
        "flow_id": 1,
        "alert": {
            "signature": record.title,
            "signature_id": int(signature_id) if signature_id.isdigit() else signature_id,
            "gid": int(gid) if gid.isdigit() else gid,
            "rev": 1,
            "category": "secure detect fixture",
            "severity": 1,
        },
    }
    benign_record = {"timestamp": now, "event_type": "flow", "flow_id": 1}

    suspicious_obs = parse_alert_record(suspicious_record, collected_at=now, source_path="secure/detect fixture")
    benign_obs = parse_alert_record(benign_record, collected_at=now, source_path="secure/detect fixture")

    return [
        FixtureOutcome(
            "suspicious_alert_record", FIRE, FIRE if suspicious_obs is not None else NO_FIRE,
            suspicious_obs is not None,
            "Secure's own EVE parser correctly recognized an alert-shaped record"
            if suspicious_obs is not None
            else "Secure's own EVE parser failed to recognize a genuine alert record",
        ),
        FixtureOutcome(
            "benign_non_alert_record", NO_FIRE, NO_FIRE if benign_obs is None else FIRE,
            benign_obs is None,
            "Secure's own EVE parser correctly skipped a non-alert record"
            if benign_obs is None
            else "Secure's own EVE parser incorrectly treated a non-alert record as an alert",
        ),
    ]


# ---------- correlate: temporal clustering ----------


def _run_temporal_clustering_fixtures() -> "List[FixtureOutcome]":
    from secure.correlate.signals import Signal

    now = datetime.now(timezone.utc)

    benign_signals = [
        Signal(timestamp=now, module="inventory", kind="new_device", strength=WEAK,
               identifier="fixture-device", label=None, source_table="devices", source_id=1),
    ]
    benign_cross_module = [c for c in cluster_signals(benign_signals) if len(distinct_modules(c)) >= 2]

    suspicious_signals = [
        Signal(timestamp=now, module="process", kind="new_process", strength=STRONG,
               identifier="/tmp/fixture-suspicious", label="fixture-suspicious",
               source_table="process_entries", source_id=1),
        Signal(timestamp=now, module="connections", kind="new_remote_endpoint", strength=STRONG,
               identifier="203.0.113.5:443/tcp", label="fixture-suspicious",
               source_table="remote_endpoints", source_id=2),
    ]
    suspicious_cross_module = [c for c in cluster_signals(suspicious_signals) if len(distinct_modules(c)) >= 2]

    return [
        FixtureOutcome(
            "benign_single_module_signal", NO_FIRE,
            FIRE if benign_cross_module else NO_FIRE, not benign_cross_module,
            f"{len(benign_cross_module)} cross-module cluster(s) formed (a single-module signal set "
            "never becomes a correlation_alerts row — see secure/correlate/scanner.py's own filter)",
        ),
        FixtureOutcome(
            "suspicious_cross_module_signals", FIRE,
            FIRE if suspicious_cross_module else NO_FIRE, bool(suspicious_cross_module),
            f"{len(suspicious_cross_module)} cross-module cluster(s) formed",
        ),
    ]


# ---------- correlate: chain scoring ----------


def _run_chain_scoring_fixtures() -> "List[FixtureOutcome]":
    from secure.correlate.chains import score_chain

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "detect_chain_fixture.db"
        with Database(db_path) as db:
            conn = db.conn

            upsert_process_entry(conn, "/usr/bin/secure_detect_fixture_benign", "secure_detect_fixture_benign", "root", "signed")
            benign_row = conn.execute(
                "SELECT id FROM process_entries WHERE executable_path = ?",
                ("/usr/bin/secure_detect_fixture_benign",),
            ).fetchone()
            benign_score = score_chain(
                conn, ObservationRef(source_table="process_entries", source_id=benign_row["id"]),
                boot_time=None, boot_time_resolved=True,
            )

            upsert_process_entry(conn, "/usr/bin/secure_detect_fixture_suspicious", "secure_detect_fixture_suspicious", "root", "unsigned")
            proc_row = conn.execute(
                "SELECT id FROM process_entries WHERE executable_path = ?",
                ("/usr/bin/secure_detect_fixture_suspicious",),
            ).fetchone()
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO persistence_alerts (created_at, run_id, kind, severity, target_type, "
                "identifier, label, message, known) VALUES (?, 'detect_fixture', "
                "'unusual_unsigned_process', 'high', 'process', ?, 'fixture', 'fixture chain finding', 0)",
                (now, "/usr/bin/secure_detect_fixture_suspicious"),
            )
            conn.commit()
            alert_row = conn.execute(
                "SELECT id FROM persistence_alerts WHERE identifier = ?",
                ("/usr/bin/secure_detect_fixture_suspicious",),
            ).fetchone()
            record_link(
                conn,
                EvidenceLink(
                    from_ref=ObservationRef(source_table="process_entries", source_id=proc_row["id"]),
                    to_ref=ObservationRef(source_table="persistence_alerts", source_id=alert_row["id"]),
                    relationship=RELATIONSHIP_DERIVED_EVIDENCE,
                    match_basis="secure_detect_fixture",
                    detail="synthetic fixture link for secure/detect/validate.py's chain_scoring fixture",
                    created_by="detect_validate_fixture",
                ),
            )
            suspicious_score = score_chain(
                conn, ObservationRef(source_table="process_entries", source_id=proc_row["id"]),
                boot_time=None, boot_time_resolved=True,
            )

    benign_fired = benign_score.confidence in (LIKELY, CONFIRMED)
    suspicious_fired = suspicious_score.confidence in (LIKELY, CONFIRMED)

    return [
        FixtureOutcome(
            "benign_isolated_node", NO_FIRE, FIRE if benign_fired else NO_FIRE, not benign_fired,
            f"confidence={benign_score.confidence}, module_count={benign_score.module_count}",
        ),
        FixtureOutcome(
            "suspicious_cross_module_chain", FIRE, FIRE if suspicious_fired else NO_FIRE, suspicious_fired,
            f"confidence={suspicious_score.confidence}, module_count={suspicious_score.module_count}",
        ),
    ]


# ---------- orchestration ----------


def run_validation(conn: sqlite3.Connection, cfg: AppConfig, record: DetectionRuleRecord) -> "List[FixtureOutcome]":
    """Run this rule's own deterministic fixtures through its family's
    existing evaluator and return every outcome — does NOT persist
    anything. `conn` is accepted for a uniform signature across
    families even though only Suricata/correlate's static dispatch
    needs it structurally; sigma/yarax read straight from disk via cfg.
    """
    if record.family == FAMILY_SIGMA:
        return _run_sigma_fixtures(cfg, record)
    if record.family == FAMILY_YARAX:
        return _run_yarax_fixtures(cfg, record)
    if record.family == FAMILY_SURICATA:
        return _run_suricata_fixtures(record)
    if record.family == FAMILY_CORRELATE:
        if record.rule_key == _CORRELATE_TEMPORAL:
            return _run_temporal_clustering_fixtures()
        if record.rule_key == _CORRELATE_CHAIN:
            return _run_chain_scoring_fixtures()
    return [FixtureOutcome("unknown", "n/a", ERROR, False, f"no fixture defined for family={record.family!r} rule_key={record.rule_key!r}")]


def validate_and_record(
    conn: sqlite3.Connection, cfg: AppConfig, record: DetectionRuleRecord
) -> "tuple[DetectionRuleRecord, List[FixtureOutcome]]":
    """Run `record`'s fixtures, persist every outcome as an append-only
    detection_rule_test_runs row, and update the catalog's own
    validation_status/last_tested_at — "passed" only if EVERY fixture
    outcome passed, "failed" if any did not. Never silently skips a
    failure to report an overall pass.
    """
    outcomes = run_validation(conn, cfg, record)
    tested_at = datetime.now(timezone.utc).isoformat()

    for outcome in outcomes:
        add_detection_rule_test_run(
            conn,
            rule_id=record.id,
            tested_at=tested_at,
            fixture_name=outcome.fixture_name,
            expected=outcome.expected,
            actual=outcome.actual,
            passed=outcome.passed,
            detail=outcome.detail,
        )

    overall = VALIDATION_PASSED if outcomes and all(o.passed for o in outcomes) else VALIDATION_FAILED
    updated = set_detection_rule_validation(conn, record.id, validation_status=overall, last_tested_at=tested_at)
    assert updated is not None
    return updated, outcomes
