"""
Tests for secure/detect/firing_history.py (Phase 25 Stage 4: "what
evidence caused it to fire," per cataloged rule).

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from secure.correlate.chains import persist_chain_score, score_chain
from secure.detect import firing_history as fh_module
from secure.detect.registry import FAMILY_CORRELATE, FAMILY_SIGMA, FAMILY_SURICATA, FAMILY_YARAX
from secure.evidence.model import EvidenceLink, ObservationRef, RELATIONSHIP_DERIVED_EVIDENCE
from secure.evidence.record import record_link
from secure.storage.database import Database
from secure.storage.models import (
    DetectionRuleRecord,
    add_correlation_alert,
    add_integration_alert,
    upsert_process_entry,
)

NOW = datetime.now(timezone.utc).isoformat()


def _record(**overrides) -> DetectionRuleRecord:
    base = dict(
        id=1, family="sigma", rule_key="x", title="t", source="s", version_label="v",
        enabled=True, required_telemetry="t", capability_status="evaluable", capability_reason="r",
        validation_status="unvalidated", last_tested_at=None, false_positive_notes="",
        first_seen_at=NOW, updated_at=NOW,
    )
    base.update(overrides)
    return DetectionRuleRecord(**base)


# ---------- sigma / yarax / suricata (integration_alerts) ----------


def test_no_firings_returns_empty_list(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record = _record(family=FAMILY_SIGMA, rule_key="never-fired")
        assert fh_module.firing_history(db.conn, record) == []


def test_sigma_matches_by_exact_identity_key(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_integration_alert(
            db.conn, run_id="r1", integration="sigma", kind="process_creation",
            discrepancy="match", severity="high", identity_key="rule-a", label="Rule A",
            message="matched",
        )
        add_integration_alert(
            db.conn, run_id="r1", integration="sigma", kind="process_creation",
            discrepancy="match", severity="low", identity_key="rule-b", label="Rule B",
            message="matched",
        )
        record = _record(family=FAMILY_SIGMA, rule_key="rule-a")
        events = fh_module.firing_history(db.conn, record)
        assert len(events) == 1
        assert events[0].source_table == "integration_alerts"
        assert events[0].label == "Rule A"
        assert events[0].explanation is not None
        assert events[0].explanation.severity == "high"


def test_yarax_matches_by_ruleset_segment_of_identity_key(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_integration_alert(
            db.conn, run_id="r1", integration="yarax", kind="yara_match",
            discrepancy="match", severity="high", identity_key="abcd1234:my_ruleset:default.rule_one",
            label="rule_one", message="matched",
        )
        add_integration_alert(
            db.conn, run_id="r1", integration="yarax", kind="yara_match",
            discrepancy="match", severity="high", identity_key="ef567890:other_ruleset:default.rule_two",
            label="rule_two", message="matched",
        )
        record = _record(family=FAMILY_YARAX, rule_key="my_ruleset")
        events = fh_module.firing_history(db.conn, record)
        assert len(events) == 1
        assert events[0].label == "rule_one"


def test_suricata_matches_by_gid_and_signature_id(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_integration_alert(
            db.conn, run_id="r1", integration="suricata", kind="network_alert",
            discrepancy="match", severity="high", identity_key="flow1:1:2000123:1:2026-01-01T00:00:00",
            label="ET TROJAN Test", message="matched",
        )
        add_integration_alert(
            db.conn, run_id="r1", integration="suricata", kind="network_alert",
            discrepancy="match", severity="low", identity_key="flow2:1:9999999:1:2026-01-01T00:00:00",
            label="Other Signature", message="matched",
        )
        record = _record(family=FAMILY_SURICATA, rule_key="1:2000123")
        events = fh_module.firing_history(db.conn, record)
        assert len(events) == 1
        assert events[0].label == "ET TROJAN Test"


def test_results_are_capped_at_limit(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        for _ in range(5):
            add_integration_alert(
                db.conn, run_id="r1", integration="sigma", kind="process_creation",
                discrepancy="match", severity="high", identity_key="rule-a", label="Rule A",
                message="matched",
            )
        record = _record(family=FAMILY_SIGMA, rule_key="rule-a")
        events = fh_module.firing_history(db.conn, record, limit=2)
        assert len(events) == 2


# ---------- correlate ----------


def test_temporal_clustering_returns_all_correlation_alerts(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_correlation_alert(
            db.conn, "run1", "fp1", 60.0, "2026-01-01T00:00:00", "2026-01-01T00:01:00",
            2, 2, 10, "medium", "manual", None, "a cross-module cluster",
            [
                {"module": "process", "kind": "new_process", "strength": "strong", "identifier": "p1", "label": None, "source_table": "process_entries", "source_id": 1, "timestamp": "2026-01-01T00:00:00"},
                {"module": "connections", "kind": "new_remote_endpoint", "strength": "weak", "identifier": "c1", "label": None, "source_table": "remote_endpoints", "source_id": 2, "timestamp": "2026-01-01T00:00:01"},
            ],
        )
        record = _record(family=FAMILY_CORRELATE, rule_key="temporal_clustering")
        events = fh_module.firing_history(db.conn, record)
        assert len(events) == 1
        assert events[0].source_table == "correlation_alerts"
        assert events[0].explanation is not None


def test_chain_scoring_returns_all_correlation_chain_alerts(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn = db.conn
        upsert_process_entry(conn, "/usr/bin/fixture_proc", "fixture_proc", "root", "unsigned")
        proc_row = conn.execute(
            "SELECT id FROM process_entries WHERE executable_path = ?", ("/usr/bin/fixture_proc",)
        ).fetchone()
        conn.execute(
            "INSERT INTO persistence_alerts (created_at, run_id, kind, severity, target_type, "
            "identifier, label, message, known) VALUES (?, 'r1', 'unusual_unsigned_process', 'high', "
            "'process', ?, 'fixture', 'fixture', 0)",
            (NOW, "/usr/bin/fixture_proc"),
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
        score = score_chain(
            conn, ObservationRef(source_table="process_entries", source_id=proc_row["id"]),
            boot_time=None, boot_time_resolved=True,
        )
        persist_chain_score(conn, "r1", score)

        record = _record(family=FAMILY_CORRELATE, rule_key="chain_scoring")
        events = fh_module.firing_history(conn, record)
        assert len(events) == 1
        assert events[0].source_table == "correlation_chain_alerts"
        assert events[0].explanation is not None


def test_unknown_correlate_rule_key_returns_empty(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record = _record(family=FAMILY_CORRELATE, rule_key="nonexistent_engine")
        assert fh_module.firing_history(db.conn, record) == []
