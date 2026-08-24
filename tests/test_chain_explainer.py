"""
Tests for secure/explain/chain_explainer.py (Phase 22 Stage 4).

Same two-track approach test_explain.py already established for
correlation_explainer.py: hand-built CorrelationChainAlertRecord
instances for fast, no-database coverage of the explainer's own
reshaping logic, plus one end-to-end test seeding a real temp database
through score_chain()/persist_chain_score() and dispatch.explain() —
proving a chain alert flows through the SAME shared Explanation path
(dispatch.py) every other source table already uses, not a special
case.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.correlate.chains import persist_chain_score, score_chain
from secure.evidence.model import RELATIONSHIP_DERIVED_EVIDENCE, RELATIONSHIP_SAME_EVENT_CONFIRMATION, EvidenceLink, ObservationRef
from secure.evidence.record import record_link
from secure.explain import vocab
from secure.explain.chain_explainer import explain_chain_alert
from secure.explain.dispatch import explain
from secure.storage.database import Database
from secure.storage.models.correlate_chains import CorrelationChainAlertRecord


def _member(source_table="connection_events", source_id=1, module="connections", source="connections", group_id=0):
    return {
        "source_table": source_table, "source_id": source_id, "timestamp": "2026-08-19T00:00:00",
        "module": module, "source": source, "weight": 1, "group_id": group_id,
    }


def _record(
    members,
    edges=None,
    severity="low",
    confidence=vocab.UNCERTAIN,
    independent_fact_count=1,
    module_count=1,
    meaningful_relationship_count=0,
    concentration=1.0,
    uncertainty_notes=None,
    explanation="explanation text",
):
    return CorrelationChainAlertRecord(
        id=1, created_at="2026-08-19T00:00:00", run_id="run1", fingerprint="fp1",
        start_source_table="connection_events", start_source_id=1,
        raw_observation_count=len(members), independent_fact_count=independent_fact_count,
        module_count=module_count, source_count=module_count,
        meaningful_relationship_count=meaningful_relationship_count, concentration=concentration,
        raw_score=3, score=3, severity=severity, confidence=confidence,
        uncertainty_notes=uncertainty_notes if uncertainty_notes is not None else ["A chain of linked evidence is not proof."],
        benign_context_notes=None, explanation=explanation,
        members=members, edges=edges if edges is not None else [], known=False,
    )


# ---------- pure explainer behavior ----------


def test_severity_always_passthrough_never_recomputed():
    for severity in ("informational", "low", "medium", "high", "critical"):
        record = _record([_member()], severity=severity)
        exp = explain_chain_alert(record)
        assert exp.severity == severity


def test_confidence_always_passthrough_never_recomputed():
    for confidence in (vocab.CONFIRMED, vocab.LIKELY, vocab.UNCERTAIN, vocab.INSUFFICIENT_EVIDENCE):
        record = _record([_member()], confidence=confidence)
        exp = explain_chain_alert(record)
        assert exp.confidence == confidence


def test_empty_members_falls_back_to_generic_explanation():
    record = _record([], severity="medium", explanation="no members")
    exp = explain_chain_alert(record)
    assert exp.degraded is False  # documented gap (no members), not a failure
    assert exp.severity == "medium"
    assert exp.confidence == vocab.INSUFFICIENT_EVIDENCE


def test_high_meaningful_relationship_count_drives_investigate_now():
    members = [_member(source_table="connection_events", source_id=1, module="connections", group_id=0),
               _member(source_table="persistence_alerts", source_id=2, module="persistence", group_id=1)]
    record = _record(
        members, severity="high", confidence=vocab.LIKELY,
        independent_fact_count=2, module_count=2, meaningful_relationship_count=1,
        concentration=0.5,
    )
    exp = explain_chain_alert(record)
    assert exp.recommended_action == vocab.INVESTIGATE_NOW


def test_low_severity_or_low_confidence_drives_classify_not_investigate():
    record = _record([_member()], severity="low", confidence=vocab.UNCERTAIN)
    exp = explain_chain_alert(record)
    assert exp.recommended_action == vocab.CLASSIFY


def test_concentrated_chain_gets_a_concentration_evidence_note():
    members = [_member(source_table="connection_events", source_id=1, module="connections", group_id=0),
               _member(source_table="connection_events", source_id=2, module="connections", group_id=1)]
    record = _record(
        members, module_count=2, independent_fact_count=2, concentration=0.75,
    )
    exp = explain_chain_alert(record)
    assert any("concentration" in item.text.lower() for item in exp.evidence)


def test_correlated_events_include_every_member():
    members = [_member(source_id=1), _member(source_id=2), _member(source_id=3)]
    record = _record(members, independent_fact_count=3, module_count=1)
    exp = explain_chain_alert(record)
    assert len(exp.correlated_events) == 3


def test_uncertainty_notes_carried_through_verbatim():
    notes = ["Custom note A.", "Custom note B."]
    record = _record([_member()], uncertainty_notes=notes)
    exp = explain_chain_alert(record)
    assert exp.uncertainty == tuple(notes)
    assert exp.uncertainty_status == vocab.UNCERTAINTY_KNOWN


# ---------- dispatch.py wiring ----------


def test_dispatch_routes_correlation_chain_alerts_table():
    record = _record([_member()], severity="critical")
    exp = explain(record, "correlation_chain_alerts")
    assert exp.severity == "critical"
    assert exp.degraded is False


def test_dispatch_degrades_gracefully_on_broken_record():
    # A record missing the fields explain_chain_alert() actually needs
    # (e.g. .members) must never crash the Alerts table — dispatch.py's
    # own try/except must catch the AttributeError and degrade cleanly,
    # same guarantee every other source table already gets.
    class _MissingFields:
        severity = "high"
        message = "raw message"

    exp = explain(_MissingFields(), "correlation_chain_alerts")
    assert exp.degraded is True
    assert exp.severity == "high"


# ---------- end-to-end against a real seeded database ----------


def _seed_connection_event(conn, *, created_at="2026-01-01T12:00:00+00:00") -> int:
    cursor = conn.execute(
        "INSERT INTO connection_events (created_at, run_id, proto, local_addr, local_port, "
        "remote_addr, remote_port, state, pid, process_name) VALUES (?, 'r', 'tcp', '10.0.0.1', "
        "51000, '203.0.113.5', 443, 'ESTABLISHED', 100, 'curl')",
        (created_at,),
    )
    conn.commit()
    return cursor.lastrowid


def _seed_integration_observation(conn, *, collected_at="2026-01-01T12:00:05+00:00") -> int:
    cursor = conn.execute(
        "INSERT INTO integration_observations (created_at, run_id, integration, kind, identity_key, "
        "fields_json, source_query, collected_at) VALUES (?, 'r', 'zeek', 'conn', 'k', '{}', 'q', ?)",
        (collected_at, collected_at),
    )
    conn.commit()
    return cursor.lastrowid


def test_explain_chain_alert_end_to_end_against_seeded_db(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn)
        obs_id = _seed_integration_observation(db.conn)
        record_link(
            db.conn,
            EvidenceLink(
                from_ref=ObservationRef(source_table="integration_observations", source_id=obs_id),
                to_ref=ObservationRef(source_table="connection_events", source_id=conn_id),
                relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION,
                match_basis="identity+timing", detail="test", created_by="test",
            ),
        )
        score = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        record, _ = persist_chain_score(db.conn, "run-1", score)

        exp = explain(record, "correlation_chain_alerts")
        assert exp.severity == record.severity
        assert exp.confidence == record.confidence
        assert len(exp.correlated_events) == record.raw_observation_count
        assert exp.degraded is False
