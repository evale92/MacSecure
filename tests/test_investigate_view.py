"""
Tests for secure/investigate/view.py (Phase 23 Stage 5: the top-level
investigate() composition + explain_observation() progressive-
disclosure hook).

Same Database/tmp_path + record_link() fixture convention as the rest
of tests/test_investigate_*.py.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.evidence.model import RELATIONSHIP_DERIVED_EVIDENCE, EvidenceLink, ObservationRef
from secure.evidence.record import record_link
from secure.investigate.entity import PERSISTENCE, PROCESS, EntityRef, persistence_key, process_key
from secure.investigate.view import explain_observation, investigate
from secure.storage.database import Database
from secure.storage.models import upsert_persistence_entry, upsert_process_entry


def _link(conn, from_table, from_id, to_table, to_id, relationship, *, detail="test"):
    record_link(
        conn,
        EvidenceLink(
            from_ref=ObservationRef(source_table=from_table, source_id=from_id),
            to_ref=ObservationRef(source_table=to_table, source_id=to_id),
            relationship=relationship,
            match_basis="identity+timing",
            detail=detail,
            created_by="test",
        ),
    )


def _seed_persistence_alert(conn, *, severity="high") -> int:
    cursor = conn.execute(
        "INSERT INTO persistence_alerts (created_at, run_id, kind, severity, target_type, "
        "identifier, label, message, known) VALUES "
        "('2026-01-01T12:00:00+00:00', 'r', 'new_entry', ?, 'login_item', 'x', 'label', 'a persistence finding', 0)",
        (severity,),
    )
    conn.commit()
    return cursor.lastrowid


# ---------- investigate() ----------


def test_investigate_nonexistent_entity(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        view = investigate(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/no/such")))
        assert view.exists is False
        assert view.summary == {}
        assert view.anchors == []
        assert view.timeline is None
        assert view.related is None
        assert view.pivots == []


def test_investigate_existing_entity_populates_every_section(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        process_record, _ = upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        persistence_record, _, _ = upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/usr/bin/curl", "signed")
        _link(db.conn, "process_entries", process_record.id, "persistence_entries", persistence_record.id, RELATIONSHIP_DERIVED_EVIDENCE)

        view = investigate(db.conn, EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl")))
        assert view.exists is True
        assert view.summary["executable_path"] == "/usr/bin/curl"
        assert len(view.anchors) == 1

        assert view.timeline is not None
        assert view.timeline.exists is True
        assert {e.source_table for e in view.timeline.events} == {"process_entries", "persistence_entries"}

        assert view.related is not None
        assert view.related.exists is True
        assert [g.hops for g in view.related.groups] == [1]

        pivot_entities = {p.entity for p in view.pivots}
        assert EntityRef(entity_type=PERSISTENCE, entity_key=persistence_key("launch_agent", "/x.plist")) in pivot_entities


# ---------- explain_observation() ----------


def test_explain_observation_alert_shaped_table_returns_explanation(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        alert_id = _seed_persistence_alert(db.conn)
        exp = explain_observation(db.conn, ObservationRef(source_table="persistence_alerts", source_id=alert_id))
        assert exp is not None
        assert exp.severity in ("critical", "high", "medium", "low", "informational", "unknown")


def test_explain_observation_non_alert_table_returns_none(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        process_record, _ = upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        exp = explain_observation(db.conn, ObservationRef(source_table="process_entries", source_id=process_record.id))
        assert exp is None


def test_explain_observation_unrecognized_table_returns_none(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        exp = explain_observation(db.conn, ObservationRef(source_table="not_a_real_table", source_id=1))
        assert exp is None


def test_explain_observation_missing_row_returns_none(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        exp = explain_observation(db.conn, ObservationRef(source_table="persistence_alerts", source_id=999999))
        assert exp is None
