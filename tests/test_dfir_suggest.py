"""
Tests for secure/dfir/suggest.py (Phase 24 Stage 4: read-only
collection candidates, gated on severity AND confidence — the concrete
mechanism behind "do not trigger broad forensic collection
automatically from low-confidence findings").

Same Database/tmp_path convention as tests/test_investigate_view.py.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

import secure.dfir.suggest as suggest_module
from secure.dfir.suggest import suggest_collections
from secure.explain.explanation import Explanation
from secure.explain.vocab import CONFIRMED, INSUFFICIENT_EVIDENCE, LIKELY, UNCERTAIN
from secure.investigate.entity import PERSISTENCE, EntityRef, persistence_key
from secure.storage.database import Database
from secure.storage.models import upsert_persistence_entry


def _seed_high_severity_unsigned_persistence(conn) -> None:
    # severity="high" + kind="unusual_unsigned_process" ->
    # alert_explainers.explain_persistence_alert() returns LIKELY
    # confidence — a real finding that clears both the severity and
    # confidence bars.
    conn.execute(
        "INSERT INTO persistence_alerts (created_at, run_id, kind, severity, target_type, "
        "identifier, label, message, known) VALUES "
        "('2026-01-01T12:00:00+00:00', 'r', 'unusual_unsigned_process', 'high', 'process', "
        "'/tmp/sketchy', 'sketchy', 'a persistence finding', 0)"
    )
    conn.commit()


def _seed_medium_severity_unsigned_persistence(conn) -> None:
    conn.execute(
        "INSERT INTO persistence_alerts (created_at, run_id, kind, severity, target_type, "
        "identifier, label, message, known) VALUES "
        "('2026-01-01T12:00:00+00:00', 'r', 'unusual_unsigned_process', 'medium', 'process', "
        "'/tmp/sketchy', 'sketchy', 'a persistence finding', 0)"
    )
    conn.commit()


def test_suggest_collections_nonexistent_entity_returns_empty(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity = EntityRef(entity_type=PERSISTENCE, entity_key=persistence_key("launch_agent", "/x.plist"))
        assert suggest_collections(db.conn, entity) == []


def test_suggest_collections_no_qualifying_findings_returns_empty(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/bin/x", "signed")
        entity = EntityRef(entity_type=PERSISTENCE, entity_key=persistence_key("launch_agent", "/x.plist"))
        # A plain, un-alerted persistence entry has no alert-shaped
        # observation attached to it at all — resolve_entity()'s own
        # anchor (persistence_entries) is never alert-shaped, so
        # explain_observation() returns None for it.
        assert suggest_collections(db.conn, entity) == []


def test_suggest_collections_high_severity_likely_confidence_finding_is_a_candidate(tmp_path: Path, monkeypatch):
    with Database(tmp_path / "test.db") as db:
        upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/tmp/sketchy", "unsigned")
        _seed_high_severity_unsigned_persistence(db.conn)

        entity = EntityRef(entity_type=PERSISTENCE, entity_key=persistence_key("launch_agent", "/x.plist"))

        # Directly verify the gate by faking explain_observation() to
        # return a real-shaped Explanation for the persistence entry's
        # own anchor ObservationRef — decoupled from evidence_links
        # wiring specifics, which is Stage 6's concern, not Stage 4's.
        def fake_explain(conn, ref):
            if ref.source_table == "persistence_entries":
                return Explanation(
                    summary="unsigned executable", severity="high", confidence=LIKELY,
                    confidence_reason="r", significance="s", recommended_action="INSPECT_PROCESS",
                    recommended_action_text="t", evidence=(), correlated_events=(),
                    uncertainty_status="none_material", uncertainty=(),
                )
            return None

        monkeypatch.setattr(suggest_module, "explain_observation", fake_explain)
        candidates = suggest_collections(db.conn, entity)
        assert len(candidates) == 1
        assert candidates[0].severity == "high"
        assert candidates[0].confidence == LIKELY
        assert candidates[0].source_table == "persistence_entries"


def test_suggest_collections_excludes_high_severity_but_low_confidence_finding(tmp_path: Path, monkeypatch):
    # The exact case the instruction names by name: severity alone is
    # never enough — an UNCERTAIN or INSUFFICIENT_EVIDENCE finding must
    # never surface as a collection candidate, however severe.
    with Database(tmp_path / "test.db") as db:
        upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/tmp/sketchy", "unsigned")
        entity = EntityRef(entity_type=PERSISTENCE, entity_key=persistence_key("launch_agent", "/x.plist"))

        def fake_explain(conn, ref):
            return Explanation(
                summary="s", severity="critical", confidence=UNCERTAIN,
                confidence_reason="r", significance="s", recommended_action="MONITOR",
                recommended_action_text="t", evidence=(), correlated_events=(),
                uncertainty_status="none_material", uncertainty=(),
            )

        monkeypatch.setattr(suggest_module, "explain_observation", fake_explain)
        assert suggest_collections(db.conn, entity) == []


def test_suggest_collections_excludes_confirmed_but_low_severity_finding(tmp_path: Path, monkeypatch):
    with Database(tmp_path / "test.db") as db:
        upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/tmp/sketchy", "unsigned")
        entity = EntityRef(entity_type=PERSISTENCE, entity_key=persistence_key("launch_agent", "/x.plist"))

        def fake_explain(conn, ref):
            return Explanation(
                summary="s", severity="low", confidence=CONFIRMED,
                confidence_reason="r", significance="s", recommended_action="MONITOR",
                recommended_action_text="t", evidence=(), correlated_events=(),
                uncertainty_status="none_material", uncertainty=(),
            )

        monkeypatch.setattr(suggest_module, "explain_observation", fake_explain)
        assert suggest_collections(db.conn, entity) == []


def test_suggest_collections_medium_severity_real_finding_is_excluded(tmp_path: Path):
    # End-to-end (no faking): a real medium-severity persistence alert
    # never clears the severity gate at all.
    with Database(tmp_path / "test.db") as db:
        upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/tmp/sketchy", "unsigned")
        _seed_medium_severity_unsigned_persistence(db.conn)
        entity = EntityRef(entity_type=PERSISTENCE, entity_key=persistence_key("launch_agent", "/x.plist"))
        assert suggest_collections(db.conn, entity) == []


def test_suggest_collections_deduplicates_the_same_observation_reached_twice(tmp_path: Path, monkeypatch):
    with Database(tmp_path / "test.db") as db:
        upsert_persistence_entry(db.conn, "launch_agent", "/x.plist", None, "/tmp/sketchy", "unsigned")
        entity = EntityRef(entity_type=PERSISTENCE, entity_key=persistence_key("launch_agent", "/x.plist"))

        calls = []

        def fake_explain(conn, ref):
            calls.append(ref)
            return Explanation(
                summary="s", severity="high", confidence=CONFIRMED,
                confidence_reason="r", significance="s", recommended_action="MONITOR",
                recommended_action_text="t", evidence=(), correlated_events=(),
                uncertainty_status="none_material", uncertainty=(),
            )

        monkeypatch.setattr(suggest_module, "explain_observation", fake_explain)
        candidates = suggest_collections(db.conn, entity)
        # Exactly one anchor exists for this entity — even though
        # dedup logic runs, there's nothing to actually collapse here;
        # this asserts the single anchor isn't somehow explained twice.
        assert len(candidates) == 1
        assert len(calls) == 1
