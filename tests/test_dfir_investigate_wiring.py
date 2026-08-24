"""
Tests for Phase 24 Stage 6: wiring forensic_collections/
forensic_evidence_items into secure/investigate/resolve.py's reverse
resolution, and secure/dfir/collector.py's evidence_links wiring that
makes a collection surface in its entity's own investigation timeline
— the pipeline's own final step, "normalized forensic evidence ->
Secure investigation."

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.config import AppConfig
from secure.dfir.collector import CollectionRequest, collect_evidence
from secure.dfir.velociraptor.collect import CollectionOutcome
from secure.evidence.model import ObservationRef
from secure.integrations.base import STATUS_OK, STATUS_UNAVAILABLE
from secure.investigate.entity import PROCESS, EntityRef, process_key
from secure.investigate.resolve import resolve_observation
from secure.investigate.view import investigate
from secure.storage.database import Database
from secure.storage.models import (
    add_forensic_collection,
    add_forensic_evidence_item,
    upsert_process_entry,
)


def _cfg(tmp_path: Path) -> AppConfig:
    return AppConfig(app_dir=str(tmp_path), dfir_artifact_allowlist=["MacOS.System.Pslist"])


# ---------- resolve.py reverse resolution ----------


def test_resolve_observation_forensic_collections_reads_stored_entity_columns(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        collection_id = add_forensic_collection(
            db.conn, requested_at="2026-01-01T12:00:00+00:00", started_at=None, completed_at=None,
            artifact_name="MacOS.System.Pslist", parameters={}, reason="r",
            entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"),
            source_table=None, source_id=None, status=STATUS_OK, detail="d", tool_version=None,
        )
        refs = resolve_observation(db.conn, ObservationRef(source_table="forensic_collections", source_id=collection_id))
        assert refs == [EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"))]


def test_resolve_observation_forensic_evidence_items_joins_to_owning_collection(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        collection_id = add_forensic_collection(
            db.conn, requested_at="2026-01-01T12:00:00+00:00", started_at=None, completed_at=None,
            artifact_name="MacOS.System.Pslist", parameters={}, reason="r",
            entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"),
            source_table=None, source_id=None, status=STATUS_OK, detail="d", tool_version=None,
        )
        item_id = add_forensic_evidence_item(
            db.conn, collection_id=collection_id, kind="MacOS.System.Pslist",
            raw_row_index=0, fields={"pid": 1}, collected_at="2026-01-01T12:00:05+00:00",
        )
        refs = resolve_observation(db.conn, ObservationRef(source_table="forensic_evidence_items", source_id=item_id))
        assert refs == [EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"))]


def test_resolve_observation_forensic_evidence_items_missing_row_returns_empty(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert resolve_observation(db.conn, ObservationRef(source_table="forensic_evidence_items", source_id=999)) == []


def test_resolve_observation_forensic_collections_missing_row_returns_empty(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert resolve_observation(db.conn, ObservationRef(source_table="forensic_collections", source_id=999)) == []


# ---------- end-to-end: collect_evidence() -> investigate() ----------


def test_collection_surfaces_in_its_entitys_own_investigation_timeline(tmp_path: Path, monkeypatch):
    import secure.dfir.collector as collector_module

    def fake_run_collection(cfg, artifact_name, parameters=None, **kwargs):
        return CollectionOutcome(
            status=STATUS_OK, detail="d", tool_version="0.7.1",
            started_at="2026-01-01T12:00:10+00:00", completed_at="2026-01-01T12:00:15+00:00",
            rows=[{"pid": 1, "name": "curl"}],
        )

    monkeypatch.setattr(collector_module, "run_collection", fake_run_collection)

    with Database(tmp_path / "test.db") as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        entity = EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"))
        request = CollectionRequest(artifact_name="MacOS.System.Pslist", parameters={}, reason="r", entity=entity)

        record = collect_evidence(db.conn, _cfg(tmp_path), request)

        view = investigate(db.conn, entity)
        tables = {e.source_table for e in view.timeline.events}
        assert "forensic_collections" in tables
        assert view.timeline.exists is True

        # the collection's OWN anchor must not itself be marked as an
        # entity anchor (that's still process_entries only) — it's
        # related evidence, one hop away.
        collection_events = [e for e in view.timeline.events if e.source_table == "forensic_collections"]
        assert len(collection_events) == 1
        assert collection_events[0].is_anchor is False
        assert collection_events[0].source_id == record.id


def test_failed_collection_still_surfaces_honestly_in_timeline(tmp_path: Path, monkeypatch):
    # Even an UNAVAILABLE collection gets linked in — an analyst
    # investigating this entity should see that a collection was
    # attempted and failed, not have it silently vanish.
    import secure.dfir.collector as collector_module

    def fake_run_collection(cfg, artifact_name, parameters=None, **kwargs):
        return CollectionOutcome(
            status=STATUS_UNAVAILABLE, detail="velociraptor not found", tool_version=None,
            started_at=None, completed_at=None, rows=[],
        )

    monkeypatch.setattr(collector_module, "run_collection", fake_run_collection)

    with Database(tmp_path / "test.db") as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        entity = EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"))
        request = CollectionRequest(artifact_name="MacOS.System.Pslist", parameters={}, reason="r", entity=entity)
        collect_evidence(db.conn, _cfg(tmp_path), request)

        view = investigate(db.conn, entity)
        tables = {e.source_table for e in view.timeline.events}
        assert "forensic_collections" in tables
