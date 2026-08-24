"""
Tests for secure/dfir/collector.py (Phase 24 Stage 5: the single
orchestration entrypoint — allowlist enforcement, and persisting a
collection's outcome + normalized evidence rows in one call).

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

import secure.dfir.collector as collector_module
from secure.config import AppConfig
from secure.dfir.collector import ArtifactNotAllowedError, CollectionRequest, collect_evidence
from secure.dfir.velociraptor.collect import CollectionOutcome
from secure.integrations.base import STATUS_OK, STATUS_UNAVAILABLE
from secure.investigate.entity import PROCESS, EntityRef, process_key
from secure.storage.database import Database
from secure.storage.models import list_forensic_evidence_items_for_collection


def _cfg(tmp_path: Path, allowlist=None) -> AppConfig:
    return AppConfig(app_dir=str(tmp_path), dfir_artifact_allowlist=allowlist or [])


def _entity() -> "EntityRef":
    return EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"))


def test_collect_evidence_rejects_artifact_outside_allowlist(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        cfg = _cfg(tmp_path, allowlist=["MacOS.System.Pslist"])
        request = CollectionRequest(
            artifact_name="Windows.System.Powershell", parameters={}, reason="curious",
            entity=_entity(),
        )
        try:
            collect_evidence(db.conn, cfg, request)
            assert False, "expected ArtifactNotAllowedError"
        except ArtifactNotAllowedError:
            pass


def test_collect_evidence_rejected_artifact_writes_no_row(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        cfg = _cfg(tmp_path, allowlist=[])
        request = CollectionRequest(artifact_name="Anything", parameters={}, reason="r", entity=_entity())
        try:
            collect_evidence(db.conn, cfg, request)
        except ArtifactNotAllowedError:
            pass
        count = db.conn.execute("SELECT COUNT(*) AS c FROM forensic_collections").fetchone()["c"]
        assert count == 0


def test_collect_evidence_allowed_artifact_persists_result_and_evidence_items(tmp_path: Path, monkeypatch):
    def fake_run_collection(cfg, artifact_name, parameters=None, **kwargs):
        return CollectionOutcome(
            status=STATUS_OK,
            detail="Collected 2 row(s).",
            tool_version="0.7.1",
            started_at="2026-01-01T12:00:00+00:00",
            completed_at="2026-01-01T12:00:05+00:00",
            rows=[{"pid": 1, "name": "launchd"}, {"pid": 2, "name": "curl"}],
        )

    monkeypatch.setattr(collector_module, "run_collection", fake_run_collection)

    with Database(tmp_path / "test.db") as db:
        cfg = _cfg(tmp_path, allowlist=["MacOS.System.Pslist"])
        request = CollectionRequest(
            artifact_name="MacOS.System.Pslist", parameters={"pid": "2"}, reason="checking curl's process tree",
            entity=_entity(), source_table="persistence_alerts", source_id=7,
        )
        record = collect_evidence(db.conn, cfg, request)

        assert record.status == STATUS_OK
        assert record.artifact_name == "MacOS.System.Pslist"
        assert record.parameters == {"pid": "2"}
        assert record.reason == "checking curl's process tree"
        assert record.entity_type == PROCESS
        assert record.entity_key == process_key("/usr/bin/curl")
        assert record.source_table == "persistence_alerts"
        assert record.source_id == 7
        assert record.tool_version == "0.7.1"
        assert record.evidence_item_count == 2

        items = list_forensic_evidence_items_for_collection(db.conn, record.id)
        assert len(items) == 2
        assert items[0].fields == {"pid": 1, "name": "launchd"}
        assert items[0].kind == "MacOS.System.Pslist"


def test_collect_evidence_failed_collection_still_persists_a_row_with_zero_evidence(tmp_path: Path, monkeypatch):
    # The whole point of "treat failure as unavailable, not exculpatory
    # evidence": a failed attempt is still recorded, honestly, with no
    # fabricated evidence rows attached to it.
    def fake_run_collection(cfg, artifact_name, parameters=None, **kwargs):
        return CollectionOutcome(
            status=STATUS_UNAVAILABLE,
            detail="velociraptor binary not found.",
            tool_version=None,
            started_at=None,
            completed_at=None,
            rows=[],
        )

    monkeypatch.setattr(collector_module, "run_collection", fake_run_collection)

    with Database(tmp_path / "test.db") as db:
        cfg = _cfg(tmp_path, allowlist=["MacOS.System.Pslist"])
        request = CollectionRequest(
            artifact_name="MacOS.System.Pslist", parameters={}, reason="r", entity=_entity(),
        )
        record = collect_evidence(db.conn, cfg, request)
        assert record.status == STATUS_UNAVAILABLE
        assert record.evidence_item_count == 0
        assert list_forensic_evidence_items_for_collection(db.conn, record.id) == []


def test_collect_evidence_two_separate_requests_never_merge(tmp_path: Path, monkeypatch):
    def fake_run_collection(cfg, artifact_name, parameters=None, **kwargs):
        return CollectionOutcome(
            status=STATUS_OK, detail="d", tool_version="0.7.1",
            started_at="2026-01-01T12:00:00+00:00", completed_at="2026-01-01T12:00:01+00:00",
            rows=[{"pid": 1}],
        )

    monkeypatch.setattr(collector_module, "run_collection", fake_run_collection)

    with Database(tmp_path / "test.db") as db:
        cfg = _cfg(tmp_path, allowlist=["MacOS.System.Pslist"])
        request = CollectionRequest(artifact_name="MacOS.System.Pslist", parameters={}, reason="r", entity=_entity())
        first = collect_evidence(db.conn, cfg, request)
        second = collect_evidence(db.conn, cfg, request)
        assert first.id != second.id
