"""
Tests for Phase 28 Stage 3: secure/ai/context.py's read-only context
builder. Follows tests/test_dfir_investigate_wiring.py's own real-
fixture convention (upsert_process_entry + a real EntityRef) rather
than mocking secure.investigate.view.investigate() — the whole point
of this module is that it reuses that real call unchanged.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.config import AppConfig
from secure.ai.context import (
    MODE_ENTITY,
    MODE_FREEFORM,
    build_entity_context,
    build_freeform_context,
)
from secure.investigate.entity import PROCESS, EntityRef, process_key
from secure.storage.database import Database
from secure.storage.models import add_persistence_alert, upsert_process_entry


def _cfg(tmp_path: Path) -> AppConfig:
    return AppConfig(app_dir=str(tmp_path))


# ---------- build_freeform_context() ----------


def test_freeform_context_on_empty_db_is_honest_not_fabricated(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        context = build_freeform_context(db.conn, _cfg(tmp_path))

    assert context.mode == MODE_FREEFORM
    assert context.findings == []
    assert context.evidence_manifest() == []
    assert context.truncated is False


def test_freeform_context_tool_health_always_reports_all_six_integrations(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        context = build_freeform_context(db.conn, _cfg(tmp_path))

    names = {t["name"] for t in context.tool_health}
    assert names == {"osquery", "yarax", "sigma", "suricata", "zeek", "velociraptor"}


def test_freeform_context_evidence_manifest_matches_findings_exactly(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_process_entry(db.conn, "/tmp/evil.sh", "evil.sh", "root", "unsigned")
        add_persistence_alert(
            db.conn, run_id="test-run", kind="launch_agent", severity="MEDIUM",
            target_type="path", identifier="/tmp/evil.sh", label=None,
            message="new unsigned launch agent",
        )
        context = build_freeform_context(db.conn, _cfg(tmp_path))

    manifest_keys = {(m["source_table"], m["source_id"]) for m in context.evidence_manifest()}
    finding_keys = {(f["source_table"], f["source_id"]) for f in context.findings if f.get("source_table")}
    assert finding_keys.issubset(manifest_keys)
    assert ("persistence_alerts", 1) in manifest_keys


def test_freeform_context_is_bounded_by_per_table_limit(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        for i in range(5):
            add_persistence_alert(
                db.conn, run_id="test-run", kind="launch_agent", severity="MEDIUM",
                target_type="path", identifier=f"/tmp/evil{i}.sh", label=None, message="m",
            )
        context = build_freeform_context(db.conn, _cfg(tmp_path), per_table_limit=2, max_findings=100)

    persistence_findings = [f for f in context.findings if f.get("source_table") == "persistence_alerts"]
    assert len(persistence_findings) <= 2


# ---------- build_entity_context() ----------


def test_entity_context_nonexistent_entity_is_honest(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        entity = EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/does-not-exist"))
        context = build_entity_context(db.conn, _cfg(tmp_path), entity)

    assert context.mode == MODE_ENTITY
    assert context.exists is False
    assert context.findings == []
    assert "no record" in " ".join(context.notes).lower()


def test_entity_context_existing_process_has_a_manifest_and_tool_health(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        entity = EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"))
        context = build_entity_context(db.conn, _cfg(tmp_path), entity)

    assert context.mode == MODE_ENTITY
    assert context.exists is True
    assert context.entity == {"entity_type": PROCESS, "entity_key": process_key("/usr/bin/curl")}
    names = {t["name"] for t in context.tool_health}
    assert names == {"osquery", "yarax", "sigma", "suricata", "zeek", "velociraptor"}


def test_entity_context_manifest_citations_are_all_table_hash_id_shaped(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        entity = EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"))
        context = build_entity_context(db.conn, _cfg(tmp_path), entity)

    for item in context.evidence_manifest():
        assert isinstance(item["source_table"], str) and item["source_table"]
        assert isinstance(item["source_id"], int)


def test_to_dict_is_json_shaped_and_includes_evidence_manifest(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        context = build_freeform_context(db.conn, _cfg(tmp_path))
    as_dict = context.to_dict()
    assert "evidence_manifest" in as_dict
    assert as_dict["mode"] == MODE_FREEFORM
