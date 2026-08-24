"""
Phase 24 Stage 7: consolidated adversarial tests for secure/dfir/,
directly against the governing instruction's own four requirements:

  1. Do not trigger broad forensic collection automatically from
     low-confidence findings (secure/dfir/suggest.py's severity+
     confidence gate is unit-tested in tests/test_dfir_suggest.py —
     this file adds a static, whole-repo guard that NOTHING besides
     the one explicit `secure dfir collect` CLI command can ever reach
     `collect_evidence()` in the first place).
  2. Preserve artifact name, collection parameters, timestamps, tool
     version, and provenance — end to end, in one assertion.
  3. Treat forensic collection failure as unavailable, not exculpatory
     evidence.
  4. Allowlist enforcement rejects unlisted artifacts, leaving no
     trace of the refused request.

Run with:  pytest
"""

from __future__ import annotations

import ast
from pathlib import Path

import secure.dfir.collector as collector_module
from secure.config import AppConfig
from secure.dfir.collector import ArtifactNotAllowedError, CollectionRequest, collect_evidence
from secure.dfir.velociraptor.collect import CollectionOutcome
from secure.integrations.base import STATUS_ERROR, STATUS_OK, STATUS_UNAVAILABLE
from secure.investigate.entity import PROCESS, EntityRef, process_key
from secure.storage.database import Database

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SECURE_ROOT = _REPO_ROOT / "secure"


def _cfg(tmp_path: Path, allowlist=None) -> AppConfig:
    return AppConfig(app_dir=str(tmp_path), dfir_artifact_allowlist=allowlist or [])


def _entity() -> EntityRef:
    return EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"))


# ---------- 1. never auto-triggered ----------


def _imports_collect_evidence(py_file: Path) -> bool:
    tree = ast.parse(py_file.read_text(), filename=str(py_file))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and "secure.dfir" in node.module:
            if any(alias.name == "collect_evidence" for alias in node.names):
                return True
    return False


def test_collect_evidence_is_imported_nowhere_except_its_own_cli_command():
    # Rule 1 of secure/dfir/__init__.py, enforced statically: the ONLY
    # place outside secure/dfir/ itself allowed to import
    # collect_evidence is secure/cli/dfir.py's own `collect` command.
    # No scan, no `run-all`, no correlation pass, no scheduled job may
    # ever import it — if one starts to, this test breaks on purpose.
    importers = []
    for py_file in _SECURE_ROOT.rglob("*.py"):
        if py_file.resolve() == (_SECURE_ROOT / "dfir" / "collector.py").resolve():
            continue  # the definition itself
        if _imports_collect_evidence(py_file):
            importers.append(py_file.relative_to(_REPO_ROOT))

    assert importers == [Path("secure/cli/dfir.py")], (
        f"collect_evidence() must only be reachable from secure/cli/dfir.py's explicit "
        f"`collect` command, but found it imported by: {importers}"
    )


def test_run_all_module_never_imports_dfir_collector():
    # A second, narrower belt-and-suspenders check aimed squarely at
    # the exact phrase in the governing instruction: `run-all` (the
    # one command that silently fans out to every other scanner) must
    # have zero awareness of secure.dfir.collector. cmd_run_all() lives
    # in secure/cli/root.py — grep its own source, not just imports,
    # since a same-module function could in principle call
    # collect_evidence without a fresh import statement.
    root_py = _SECURE_ROOT / "cli" / "root.py"
    assert root_py.exists(), "expected secure/cli/root.py to define cmd_run_all()"
    text = root_py.read_text()
    assert "dfir" not in text.lower(), (
        "secure/cli/root.py (home of cmd_run_all) must have zero awareness of secure.dfir — "
        "run-all must never be able to trigger a forensic collection."
    )


# ---------- 2. provenance preserved end to end ----------


def test_collect_evidence_preserves_every_provenance_field_end_to_end(tmp_path: Path, monkeypatch):
    def fake_run_collection(cfg, artifact_name, parameters=None, **kwargs):
        return CollectionOutcome(
            status=STATUS_OK, detail="Collected 1 row(s).", tool_version="0.7.1",
            started_at="2026-01-01T12:00:10+00:00", completed_at="2026-01-01T12:00:15+00:00",
            rows=[{"pid": 1, "name": "curl"}],
        )

    monkeypatch.setattr(collector_module, "run_collection", fake_run_collection)

    with Database(tmp_path / "test.db") as db:
        cfg = _cfg(tmp_path, allowlist=["MacOS.System.Pslist"])
        request = CollectionRequest(
            artifact_name="MacOS.System.Pslist", parameters={"pid": "2", "path": "/usr/bin/curl"},
            reason="chasing a persistence alert", entity=_entity(),
            source_table="persistence_alerts", source_id=42,
        )
        record = collect_evidence(db.conn, cfg, request)

        # artifact name + parameters, exactly as supplied
        assert record.artifact_name == "MacOS.System.Pslist"
        assert record.parameters == {"pid": "2", "path": "/usr/bin/curl"}
        # reason + entity + motivating finding
        assert record.reason == "chasing a persistence alert"
        assert record.entity_type == PROCESS
        assert record.entity_key == process_key("/usr/bin/curl")
        assert record.source_table == "persistence_alerts"
        assert record.source_id == 42
        # every timestamp the outcome produced, none dropped
        assert record.requested_at is not None
        assert record.started_at == "2026-01-01T12:00:10+00:00"
        assert record.completed_at == "2026-01-01T12:00:15+00:00"
        assert record.created_at is not None
        # tool version
        assert record.tool_version == "0.7.1"
        # normalized evidence itself
        assert record.evidence_item_count == 1


# ---------- 3. failure treated as unavailable, never exculpatory ----------


def test_unavailable_collection_never_looks_like_a_clean_scan(tmp_path: Path, monkeypatch):
    def fake_run_collection(cfg, artifact_name, parameters=None, **kwargs):
        return CollectionOutcome(
            status=STATUS_UNAVAILABLE, detail="velociraptor binary not found.", tool_version=None,
            started_at=None, completed_at=None, rows=[],
        )

    monkeypatch.setattr(collector_module, "run_collection", fake_run_collection)

    with Database(tmp_path / "test.db") as db:
        cfg = _cfg(tmp_path, allowlist=["MacOS.System.Pslist"])
        request = CollectionRequest(artifact_name="MacOS.System.Pslist", parameters={}, reason="r", entity=_entity())
        record = collect_evidence(db.conn, cfg, request)

        # An UNAVAILABLE collection is recorded through the exact same
        # path as a successful one — same table, same function, no
        # separate "it failed" code path that could diverge or be
        # skipped — with zero evidence items, never fabricated ones.
        assert record.status == STATUS_UNAVAILABLE
        assert record.status != STATUS_OK
        assert record.evidence_item_count == 0


def test_error_collection_also_never_looks_like_a_clean_scan(tmp_path: Path, monkeypatch):
    def fake_run_collection(cfg, artifact_name, parameters=None, **kwargs):
        return CollectionOutcome(
            status=STATUS_ERROR, detail="artifact not found on this system", tool_version="0.7.1",
            started_at="2026-01-01T12:00:00+00:00", completed_at="2026-01-01T12:00:01+00:00", rows=[],
        )

    monkeypatch.setattr(collector_module, "run_collection", fake_run_collection)

    with Database(tmp_path / "test.db") as db:
        cfg = _cfg(tmp_path, allowlist=["MacOS.System.Pslist"])
        request = CollectionRequest(artifact_name="MacOS.System.Pslist", parameters={}, reason="r", entity=_entity())
        record = collect_evidence(db.conn, cfg, request)
        assert record.status == STATUS_ERROR
        assert record.evidence_item_count == 0


# ---------- 4. allowlist enforcement, no trace left behind ----------


def test_allowlist_rejection_raises_before_any_subprocess_or_storage_write(tmp_path: Path, monkeypatch):
    called = {"run_collection": False}

    def fake_run_collection(cfg, artifact_name, parameters=None, **kwargs):
        called["run_collection"] = True
        return CollectionOutcome(
            status=STATUS_OK, detail="d", tool_version="0.7.1",
            started_at="x", completed_at="y", rows=[{"pid": 1}],
        )

    monkeypatch.setattr(collector_module, "run_collection", fake_run_collection)

    with Database(tmp_path / "test.db") as db:
        cfg = _cfg(tmp_path, allowlist=["MacOS.System.Pslist"])  # different artifact than requested
        request = CollectionRequest(
            artifact_name="Windows.System.Powershell", parameters={}, reason="r", entity=_entity(),
        )
        try:
            collect_evidence(db.conn, cfg, request)
            assert False, "expected ArtifactNotAllowedError"
        except ArtifactNotAllowedError:
            pass

        # the refusal happened before run_collection was ever called...
        assert called["run_collection"] is False
        # ...and before any row was written — a refused request leaves
        # no trace, because it never actually happened.
        assert db.conn.execute("SELECT COUNT(*) AS c FROM forensic_collections").fetchone()["c"] == 0
        assert db.conn.execute("SELECT COUNT(*) AS c FROM forensic_evidence_items").fetchone()["c"] == 0


def test_empty_allowlist_rejects_every_artifact(tmp_path: Path):
    # The documented default: nothing collectible until the operator
    # explicitly configures dfir_artifact_allowlist.
    with Database(tmp_path / "test.db") as db:
        cfg = _cfg(tmp_path, allowlist=[])
        for artifact_name in ("MacOS.System.Pslist", "Generic.Client.Info", "Windows.System.Powershell"):
            request = CollectionRequest(artifact_name=artifact_name, parameters={}, reason="r", entity=_entity())
            try:
                collect_evidence(db.conn, cfg, request)
                assert False, f"expected ArtifactNotAllowedError for {artifact_name!r}"
            except ArtifactNotAllowedError:
                pass
        assert db.conn.execute("SELECT COUNT(*) AS c FROM forensic_collections").fetchone()["c"] == 0
