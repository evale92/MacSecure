"""
Tests for the `secure dfir ...` CLI front end (secure/cli/dfir.py,
Phase 24 Stage 5). Follows the same isolated-temp-app-dir /
_run_capturing_stdout convention as tests/test_cli_anomalies.py.

secure/dfir/collector.py, suggest.py, and velociraptor/ already have
their own dedicated unit tests (tests/test_dfir_collector.py,
test_dfir_suggest.py, test_dfir_velociraptor.py) — this file's job is
only to check the CLI layer wires those correctly: argument parsing,
exit codes, and the two adversarial behaviors that are specifically
CLI-visible: (1) an allowlist refusal prints a clear message and exits
nonzero rather than crashing, and (2) `secure dfir evidence` on a
failed collection explicitly says so, rather than looking identical to
"ran fine, found nothing."

Run with:  pytest
"""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path

from secure import cli
from secure.cli import dfir as dfir_cli
from secure.config import load_config
from secure.dfir import collector as collector_module
from secure.dfir.velociraptor.collect import CollectionOutcome
from secure.integrations.base import STATUS_OK, STATUS_UNAVAILABLE
from secure.investigate.entity import PROCESS, process_key
from secure.storage.database import Database
from secure.storage.models import upsert_process_entry


def _bootstrap_to_tmp(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cli, "load_config", lambda: load_config(app_dir=tmp_path))
    return load_config(app_dir=tmp_path)


def _run_capturing_stdout(fn, *args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*args)
    return rc, buf.getvalue()


def _ns(**kwargs) -> argparse.Namespace:
    return argparse.Namespace(**kwargs)


def _collect_ns(**overrides):
    base = dict(
        artifact="MacOS.System.Pslist", param=None, reason="checking",
        entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"),
        source_table=None, source_id=None,
    )
    base.update(overrides)
    return _ns(**base)


# ---------- status ----------


def test_dfir_status_reports_empty_allowlist(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(dfir_cli.cmd_dfir_status, _ns())
    assert rc == 0
    assert "No artifacts are currently allowed" in stdout


# ---------- suggest ----------


def test_dfir_suggest_invalid_entity_returns_1(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        dfir_cli.cmd_dfir_suggest, _ns(entity_type="not_a_real_type", entity_key="x")
    )
    assert rc == 1
    assert "Invalid entity" in stdout


def test_dfir_suggest_no_candidates_for_unseen_entity(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        dfir_cli.cmd_dfir_suggest, _ns(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"))
    )
    assert rc == 0
    assert "No collection candidates" in stdout


# ---------- collect: allowlist enforcement (adversarial) ----------


def test_dfir_collect_refuses_artifact_outside_allowlist_and_writes_no_row(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    assert cfg.dfir_artifact_allowlist == []  # nothing collectible until explicitly configured

    rc, stdout = _run_capturing_stdout(dfir_cli.cmd_dfir_collect, _collect_ns())
    assert rc == 1
    assert "Refused" in stdout

    with Database(cfg.database_path()) as db:
        count = db.conn.execute("SELECT COUNT(*) AS c FROM forensic_collections").fetchone()["c"]
        assert count == 0


def test_dfir_collect_rejects_malformed_param(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(dfir_cli.cmd_dfir_collect, _collect_ns(param=["no-equals-sign"]))
    assert rc == 1
    assert "KEY=VALUE" in stdout


def test_dfir_collect_invalid_entity_returns_1_before_touching_storage(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        dfir_cli.cmd_dfir_collect, _collect_ns(entity_type="not_a_real_type")
    )
    assert rc == 1
    assert "Invalid entity" in stdout
    with Database(cfg.database_path()) as db:
        count = db.conn.execute("SELECT COUNT(*) AS c FROM forensic_collections").fetchone()["c"]
        assert count == 0


# ---------- collect + list + show + evidence: end-to-end provenance ----------


def test_dfir_collect_allowed_artifact_end_to_end_through_list_show_evidence(tmp_path: Path, monkeypatch):
    def fake_run_collection(cfg, artifact_name, parameters=None, **kwargs):
        return CollectionOutcome(
            status=STATUS_OK, detail="Collected 1 row(s).", tool_version="0.7.1",
            started_at="2026-01-01T12:00:00+00:00", completed_at="2026-01-01T12:00:05+00:00",
            rows=[{"pid": 1, "name": "curl"}],
        )

    monkeypatch.setattr(collector_module, "run_collection", fake_run_collection)
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    cfg.dfir_artifact_allowlist.append("MacOS.System.Pslist")
    monkeypatch.setattr(cli, "load_config", lambda: cfg)

    with Database(cfg.database_path()) as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")

    rc, stdout = _run_capturing_stdout(dfir_cli.cmd_dfir_collect, _collect_ns(param=["pid=2"]))
    assert rc == 0
    assert "OK" in stdout
    assert "evidence items: 1" in stdout

    rc, stdout = _run_capturing_stdout(dfir_cli.cmd_dfir_list, _ns(entity_type=None, entity_key=None, limit=100))
    assert rc == 0
    assert "#1" in stdout
    assert "MacOS.System.Pslist" in stdout

    rc, stdout = _run_capturing_stdout(dfir_cli.cmd_dfir_show, _ns(collection_id=1))
    assert rc == 0
    # Provenance preserved end to end: artifact name, parameters,
    # reason, timestamps, tool version — all visible, none dropped.
    assert "MacOS.System.Pslist" in stdout
    assert "checking" in stdout
    assert "{'pid': '2'}" in stdout
    assert "requested_at:" in stdout
    assert "started_at:   2026-01-01T12:00:00+00:00" in stdout
    assert "completed_at: 2026-01-01T12:00:05+00:00" in stdout
    assert "0.7.1" in stdout

    rc, stdout = _run_capturing_stdout(dfir_cli.cmd_dfir_evidence, _ns(collection_id=1))
    assert rc == 0
    assert "pid" in stdout and "curl" in stdout


# ---------- evidence: failure never looks exculpatory (adversarial) ----------


def test_dfir_evidence_on_failed_collection_explicitly_says_so_not_clean(tmp_path: Path, monkeypatch):
    def fake_run_collection(cfg, artifact_name, parameters=None, **kwargs):
        return CollectionOutcome(
            status=STATUS_UNAVAILABLE, detail="velociraptor binary not found.", tool_version=None,
            started_at=None, completed_at=None, rows=[],
        )

    monkeypatch.setattr(collector_module, "run_collection", fake_run_collection)
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    cfg.dfir_artifact_allowlist.append("MacOS.System.Pslist")
    monkeypatch.setattr(cli, "load_config", lambda: cfg)

    with Database(cfg.database_path()) as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")

    rc, _ = _run_capturing_stdout(dfir_cli.cmd_dfir_collect, _collect_ns())
    assert rc == 1  # a failed collection is a nonzero exit, not silently "fine"

    rc, stdout = _run_capturing_stdout(dfir_cli.cmd_dfir_evidence, _ns(collection_id=1))
    assert rc == 0
    assert "no evidence items recorded" in stdout
    assert "did not complete successfully" in stdout
    assert "not 'nothing found'" in stdout
