"""
Tests for the `secure ai verify ...` and `secure ai changes ...` CLI
front ends (secure/cli/ai.py, Phase 28 Stage 6-7). Same isolated-temp-
app-dir / _run_capturing_stdout / stub-provider convention as
tests/test_cli_ai.py.

Run with:  pytest
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from secure import cli
from secure.ai.base import STATUS_OK as PSTATUS_OK
from secure.ai.base import ProviderCompletionResult, ProviderIdentity
from secure.ai.verify import operations as ops_module
from secure.cli import ai as ai_cli
from secure.config import load_config


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


# ---------- secure ai verify ... ----------


def test_cmd_ai_verify_list_ops_shows_the_fixed_set(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(ai_cli.cmd_ai_verify_list_ops, _ns())
    assert rc == 0
    for op in ("list_tests", "read_file", "run_pytest", "run_validation_suite", "run_scenario", "check_tool_health"):
        assert op in stdout


def test_cmd_ai_verify_run_rejects_unknown_op(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        ai_cli.cmd_ai_verify_run,
        _ns(op="rm_rf_root", path=None, scenario_id=None, test_path=None, timeout=None),
    )
    assert rc == 1
    assert "not an allowed operation" in stdout


def test_cmd_ai_verify_run_check_tool_health(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        ai_cli.cmd_ai_verify_run,
        _ns(op="check_tool_health", path=None, scenario_id=None, test_path=None, timeout=None),
    )
    assert rc == 0
    assert "overall: ok" in stdout


def test_cmd_ai_verify_run_rejects_path_escape(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        ai_cli.cmd_ai_verify_run,
        _ns(op="read_file", path="../../etc/passwd", scenario_id=None, test_path=None, timeout=None),
    )
    assert rc == 1
    assert "overall: error" in stdout


def test_cmd_ai_verify_suite_then_history_then_show(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    monkeypatch.setattr(
        ops_module.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess([], returncode=0, stdout="", stderr=""),
    )
    rc, stdout = _run_capturing_stdout(ai_cli.cmd_ai_verify_suite, _ns())
    assert rc == 0
    assert "Verification run #1" in stdout

    rc2, hist = _run_capturing_stdout(ai_cli.cmd_ai_verify_history, _ns(limit=50))
    assert rc2 == 0
    assert "#1" in hist

    rc3, show = _run_capturing_stdout(ai_cli.cmd_ai_verify_show, _ns(run_id=1))
    assert rc3 == 0
    assert "Verification run #1" in show


def test_cmd_ai_verify_show_missing_run(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(ai_cli.cmd_ai_verify_show, _ns(run_id=999))
    assert rc == 1
    assert "No AI verification run found" in stdout


# ---------- secure ai changes ... ----------


@dataclass
class StubProvider:
    name: str
    configured: bool = True
    text: str = "{}"

    def __post_init__(self):
        self.identity = ProviderIdentity(name=self.name)
        self.model_name = f"{self.name}-model"

    def check_reachable(self):
        return self.configured, "stub"

    def complete(self, system_prompt, user_prompt, *, timeout=None):
        return ProviderCompletionResult(
            provider=self.name, model=self.model_name, status=PSTATUS_OK, text=self.text,
            requested_at="t", latency_ms=1.0, raw_response=None, error=None,
        )


def _answer(summary: str, **extra) -> str:
    payload = {"summary": summary, "claims": [], "suggested_next_steps": []}
    payload.update(extra)
    return json.dumps(payload)


def _stub_providers(cfg):
    return {
        "ollama": StubProvider(name="ollama", text=_answer("proposed change text")),
        "openai_compatible": StubProvider(name="openai_compatible", text=_answer("verifier take", agreement="agrees")),
    }


def test_cmd_ai_changes_propose_then_list_then_show(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    import secure.ai.changes.workflow as workflow_module

    monkeypatch.setattr(workflow_module, "build_providers", _stub_providers)

    rc, stdout = _run_capturing_stdout(
        ai_cli.cmd_ai_changes_propose,
        _ns(title="Simplify X", topic="X", affected_component="secure/x", entity_type=None, entity_key=None),
    )
    assert rc == 0
    assert "CR-1" in stdout
    assert "THIS IS NOT APPROVED" in stdout

    rc2, listing = _run_capturing_stdout(ai_cli.cmd_ai_changes_list, _ns(status=None, limit=50))
    assert rc2 == 0
    assert "CR-1" in listing

    rc3, show = _run_capturing_stdout(ai_cli.cmd_ai_changes_show, _ns(cr_id="CR-1"))
    assert rc3 == 0
    assert "proposed change text" in show
    assert "To approve:" in show


def test_cmd_ai_changes_approve_requires_correct_hash(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    import secure.ai.changes.workflow as workflow_module

    monkeypatch.setattr(workflow_module, "build_providers", _stub_providers)
    _run_capturing_stdout(
        ai_cli.cmd_ai_changes_propose,
        _ns(title="t", topic="t", affected_component="c", entity_type=None, entity_key=None),
    )

    rc, stdout = _run_capturing_stdout(
        ai_cli.cmd_ai_changes_approve, _ns(cr_id="CR-1", revision_hash="wrong", approved_by="erick")
    )
    assert rc == 1
    assert "REFUSED" in stdout

    from secure.storage.database import Database
    from secure.storage.models import find_ai_change_request

    with Database(cfg.database_path()) as db:
        record = find_ai_change_request(db.conn, "CR-1")

    rc2, stdout2 = _run_capturing_stdout(
        ai_cli.cmd_ai_changes_approve,
        _ns(cr_id="CR-1", revision_hash=record.revision_hash, approved_by="erick"),
    )
    assert rc2 == 0
    assert "approved" in stdout2


def test_cmd_ai_changes_reject(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    import secure.ai.changes.workflow as workflow_module

    monkeypatch.setattr(workflow_module, "build_providers", _stub_providers)
    _run_capturing_stdout(
        ai_cli.cmd_ai_changes_propose,
        _ns(title="t", topic="t", affected_component="c", entity_type=None, entity_key=None),
    )
    rc, stdout = _run_capturing_stdout(ai_cli.cmd_ai_changes_reject, _ns(cr_id="CR-1", approved_by="erick"))
    assert rc == 0
    assert "rejected" in stdout


def test_cmd_ai_changes_list_empty(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(ai_cli.cmd_ai_changes_list, _ns(status=None, limit=50))
    assert rc == 0
    assert "No change requests found" in stdout
