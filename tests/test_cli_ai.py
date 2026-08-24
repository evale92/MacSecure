"""
Tests for the `secure ai status/ask/history/show` CLI front end
(secure/cli/ai.py, Phase 28 Stage 2 + 5). Follows the same isolated-
temp-app-dir / _run_capturing_stdout / stub-provider convention as
tests/test_cli_validate.py and tests/test_ai_roles_analyst.py.

Run with:  pytest
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
from dataclasses import dataclass
from pathlib import Path

from secure import cli
from secure.ai.base import STATUS_OK as PSTATUS_OK
from secure.ai.base import ProviderCompletionResult, ProviderIdentity
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


def _answer_json(summary: str) -> str:
    return json.dumps({"summary": summary, "claims": [], "suggested_next_steps": ["step"]})


# ---------- status ----------


def test_cmd_ai_status_shows_both_providers_even_when_unconfigured(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(ai_cli.cmd_ai_status, _ns())
    assert rc == 0
    assert "ollama" in stdout
    assert "openai_compatible" in stdout


# ---------- ask ----------


def test_cmd_ai_ask_no_provider_configured_reports_that_clearly(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        ai_cli.cmd_ai_ask, _ns(question="why?", entity_type=None, entity_key=None)
    )
    assert rc == 1
    assert "No provider was available" in stdout


def test_cmd_ai_ask_with_stub_provider_prints_the_answer(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    import secure.ai.analyst as analyst_module

    monkeypatch.setattr(
        analyst_module, "build_providers",
        lambda cfg: {
            "ollama": StubProvider(name="ollama", text=_answer_json("here is why")),
            "openai_compatible": StubProvider(name="openai_compatible", configured=False),
        },
    )
    rc, stdout = _run_capturing_stdout(
        ai_cli.cmd_ai_ask, _ns(question="why is this important?", entity_type=None, entity_key=None)
    )
    assert rc == 0
    assert "here is why" in stdout
    assert "Model A" in stdout


def test_cmd_ai_ask_requires_both_entity_flags_together(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(
        ai_cli.cmd_ai_ask, _ns(question="q", entity_type="process", entity_key=None)
    )
    assert rc == 1
    assert "required together" in stdout


# ---------- history / show ----------


def test_cmd_ai_history_empty_says_so(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(ai_cli.cmd_ai_history, _ns(limit=50))
    assert rc == 0
    assert "No AI analyst queries yet" in stdout


def test_cmd_ai_history_and_show_after_a_real_ask(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    import secure.ai.analyst as analyst_module

    monkeypatch.setattr(
        analyst_module, "build_providers",
        lambda cfg: {
            "ollama": StubProvider(name="ollama", text=_answer_json("solo")),
            "openai_compatible": StubProvider(name="openai_compatible", configured=False),
        },
    )
    _run_capturing_stdout(ai_cli.cmd_ai_ask, _ns(question="q1", entity_type=None, entity_key=None))

    rc, stdout = _run_capturing_stdout(ai_cli.cmd_ai_history, _ns(limit=50))
    assert rc == 0
    assert "q1" in stdout

    rc2, stdout2 = _run_capturing_stdout(ai_cli.cmd_ai_show, _ns(query_id=1))
    assert rc2 == 0
    assert "solo" in stdout2


def test_cmd_ai_show_missing_id_is_a_clean_error(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    rc, stdout = _run_capturing_stdout(ai_cli.cmd_ai_show, _ns(query_id=999))
    assert rc == 1
    assert "No AI analyst query found" in stdout
