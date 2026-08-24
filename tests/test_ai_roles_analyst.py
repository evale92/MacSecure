"""
Tests for Phase 28 Stage 5: secure/ai/roles.py (two-role, two-pass
orchestration) and secure/ai/analyst.py (ask(), the top-level entry
point). Uses small stub providers implementing the duck-typed
provider interface (secure/ai/base.py) rather than any real or fake
HTTP server — roles.py/analyst.py never touch the network themselves,
only whatever `.complete()` returns.

Run with:  pytest
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from secure.ai.analyst import STATUS_ERROR, STATUS_OK, STATUS_PARTIAL, STATUS_UNAVAILABLE, ask
from secure.ai.base import STATUS_ERROR as PSTATUS_ERROR
from secure.ai.base import STATUS_OK as PSTATUS_OK
from secure.ai.base import STATUS_UNAVAILABLE as PSTATUS_UNAVAILABLE
from secure.ai.base import ProviderCompletionResult, ProviderIdentity
from secure.ai.context import MODE_FREEFORM, build_freeform_context
from secure.ai.roles import resolve_role_providers, run_analyst, run_verifier
from secure.config import AppConfig
from secure.storage.database import Database
from secure.storage.models import find_ai_analyst_query


def _answer_json(summary: str, agreement: "str | None" = None, **extra) -> str:
    payload = {"summary": summary, "claims": [], "suggested_next_steps": []}
    if agreement is not None:
        payload["agreement"] = agreement
    payload.update(extra)
    return json.dumps(payload)


@dataclass
class StubProvider:
    name: str
    configured: bool = True
    text: str = "{}"
    status: str = PSTATUS_OK

    def __post_init__(self):
        self.identity = ProviderIdentity(name=self.name)
        self.model_name = f"{self.name}-model"
        self.calls = []

    def check_reachable(self):
        return self.configured, "stub"

    def complete(self, system_prompt, user_prompt, *, timeout=None):
        self.calls.append((system_prompt, user_prompt))
        return ProviderCompletionResult(
            provider=self.name, model=self.model_name, status=self.status,
            text=self.text if self.status == PSTATUS_OK else None,
            requested_at="t", latency_ms=1.0, raw_response=None,
            error=None if self.status == PSTATUS_OK else "stub failure",
        )


def _empty_context(tmp_path: Path):
    with Database(tmp_path / "ctx.db") as db:
        return build_freeform_context(db.conn, AppConfig(app_dir=str(tmp_path)))


# ---------- resolve_role_providers() ----------


def test_resolve_role_providers_prefers_two_different_backends():
    ollama = StubProvider(name="ollama")
    compat = StubProvider(name="openai_compatible")
    a, b = resolve_role_providers({"ollama": ollama, "openai_compatible": compat})
    assert a is ollama
    assert b is compat


def test_resolve_role_providers_falls_back_to_one_provider_playing_both_roles():
    ollama = StubProvider(name="ollama")
    compat = StubProvider(name="openai_compatible", configured=False)
    a, b = resolve_role_providers({"ollama": ollama, "openai_compatible": compat})
    assert a is ollama
    assert b is ollama


def test_resolve_role_providers_neither_configured_returns_none_none():
    ollama = StubProvider(name="ollama", configured=False)
    compat = StubProvider(name="openai_compatible", configured=False)
    a, b = resolve_role_providers({"ollama": ollama, "openai_compatible": compat})
    assert a is None
    assert b is None


# ---------- run_analyst() / run_verifier() ----------


def test_run_analyst_parses_and_validates_citations(tmp_path: Path):
    context = _empty_context(tmp_path)
    provider = StubProvider(name="ollama", text=_answer_json("my analysis"))
    result = run_analyst(provider, context, "why?")
    assert result.completion.ok is True
    assert result.answer.parse_ok is True
    assert result.answer.summary == "my analysis"


def test_run_verifier_makes_exactly_two_calls_independent_then_review(tmp_path: Path):
    context = _empty_context(tmp_path)
    analyst_answer = run_analyst(StubProvider(name="ollama", text=_answer_json("A's take")), context, "q").answer

    verifier_provider = StubProvider(name="openai_compatible", text=_answer_json("B's take", agreement="agrees"))
    result = run_verifier(verifier_provider, context, "q", analyst_answer)

    assert len(verifier_provider.calls) == 2
    # First call (independent) must not mention Model A's answer at all.
    assert "A's take" not in verifier_provider.calls[0][1]
    # Second call (review) must show both answers.
    assert "A's take" in verifier_provider.calls[1][1]
    assert result.review_answer.agreement == "agrees"


def test_run_verifier_review_prompt_never_leaks_into_independent_pass(tmp_path: Path):
    context = _empty_context(tmp_path)
    analyst_answer = run_analyst(StubProvider(name="ollama", text=_answer_json("secret A conclusion")), context, "q").answer
    verifier_provider = StubProvider(name="openai_compatible", text=_answer_json("independent"))
    run_verifier(verifier_provider, context, "q", analyst_answer)
    independent_system, independent_user = verifier_provider.calls[0]
    assert "secret A conclusion" not in independent_system
    assert "secret A conclusion" not in independent_user


# ---------- ask() ----------


def test_ask_no_provider_configured_is_unavailable_and_persists(tmp_path: Path, monkeypatch):
    import secure.ai.analyst as analyst_module

    monkeypatch.setattr(
        analyst_module, "build_providers",
        lambda cfg: {"ollama": StubProvider(name="ollama", configured=False),
                     "openai_compatible": StubProvider(name="openai_compatible", configured=False)},
    )
    with Database(tmp_path / "test.db") as db:
        outcome = ask(db.conn, AppConfig(app_dir=str(tmp_path)), "why?")
        assert outcome.status == STATUS_UNAVAILABLE
        assert outcome.analyst is None
        record = find_ai_analyst_query(db.conn, outcome.query_id)
        assert record.status == STATUS_UNAVAILABLE


def test_ask_both_providers_succeed_is_ok_with_full_citation_counts(tmp_path: Path, monkeypatch):
    import secure.ai.analyst as analyst_module

    monkeypatch.setattr(
        analyst_module, "build_providers",
        lambda cfg: {
            "ollama": StubProvider(name="ollama", text=_answer_json("A's answer")),
            "openai_compatible": StubProvider(name="openai_compatible", text=_answer_json("B's answer", agreement="agrees")),
        },
    )
    with Database(tmp_path / "test.db") as db:
        outcome = ask(db.conn, AppConfig(app_dir=str(tmp_path)), "why is this important?")
        record = find_ai_analyst_query(db.conn, outcome.query_id)

    assert outcome.status == STATUS_OK
    assert outcome.analyst is not None
    assert outcome.verifier is not None
    assert record.status == STATUS_OK
    assert record.provider_a == "ollama"
    assert record.provider_b == "openai_compatible"


def test_ask_single_configured_provider_plays_both_roles_and_still_reaches_ok(tmp_path: Path, monkeypatch):
    # resolve_role_providers() falls back to ONE provider playing both
    # roles when only one backend is configured (still three genuine
    # completion calls) — this is deliberate, not a degraded mode, so
    # the outcome should be a normal STATUS_OK, not "partial".
    import secure.ai.analyst as analyst_module

    monkeypatch.setattr(
        analyst_module, "build_providers",
        lambda cfg: {
            "ollama": StubProvider(name="ollama", text=_answer_json("solo answer", agreement="agrees")),
            "openai_compatible": StubProvider(name="openai_compatible", configured=False),
        },
    )
    with Database(tmp_path / "test.db") as db:
        outcome = ask(db.conn, AppConfig(app_dir=str(tmp_path)), "q")

    assert outcome.status == STATUS_OK
    assert outcome.verifier is not None
    assert outcome.analyst.completion.provider == "ollama"
    assert outcome.verifier.independent_completion.provider == "ollama"


def test_ask_verifier_pass_failing_is_partial(tmp_path: Path, monkeypatch):
    # A provider that answers the analyst's call fine but fails on its
    # own verifier passes should leave the analyst's real answer intact
    # (status="partial") rather than discarding it — "passing tests
    # does not equal approval," but a good answer with an unfinished
    # verification also shouldn't just vanish.
    import secure.ai.analyst as analyst_module

    class FlakyOnceProvider(StubProvider):
        def complete(self, system_prompt, user_prompt, *, timeout=None):
            self.calls.append((system_prompt, user_prompt))
            if len(self.calls) == 1:
                return ProviderCompletionResult(
                    provider=self.name, model=self.model_name, status=PSTATUS_OK,
                    text=_answer_json("first call succeeds"), requested_at="t", latency_ms=1.0,
                    raw_response=None, error=None,
                )
            return ProviderCompletionResult(
                provider=self.name, model=self.model_name, status=PSTATUS_ERROR,
                text=None, requested_at="t", latency_ms=1.0, raw_response=None, error="flaky failure",
            )

    monkeypatch.setattr(
        analyst_module, "build_providers",
        lambda cfg: {
            "ollama": FlakyOnceProvider(name="ollama"),
            "openai_compatible": StubProvider(name="openai_compatible", configured=False),
        },
    )
    with Database(tmp_path / "test.db") as db:
        outcome = ask(db.conn, AppConfig(app_dir=str(tmp_path)), "q")
        record = find_ai_analyst_query(db.conn, outcome.query_id)

    assert outcome.status == STATUS_PARTIAL
    assert outcome.analyst.answer.parse_ok is True  # the good analyst answer is preserved
    assert record.status == STATUS_PARTIAL


def test_ask_analyst_call_fails_is_error_status(tmp_path: Path, monkeypatch):
    import secure.ai.analyst as analyst_module

    monkeypatch.setattr(
        analyst_module, "build_providers",
        lambda cfg: {
            "ollama": StubProvider(name="ollama", status=PSTATUS_ERROR),
            "openai_compatible": StubProvider(name="openai_compatible", configured=False),
        },
    )
    with Database(tmp_path / "test.db") as db:
        outcome = ask(db.conn, AppConfig(app_dir=str(tmp_path)), "q")

    assert outcome.status == STATUS_ERROR
    assert outcome.verifier is None


def test_ask_entity_scoped_question_uses_entity_mode(tmp_path: Path, monkeypatch):
    import secure.ai.analyst as analyst_module
    from secure.investigate.entity import PROCESS, EntityRef, process_key
    from secure.storage.models import upsert_process_entry

    monkeypatch.setattr(
        analyst_module, "build_providers",
        lambda cfg: {
            "ollama": StubProvider(name="ollama", text=_answer_json("entity answer")),
            "openai_compatible": StubProvider(name="openai_compatible", configured=False),
        },
    )
    with Database(tmp_path / "test.db") as db:
        upsert_process_entry(db.conn, "/usr/bin/curl", "curl", "root", "signed")
        entity = EntityRef(entity_type=PROCESS, entity_key=process_key("/usr/bin/curl"))
        outcome = ask(db.conn, AppConfig(app_dir=str(tmp_path)), "what is this?", entity=entity)
        record = find_ai_analyst_query(db.conn, outcome.query_id)

    assert record.mode != MODE_FREEFORM
    assert record.entity_type == PROCESS
