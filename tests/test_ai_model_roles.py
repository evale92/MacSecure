"""
Tests for Phase 32 (Part 2: Supervised Agentic Development & Self-Healing —
"Local Model Routing"): secure/ai/model_roles.py, plus the two real provider
classes' new `.timeout` property (secure/ai/providers/ollama.py,
secure/ai/providers/openai_compatible.py).

Uses the same small duck-typed StubProvider pattern tests/test_ai_roles_analyst.py
already established for Phase 28 — model_roles.py never touches the network
itself, only whatever a provider's `.complete()`/`.identity`/`.model_name`/
`.configured`/`.timeout` report.

Run with:  pytest
"""

from __future__ import annotations

from dataclasses import dataclass

from secure.ai.base import STATUS_ERROR as PSTATUS_ERROR
from secure.ai.base import STATUS_OK as PSTATUS_OK
from secure.ai.base import STATUS_UNAVAILABLE as PSTATUS_UNAVAILABLE
from secure.ai.base import ProviderCompletionResult, ProviderIdentity
from secure.ai.model_roles import (
    ALL_MAINTENANCE_ROLES,
    ROLE_INDEPENDENT_REVIEWER,
    ROLE_PRIMARY_CODER,
    RoleBinding,
    invoke_role,
    now_iso,
    resolve_maintenance_roles,
)
from secure.ai.providers.ollama import build_provider as build_ollama_provider
from secure.ai.providers.openai_compatible import build_provider as build_openai_compatible_provider


@dataclass
class StubProvider:
    name: str
    configured: bool = True
    text: str = "hello"
    status: str = PSTATUS_OK
    timeout: float = 30.0

    def __post_init__(self):
        self.identity = ProviderIdentity(name=self.name)
        self.model_name = f"{self.name}-model"
        self.calls = []

    def check_reachable(self):
        return self.configured, "stub"

    def complete(self, system_prompt, user_prompt, *, timeout=None):
        self.calls.append((system_prompt, user_prompt, timeout))
        return ProviderCompletionResult(
            provider=self.name, model=self.model_name, status=self.status,
            text=self.text if self.status == PSTATUS_OK else None,
            requested_at="t", latency_ms=1.0, raw_response=None,
            error=None if self.status == PSTATUS_OK else "stub failure",
        )


# ---------- resolve_maintenance_roles() ----------


def test_resolve_maintenance_roles_prefers_two_different_backends():
    ollama = StubProvider(name="ollama", timeout=11.0)
    compat = StubProvider(name="openai_compatible", timeout=22.0)
    bindings = resolve_maintenance_roles({"ollama": ollama, "openai_compatible": compat})

    coder = bindings[ROLE_PRIMARY_CODER]
    reviewer = bindings[ROLE_INDEPENDENT_REVIEWER]
    assert coder.provider_name == "ollama"
    assert reviewer.provider_name == "openai_compatible"
    assert coder.provider_name != reviewer.provider_name
    assert coder.configured is True and reviewer.configured is True
    assert coder.model == "ollama-model"
    assert reviewer.model == "openai_compatible-model"
    assert coder.timeout_seconds == 11.0
    assert reviewer.timeout_seconds == 22.0


def test_resolve_maintenance_roles_falls_back_to_one_provider_playing_both_roles():
    ollama = StubProvider(name="ollama")
    compat = StubProvider(name="openai_compatible", configured=False)
    bindings = resolve_maintenance_roles({"ollama": ollama, "openai_compatible": compat})

    assert bindings[ROLE_PRIMARY_CODER].provider_name == "ollama"
    assert bindings[ROLE_INDEPENDENT_REVIEWER].provider_name == "ollama"
    assert bindings[ROLE_PRIMARY_CODER].configured is True
    assert bindings[ROLE_INDEPENDENT_REVIEWER].configured is True


def test_resolve_maintenance_roles_neither_configured_reports_honestly():
    ollama = StubProvider(name="ollama", configured=False)
    compat = StubProvider(name="openai_compatible", configured=False)
    bindings = resolve_maintenance_roles({"ollama": ollama, "openai_compatible": compat})

    for role in ALL_MAINTENANCE_ROLES:
        binding = bindings[role]
        assert binding.configured is False
        assert binding.provider_name == ""
        assert binding.model == ""
        assert binding.timeout_seconds is None


def test_resolve_maintenance_roles_always_returns_both_roles():
    bindings = resolve_maintenance_roles({"ollama": None, "openai_compatible": None})
    assert set(bindings.keys()) == set(ALL_MAINTENANCE_ROLES)
    assert isinstance(bindings[ROLE_PRIMARY_CODER], RoleBinding)
    assert isinstance(bindings[ROLE_INDEPENDENT_REVIEWER], RoleBinding)


# ---------- invoke_role() ----------


def test_invoke_role_both_roles_invokable_independently():
    ollama = StubProvider(name="ollama", text="coder output")
    compat = StubProvider(name="openai_compatible", text="reviewer output")

    coder_result = invoke_role(ROLE_PRIMARY_CODER, ollama, "sys", "fix this")
    reviewer_result = invoke_role(ROLE_INDEPENDENT_REVIEWER, compat, "sys", "review this")

    assert coder_result.role == ROLE_PRIMARY_CODER
    assert coder_result.completion.text == "coder output"
    assert reviewer_result.role == ROLE_INDEPENDENT_REVIEWER
    assert reviewer_result.completion.text == "reviewer output"
    # No shared mutable state: each provider only saw its own call.
    assert len(ollama.calls) == 1
    assert len(compat.calls) == 1


def test_invoke_role_unavailable_provider_fails_honestly_not_a_crash():
    unavailable = StubProvider(name="ollama", configured=False, status=PSTATUS_UNAVAILABLE)
    result = invoke_role(ROLE_PRIMARY_CODER, unavailable, "sys", "fix this")
    assert result.completion.status == PSTATUS_UNAVAILABLE
    assert result.completion.text is None
    assert result.completion.error is not None


def test_invoke_role_passes_explicit_timeout_through():
    provider = StubProvider(name="ollama")
    invoke_role(ROLE_PRIMARY_CODER, provider, "sys", "user", timeout=7.5)
    assert provider.calls[0][2] == 7.5


# ---------- now_iso() ----------


def test_now_iso_returns_iso_format_string():
    value = now_iso()
    assert isinstance(value, str)
    assert "T" in value


# ---------- real provider .timeout property (Ollama / OpenAI-compatible) ----------


def test_ollama_provider_exposes_configured_timeout():
    provider = build_ollama_provider(host="http://127.0.0.1:11434", model="llama3.1", timeout=42.0)
    assert provider.timeout == 42.0


def test_ollama_provider_unconfigured_still_exposes_timeout_and_fails_honestly():
    provider = build_ollama_provider(host="", model="llama3.1", timeout=15.0)
    assert provider.timeout == 15.0
    assert provider.configured is False
    result = provider.complete("sys", "user")
    assert result.status == PSTATUS_UNAVAILABLE
    assert result.text is None


def test_openai_compatible_provider_exposes_configured_timeout():
    provider = build_openai_compatible_provider(host="http://127.0.0.1:8080", model="local-model", api_key="", timeout=9.0)
    assert provider.timeout == 9.0


def test_openai_compatible_provider_unconfigured_still_exposes_timeout_and_fails_honestly():
    provider = build_openai_compatible_provider(host="", model="local-model", api_key="", timeout=5.0)
    assert provider.timeout == 5.0
    assert provider.configured is False
    result = provider.complete("sys", "user")
    assert result.status == PSTATUS_UNAVAILABLE
    assert result.text is None


# ---------- deterministic Secure logic remains authoritative ----------


def test_resolve_maintenance_roles_binding_is_pure_no_network_call():
    # Building bindings must never invoke .complete() on either provider —
    # role assignment is deterministic bookkeeping, not a model call.
    ollama = StubProvider(name="ollama")
    compat = StubProvider(name="openai_compatible")
    resolve_maintenance_roles({"ollama": ollama, "openai_compatible": compat})
    assert ollama.calls == []
    assert compat.calls == []
