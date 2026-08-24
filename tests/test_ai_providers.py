"""
Tests for Phase 28 Stage 2: the two local-model provider backends
(secure/ai/providers/ollama.py, secure/ai/providers/openai_compatible.py)
and secure/ai/registry.py. Follows the exact same "monkeypatch the
module-level http_get_json/http_post_json" convention
tests/test_threatintel.py already established for
secure/threatintel/providers/virustotal.py — no real network, no real
HTTP server.

Run with:  pytest
"""

from __future__ import annotations

from secure.ai import base as base_module
from secure.ai.providers import _http as http_module
from secure.ai.providers import ollama, openai_compatible
from secure.ai.registry import build_providers
from secure.config import AppConfig


# ---------- ollama.py ----------


def test_ollama_provider_unconfigured_is_unavailable_without_any_http_call(monkeypatch):
    called = {"count": 0}
    monkeypatch.setattr(
        ollama, "http_post_json", lambda *a, **k: called.__setitem__("count", called["count"] + 1) or None
    )
    provider = ollama.build_provider("", "llama3.1", 30.0)
    assert provider.configured is False
    result = provider.complete("sys", "user")
    assert result.status == base_module.STATUS_UNAVAILABLE
    assert result.text is None
    assert called["count"] == 0  # never even tried to reach the network


def test_ollama_provider_check_reachable_unconfigured():
    provider = ollama.build_provider("", "llama3.1", 30.0)
    reachable, detail = provider.check_reachable()
    assert reachable is False
    assert "not configured" in detail


def test_ollama_provider_check_reachable_ok(monkeypatch):
    monkeypatch.setattr(
        ollama, "http_get_json",
        lambda url, headers=None, timeout=5.0: http_module.HttpResult(
            ok=True, status_code=200, json={"models": [{"name": "llama3.1"}]}, text="", error=None
        ),
    )
    provider = ollama.build_provider("http://127.0.0.1:11434", "llama3.1", 30.0)
    reachable, detail = provider.check_reachable()
    assert reachable is True
    assert "1 model" in detail


def test_ollama_provider_complete_success(monkeypatch):
    captured = {}

    def fake_post(url, body, headers=None, timeout=60.0):
        captured["url"] = url
        captured["body"] = body
        return http_module.HttpResult(
            ok=True, status_code=200, json={"message": {"role": "assistant", "content": "hello"}}, text="", error=None
        )

    monkeypatch.setattr(ollama, "http_post_json", fake_post)
    provider = ollama.build_provider("http://127.0.0.1:11434", "llama3.1", 30.0)
    result = provider.complete("system prompt", "user prompt")

    assert result.status == base_module.STATUS_OK
    assert result.text == "hello"
    assert result.provider == "ollama"
    assert captured["url"] == "http://127.0.0.1:11434/api/chat"
    assert captured["body"]["messages"][0] == {"role": "system", "content": "system prompt"}
    assert captured["body"]["messages"][1] == {"role": "user", "content": "user prompt"}
    assert captured["body"]["stream"] is False


def test_ollama_provider_complete_empty_content_is_error(monkeypatch):
    monkeypatch.setattr(
        ollama, "http_post_json",
        lambda url, body, headers=None, timeout=60.0: http_module.HttpResult(
            ok=True, status_code=200, json={"message": {}}, text="", error=None
        ),
    )
    provider = ollama.build_provider("http://127.0.0.1:11434", "llama3.1", 30.0)
    result = provider.complete("s", "u")
    assert result.status == base_module.STATUS_ERROR
    assert result.text is None


def test_ollama_provider_complete_timeout(monkeypatch):
    monkeypatch.setattr(
        ollama, "http_post_json",
        lambda url, body, headers=None, timeout=60.0: http_module.HttpResult(
            ok=False, status_code=None, json=None, text="", error="request timed out after 60.0s"
        ),
    )
    provider = ollama.build_provider("http://127.0.0.1:11434", "llama3.1", 30.0)
    result = provider.complete("s", "u")
    assert result.status == base_module.STATUS_TIMEOUT


def test_ollama_provider_complete_generic_failure_is_error(monkeypatch):
    monkeypatch.setattr(
        ollama, "http_post_json",
        lambda url, body, headers=None, timeout=60.0: http_module.HttpResult(
            ok=False, status_code=500, json=None, text="", error="HTTP 500"
        ),
    )
    provider = ollama.build_provider("http://127.0.0.1:11434", "llama3.1", 30.0)
    result = provider.complete("s", "u")
    assert result.status == base_module.STATUS_ERROR


# ---------- openai_compatible.py ----------


def test_openai_compatible_unconfigured_is_unavailable_without_any_http_call(monkeypatch):
    called = {"count": 0}
    monkeypatch.setattr(
        openai_compatible, "http_post_json",
        lambda *a, **k: called.__setitem__("count", called["count"] + 1) or None,
    )
    provider = openai_compatible.build_provider("", "local-model", "", 30.0)
    assert provider.configured is False
    result = provider.complete("sys", "user")
    assert result.status == base_module.STATUS_UNAVAILABLE
    assert called["count"] == 0


def test_openai_compatible_sends_bearer_token_when_api_key_set(monkeypatch):
    captured = {}

    def fake_post(url, body, headers=None, timeout=60.0):
        captured["headers"] = headers
        return http_module.HttpResult(
            ok=True, status_code=200,
            json={"choices": [{"message": {"role": "assistant", "content": "hi"}}]}, text="", error=None,
        )

    monkeypatch.setattr(openai_compatible, "http_post_json", fake_post)
    provider = openai_compatible.build_provider("http://127.0.0.1:1234/v1", "local-model", "secret-key", 30.0)
    result = provider.complete("s", "u")

    assert result.status == base_module.STATUS_OK
    assert result.text == "hi"
    assert captured["headers"]["Authorization"] == "Bearer secret-key"
    assert "secret-key" not in (result.error or "")


def test_openai_compatible_no_api_key_sends_no_auth_header(monkeypatch):
    captured = {}

    def fake_post(url, body, headers=None, timeout=60.0):
        captured["headers"] = headers
        return http_module.HttpResult(
            ok=True, status_code=200,
            json={"choices": [{"message": {"role": "assistant", "content": "hi"}}]}, text="", error=None,
        )

    monkeypatch.setattr(openai_compatible, "http_post_json", fake_post)
    provider = openai_compatible.build_provider("http://127.0.0.1:1234/v1", "local-model", "", 30.0)
    provider.complete("s", "u")
    assert captured["headers"] == {}


def test_openai_compatible_no_choices_is_error(monkeypatch):
    monkeypatch.setattr(
        openai_compatible, "http_post_json",
        lambda url, body, headers=None, timeout=60.0: http_module.HttpResult(
            ok=True, status_code=200, json={"choices": []}, text="", error=None
        ),
    )
    provider = openai_compatible.build_provider("http://127.0.0.1:1234/v1", "local-model", "", 30.0)
    result = provider.complete("s", "u")
    assert result.status == base_module.STATUS_ERROR


def test_openai_compatible_check_reachable_ok(monkeypatch):
    monkeypatch.setattr(
        openai_compatible, "http_get_json",
        lambda url, headers=None, timeout=5.0: http_module.HttpResult(
            ok=True, status_code=200, json={"data": [{"id": "local-model"}]}, text="", error=None
        ),
    )
    provider = openai_compatible.build_provider("http://127.0.0.1:1234/v1", "local-model", "", 30.0)
    reachable, detail = provider.check_reachable()
    assert reachable is True
    assert "1 model" in detail


# ---------- registry.py ----------


def test_build_providers_always_returns_both_backends_even_when_unconfigured():
    providers = build_providers(AppConfig())
    assert set(providers.keys()) == {"ollama", "openai_compatible"}
    assert providers["ollama"].configured is False
    assert providers["openai_compatible"].configured is False


def test_build_providers_reflects_configured_hosts():
    cfg = AppConfig(ollama_host="http://127.0.0.1:11434", local_llm_host="http://127.0.0.1:1234/v1")
    providers = build_providers(cfg)
    assert providers["ollama"].configured is True
    assert providers["openai_compatible"].configured is True


# ---------- base.py invariants ----------


def test_provider_completion_result_rejects_text_without_ok_status():
    try:
        base_module.ProviderCompletionResult(
            provider="x", model="y", status=base_module.STATUS_ERROR, text="should not be allowed",
            requested_at="t", latency_ms=1.0, raw_response=None, error="e",
        )
        assert False, "should have raised"
    except ValueError:
        pass


def test_provider_completion_result_rejects_error_when_ok():
    try:
        base_module.ProviderCompletionResult(
            provider="x", model="y", status=base_module.STATUS_OK, text="fine",
            requested_at="t", latency_ms=1.0, raw_response=None, error="should not be allowed",
        )
        assert False, "should have raised"
    except ValueError:
        pass
