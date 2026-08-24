"""
secure/ai/providers/openai_compatible.py — a generic local model
backend speaking the OpenAI chat-completions API shape
(`POST {host}/chat/completions`, `GET {host}/models`). One
implementation covers LM Studio, llama.cpp's own server, MLX-compatible
servers, vLLM, text-generation-webui, and anything else exposing a
local OpenAI-compatible endpoint — this project deliberately does not
maintain a separate module per tool for what is, at the wire level, the
same API.

Gated by AppConfig.local_llm_host exactly like
secure.ai.providers.ollama is gated by `ollama_host` — empty string
means "not configured," checked first, before any HTTP call.
`local_llm_api_key` is optional (most local, non-network-exposed
servers accept any value or ignore auth entirely); when set it's sent
as a Bearer token, never logged or included in any persisted
`raw_response`.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

from secure.ai.base import STATUS_ERROR, STATUS_OK, STATUS_TIMEOUT, STATUS_UNAVAILABLE, ProviderCompletionResult, ProviderIdentity
from secure.ai.providers._http import http_get_json, http_post_json

_IDENTITY = ProviderIdentity(name="openai_compatible")


class OpenAICompatibleProvider:
    identity = _IDENTITY

    def __init__(self, host: str, model: str, api_key: str, timeout: float) -> None:
        self._host = host.rstrip("/") if host else ""
        self._model = model
        self._api_key = api_key
        self._timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self._host)

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def timeout(self) -> float:
        """Phase 32 (Local Model Routing) reads this to record a role's
        effective timeout without reaching into private state."""
        return self._timeout

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._api_key}"} if self._api_key else {}

    def check_reachable(self) -> "tuple[bool, str]":
        """A lightweight liveness check (GET {host}/models) that never
        invokes the model itself. Used by `secure ai status`, never by
        `complete()`."""
        if not self._host:
            return False, "local_llm_host is not configured"
        result = http_get_json(f"{self._host}/models", headers=self._headers(), timeout=5.0)
        if not result.ok:
            return False, result.error or "unreachable"
        count = len((result.json or {}).get("data", []))
        return True, f"reachable, {count} model(s) listed" if result.json else "reachable"

    def complete(
        self, system_prompt: str, user_prompt: str, *, timeout: "Optional[float]" = None
    ) -> ProviderCompletionResult:
        requested_at = datetime.now(timezone.utc).isoformat()

        if not self._host:
            return ProviderCompletionResult(
                provider=self.identity.name, model=self._model, status=STATUS_UNAVAILABLE,
                text=None, requested_at=requested_at, latency_ms=None, raw_response=None,
                error="local_llm_host is not configured — set AppConfig.local_llm_host to enable this provider.",
            )

        effective_timeout = timeout if timeout is not None else self._timeout
        body = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        t0 = time.monotonic()
        result = http_post_json(
            f"{self._host}/chat/completions", body, headers=self._headers(), timeout=effective_timeout
        )
        latency_ms = (time.monotonic() - t0) * 1000.0

        if not result.ok:
            is_timeout = result.error is not None and "timed out" in result.error.lower()
            return ProviderCompletionResult(
                provider=self.identity.name, model=self._model,
                status=STATUS_TIMEOUT if is_timeout else STATUS_ERROR,
                text=None, requested_at=requested_at, latency_ms=latency_ms,
                raw_response=result.json, error=result.error or "request failed",
            )

        choices = (result.json or {}).get("choices") or []
        text = choices[0].get("message", {}).get("content") if choices else None
        if not text:
            return ProviderCompletionResult(
                provider=self.identity.name, model=self._model, status=STATUS_ERROR,
                text=None, requested_at=requested_at, latency_ms=latency_ms,
                raw_response=result.json, error="response had no choices[0].message.content",
            )

        return ProviderCompletionResult(
            provider=self.identity.name, model=self._model, status=STATUS_OK,
            text=text, requested_at=requested_at, latency_ms=latency_ms,
            raw_response=result.json, error=None,
        )


def build_provider(host: str, model: str, api_key: str, timeout: float) -> OpenAICompatibleProvider:
    """Always returns a real provider instance, even when `host` is
    empty — see secure/ai/providers/ollama.py's build_provider() for
    why."""
    return OpenAICompatibleProvider(host=host, model=model, api_key=api_key, timeout=timeout)
