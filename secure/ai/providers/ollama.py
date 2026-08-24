"""
secure/ai/providers/ollama.py — the Ollama local-model backend
(https://ollama.com's own HTTP API, normally bound to
http://127.0.0.1:11434). Secure never installs, starts, or manages
Ollama itself — same "Secure never manages the external tool, only
talks to whatever's already running" discipline
secure/dfir/velociraptor/ and secure/integrations/*/​ already
establish for their own external tools.

Gated by AppConfig.ollama_host exactly like
secure.threatintel.providers.virustotal is gated by
`virustotal_api_key`: the empty-string default means "not configured",
checked as the very first thing in `complete()`, before any HTTP call.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional

from secure.ai.base import STATUS_ERROR, STATUS_OK, STATUS_TIMEOUT, STATUS_UNAVAILABLE, ProviderCompletionResult, ProviderIdentity
from secure.ai.providers._http import http_get_json, http_post_json

_IDENTITY = ProviderIdentity(name="ollama")


class OllamaProvider:
    identity = _IDENTITY

    def __init__(self, host: str, model: str, timeout: float) -> None:
        self._host = host.rstrip("/") if host else ""
        self._model = model
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

    def check_reachable(self) -> "tuple[bool, str]":
        """A lightweight liveness check (GET /api/tags — lists locally
        installed models) that never invokes the model itself. Used by
        `secure ai status`, never by `complete()`.
        """
        if not self._host:
            return False, "ollama_host is not configured"
        result = http_get_json(f"{self._host}/api/tags", timeout=5.0)
        if not result.ok:
            return False, result.error or "unreachable"
        return True, f"reachable, {len(result.json.get('models', []))} model(s) installed" if result.json else "reachable"

    def complete(
        self, system_prompt: str, user_prompt: str, *, timeout: "Optional[float]" = None
    ) -> ProviderCompletionResult:
        requested_at = datetime.now(timezone.utc).isoformat()

        if not self._host:
            return ProviderCompletionResult(
                provider=self.identity.name, model=self._model, status=STATUS_UNAVAILABLE,
                text=None, requested_at=requested_at, latency_ms=None, raw_response=None,
                error="ollama_host is not configured — set AppConfig.ollama_host to enable this provider.",
            )

        effective_timeout = timeout if timeout is not None else self._timeout
        body = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
        }

        t0 = time.monotonic()
        result = http_post_json(f"{self._host}/api/chat", body, timeout=effective_timeout)
        latency_ms = (time.monotonic() - t0) * 1000.0

        if not result.ok:
            is_timeout = result.error is not None and "timed out" in result.error.lower()
            return ProviderCompletionResult(
                provider=self.identity.name, model=self._model,
                status=STATUS_TIMEOUT if is_timeout else STATUS_ERROR,
                text=None, requested_at=requested_at, latency_ms=latency_ms,
                raw_response=result.json, error=result.error or "request failed",
            )

        message = (result.json or {}).get("message") or {}
        text = message.get("content")
        if not text:
            return ProviderCompletionResult(
                provider=self.identity.name, model=self._model, status=STATUS_ERROR,
                text=None, requested_at=requested_at, latency_ms=latency_ms,
                raw_response=result.json, error="response had no message.content",
            )

        return ProviderCompletionResult(
            provider=self.identity.name, model=self._model, status=STATUS_OK,
            text=text, requested_at=requested_at, latency_ms=latency_ms,
            raw_response=result.json, error=None,
        )


def build_provider(host: str, model: str, timeout: float) -> OllamaProvider:
    """Always returns a real provider instance, even when `host` is
    empty — the provider self-reports STATUS_UNAVAILABLE honestly, the
    same "always show up, report your own honest status" convention
    secure/threatintel/registry.py's own docstring establishes.
    """
    return OllamaProvider(host=host, model=model, timeout=timeout)
