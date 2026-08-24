"""
secure/ai/registry.py — builds the two local-model providers from
AppConfig. Mirrors secure/threatintel/registry.py exactly: both
providers are always registered, never conditionally omitted based on
config — each provider's own `.complete()` already reports
STATUS_UNAVAILABLE honestly when it isn't configured. This means
`secure ai status` can always show every backend Secure KNOWS about,
not just the ones currently configured.
"""

from __future__ import annotations

from secure.ai.providers import ollama, openai_compatible
from secure.config import AppConfig


def build_providers(cfg: AppConfig) -> dict:
    """Returns {"ollama": OllamaProvider, "openai_compatible":
    OpenAICompatibleProvider} — a dict (not a list, unlike
    threatintel's registry) since secure/ai/roles.py needs to address
    each backend by name when assigning Model A/Model B roles.
    """
    return {
        "ollama": ollama.build_provider(cfg.ollama_host, cfg.ollama_model, cfg.ollama_timeout_seconds),
        "openai_compatible": openai_compatible.build_provider(
            cfg.local_llm_host, cfg.local_llm_model, cfg.local_llm_api_key, cfg.local_llm_timeout_seconds
        ),
    }
