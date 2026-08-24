"""
secure/ai/base.py — the generic, provider-neutral boundary every local
model backend (Ollama today, a generic OpenAI-compatible local server
tomorrow) is built on. Same "smallest generic boundary, no ABCs, no
plugin registry, plain dataclasses and string constants" discipline
secure/threatintel/base.py and secure/integrations/base.py already
establish for their own external boundaries.

Providers are duck-typed: anything with a `.identity` (a
ProviderIdentity) and a `.complete(system_prompt, user_prompt, *,
timeout) -> ProviderCompletionResult` method is a valid provider. A
provider never sees anything about findings/evidence/citations — it is
handed two plain strings (a system prompt and a user prompt, both
already fully assembled by secure/ai/prompt.py) and returns plain
text. All of Secure's own read-only context assembly, citation
validation, and role orchestration happen entirely OUTSIDE the
provider boundary, so adding a third backend later never requires
touching context.py, response.py, or roles.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

STATUS_OK = "ok"                  # reached the local server; got a real completion back
STATUS_UNAVAILABLE = "unavailable"  # not configured (empty host) — routine, not an error
STATUS_TIMEOUT = "timeout"        # request exceeded its own timeout
STATUS_ERROR = "error"            # reachable config, but this specific attempt failed

_VALID_STATUSES = (STATUS_OK, STATUS_UNAVAILABLE, STATUS_TIMEOUT, STATUS_ERROR)


@dataclass(frozen=True)
class ProviderIdentity:
    """`name` is a short, stable identifier (e.g. "ollama",
    "openai_compatible") used as the `provider_a`/`provider_b` column
    value wherever a query is persisted. `schema_version` mirrors every
    other *Identity dataclass in this codebase — bump only when this
    provider's own ProviderCompletionResult shape changes.
    """

    name: str
    schema_version: int = 1


@dataclass(frozen=True)
class ProviderCompletionResult:
    """One provider's full, normalized outcome for one completion
    request.

    provider/model  — which provider and which model string were used.
    status          — one of the STATUS_* constants above.
    text            — the model's raw completion text; None whenever
        status != STATUS_OK (there is nothing to show for a failed
        request — never a fabricated placeholder).
    requested_at    — when this request was made.
    latency_ms      — wall-clock time for this request, None only when
        the request never actually happened (STATUS_UNAVAILABLE).
    raw_response    — the real, possibly-truncated normalized payload
        received — exact provenance, never fabricated; None when no
        response was ever received.
    error           — short human-readable failure detail; None only
        when status == STATUS_OK.
    """

    provider: str
    model: str
    status: str
    text: "Optional[str]"
    requested_at: str
    latency_ms: "Optional[float]"
    raw_response: "Optional[dict]"
    error: "Optional[str]"

    def __post_init__(self) -> None:
        if self.status not in _VALID_STATUSES:
            raise ValueError(f"invalid ProviderCompletionResult.status: {self.status!r}")
        if self.status != STATUS_OK and self.text is not None:
            raise ValueError(
                "text must be None unless status == STATUS_OK — a failed or unavailable "
                "request has nothing real to show; never fabricate placeholder text."
            )
        if self.status == STATUS_OK and self.error is not None:
            raise ValueError("error must be None when status == STATUS_OK")

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK
