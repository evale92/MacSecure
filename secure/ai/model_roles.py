"""
secure/ai/model_roles.py — Phase 32 (Part 2: Supervised Agentic
Development & Self-Healing — "Local Model Routing").

Assigns Secure's two ENGINEERING-MAINTENANCE roles — PRIMARY_CODER and
INDEPENDENT_REVIEWER — to the same two local-model providers Phase 28
already built (secure/ai/providers/ollama.py,
secure/ai/providers/openai_compatible.py), and nothing else. This
module builds NO new inference framework, NO new HTTP client, and NO
new provider class — every actual model call still goes through
secure.ai.base.ProviderCompletionResult via a provider's own
.complete(), unchanged. Per the governing instruction ("Do not build
another inference framework... Secure should primarily own policy,
trust boundaries, ... provenance, auditing... Existing frameworks
should own... code generation... tool invocation"), this module owns
ONLY role assignment and stamping a role name onto an otherwise
unmodified provider result.

Distinct from secure/ai/roles.py's Model A (Analyst) / Model B
(Verifier) roles, which are a SEPARATE role assignment for a SEPARATE
feature (the AI Security Analyst's own question-answering, Phase 28).
Both role systems reuse the identical, already-generic
resolve_role_providers() function from secure/ai/roles.py, completely
unchanged — assigning two new named roles to the same two provider
instances is exactly the generic thing that function already does;
nothing about it is Analyst/Verifier-specific, so it needed no
modification at all to serve a second, unrelated pair of roles. This is
the smallest possible architecture for Phase 32: zero new config
fields, zero new provider registration, one new thin module.

Preferring two DIFFERENT provider backends (Ollama vs. an
OpenAI-compatible local server) for PRIMARY_CODER vs.
INDEPENDENT_REVIEWER when both are configured is what makes the
reviewer role meaningful — "review is not merely the same model
agreeing with itself" (the governing instruction's own words, echoing
Phase 28's Model A/Model B rationale). When only one backend is
configured, both roles still resolve honestly to it (two independent
invocations of the same model, not a failure) — never silently
disabling the maintenance workflow just because a second backend
hasn't been set up yet. When neither backend is configured, both roles
report configured=False, honestly, with no crash and no fabricated
identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from secure.ai.base import ProviderCompletionResult
from secure.ai.roles import resolve_role_providers

ROLE_PRIMARY_CODER = "primary_coder"
ROLE_INDEPENDENT_REVIEWER = "independent_reviewer"

ALL_MAINTENANCE_ROLES = (ROLE_PRIMARY_CODER, ROLE_INDEPENDENT_REVIEWER)


@dataclass(frozen=True)
class RoleBinding:
    """Which provider plays which maintenance role, and everything
    about that assignment worth recording BEFORE any completion is
    even attempted — this is what Phase 32's own acceptance criterion
    "model identity is recorded" refers to: provider, model, role,
    availability, and timeout are all captured here, independent of
    whether the role is ever actually invoked.

    `provider_name`/`model` are the empty string, and `configured` is
    False, when no provider could be assigned to this role at all
    (neither backend configured) — never a fabricated identity.
    """

    role: str
    provider_name: str
    model: str
    configured: bool
    timeout_seconds: "Optional[float]"


@dataclass(frozen=True)
class RoleInvocationResult:
    """One maintenance role's completion attempt — a plain
    ProviderCompletionResult (Phase 28's own frozen shape, unmodified)
    with the role name stamped on alongside it. Deliberately does NOT
    subclass or wrap ProviderCompletionResult's fields into a new
    shape — callers that already know how to read a
    ProviderCompletionResult (status/text/error/latency_ms/...) read
    `.completion` exactly the same way they always have."""

    role: str
    completion: ProviderCompletionResult


def _binding(role: str, provider: "Optional[object]") -> RoleBinding:
    if provider is None:
        return RoleBinding(role=role, provider_name="", model="", configured=False, timeout_seconds=None)
    identity = getattr(provider, "identity", None)
    provider_name = identity.name if identity is not None else ""
    return RoleBinding(
        role=role,
        provider_name=provider_name,
        model=getattr(provider, "model_name", ""),
        configured=bool(getattr(provider, "configured", False)),
        timeout_seconds=getattr(provider, "timeout", None),
    )


def resolve_maintenance_roles(providers: dict) -> "dict[str, RoleBinding]":
    """Assigns PRIMARY_CODER and INDEPENDENT_REVIEWER to Secure's two
    registered local-model providers (secure.ai.registry.build_providers()'s
    own {"ollama": ..., "openai_compatible": ...} dict — the exact same
    dict Phase 28's ask() already builds and passes to
    resolve_role_providers()), reused completely unchanged. Always
    returns a binding for both roles, even when nothing is configured —
    "unavailable models fail honestly," never an exception, never a
    missing key."""
    coder_provider, reviewer_provider = resolve_role_providers(providers)
    return {
        ROLE_PRIMARY_CODER: _binding(ROLE_PRIMARY_CODER, coder_provider),
        ROLE_INDEPENDENT_REVIEWER: _binding(ROLE_INDEPENDENT_REVIEWER, reviewer_provider),
    }


def invoke_role(
    role: str, provider, system_prompt: str, user_prompt: str, *, timeout: "Optional[float]" = None
) -> RoleInvocationResult:
    """Invokes one maintenance role's assigned provider — the ENTIRE
    "invocation" here is a direct, unmodified call to the provider's
    own .complete() (Phase 28's provider boundary; see secure/ai/base.py's
    own docstring for why nothing above that boundary needs to change
    for a new caller). Both roles can be invoked independently: this
    function takes one role/provider pair at a time and has no shared
    mutable state between calls, so PRIMARY_CODER and
    INDEPENDENT_REVIEWER invocations never interfere with each other
    and neither has to wait on or know about the other.

    `provider` is passed explicitly (not re-resolved from a role name)
    so a caller that already has a RoleBinding's matching provider
    instance in hand (from the same resolve_maintenance_roles() dict
    used to build the providers dict itself) never pays for a second
    resolution, and so this function works identically for a real
    provider or a duck-typed test stub."""
    completion = provider.complete(system_prompt, user_prompt, timeout=timeout)
    return RoleInvocationResult(role=role, completion=completion)


def now_iso() -> str:
    """Small convenience for callers (CLI, later phases' persistence)
    that want a timestamp in the same format ProviderCompletionResult's
    own `requested_at` field already uses."""
    return datetime.now(timezone.utc).isoformat()
