"""
secure/threatintel/base.py — the generic, provider-neutral boundary
every threat-intelligence source (a local IOC feed today, a network API
tomorrow, MISP later) is built on. Deliberately minimal, the same
"smallest generic boundary, no ABCs, no plugin registry, plain
dataclasses and string constants" discipline
secure/integrations/base.py's own docstring establishes for external
security-engine integrations — this is that same discipline applied to
a different kind of external source (a reputation LOOKUP, not a log/
telemetry COLLECTION).

Providers are duck-typed, not a formal class hierarchy: anything with
a `.identity` (a ProviderIdentity) and a `.lookup(indicator_type,
indicator_value) -> ProviderLookupResult` method is a valid provider.
This is what lets "additional reputable feeds or MISP can be added
later without changing Secure's analysis layers" (Phase 20's own
requirement) — enrich.py, explain wiring, and the CLI only ever call
these two things; a new provider module is a pure addition, registered
in registry.py, and nothing else in this codebase needs to change.

Five concepts:

    1. Identity        — ProviderIdentity: which provider this is, this
       provider MODULE's own normalized-result-shape version, and
       whether it ever makes an outbound network call (`network`) —
       the one flag enrich.py's privacy filter keys off of (see
       indicators.py's is_sendable_to_network_provider()).
    2. Lookup status    — LookupStatus: what happened when this
       provider was asked about one indicator. SIX states, deliberately
       including a status distinct from both "found and clean" and
       "couldn't check" — see NOT_FOUND's own comment below, which is
       Phase 20's own explicit "never silently turn 'not found' into
       safe" requirement made structural rather than a convention to
       remember.
    3. Verdict          — Verdict: Secure's own translated three-value
       bucket from a provider's raw response — never used unless
       status is OK.
    4. Normalized result — ProviderLookupResult: one lookup's full
       outcome, reshaped into a common shape regardless of which
       provider produced it, so callers don't need to know any one
       provider's own response format.
    5. Exact provenance — ProviderLookupResult.source_query (exactly
       what was requested — never including a secret/API key) and
       raw_response (the real, possibly-truncated payload received,
       never fabricated) — the same "exact source provenance, not a
       paraphrase" discipline Phase 15 established for
       ExternalObservation.source_query.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple

# ---------- Lookup status ----------
#
# Every one of these is a genuinely different fact, and collapsing any
# two of them together is exactly the kind of silent mistake Phase 20's
# instruction calls out by name.
STATUS_OK = "ok"                        # the provider was reached and returned a real answer
STATUS_NOT_FOUND = "not_found"          # the provider was reached; it has NO RECORD for this
                                         # indicator. NOT the same as "clean" — a provider having
                                         # no record is not the same as a provider vouching for
                                         # something. Never displayed or stored as a "safe" verdict.
STATUS_UNAVAILABLE = "unavailable"      # this provider isn't configured/reachable at all right
                                         # now — routine, not an error (e.g. no API key set).
STATUS_ERROR = "error"                  # the provider was reachable but this specific attempt
                                         # failed unexpectedly.
STATUS_RATE_LIMITED = "rate_limited"    # the provider explicitly rejected this request as
                                         # over-quota — distinct from ERROR so a caller can
                                         # decide to back off rather than treat it as broken.
STATUS_SKIPPED_PRIVATE = "skipped_private"  # enrich.py itself declined to send this indicator
                                             # to a network-capable provider because it looked
                                             # private/local — see indicators.py. The provider's
                                             # own .lookup() is never even called in this case.

_VALID_STATUSES = (
    STATUS_OK, STATUS_NOT_FOUND, STATUS_UNAVAILABLE, STATUS_ERROR,
    STATUS_RATE_LIMITED, STATUS_SKIPPED_PRIVATE,
)


# ---------- Verdict ----------
#
# Secure's OWN translated bucket — a translation of the provider's raw
# response, never a second, independent judgment (the same "translate,
# don't reinterpret" discipline Suricata's/Sigma's own severity
# classifiers already use). Only meaningful when status == STATUS_OK.
VERDICT_UNKNOWN = "unknown"
VERDICT_CLEAN = "clean"          # the provider EXPLICITLY vouches for this indicator
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_MALICIOUS = "malicious"

_VALID_VERDICTS = (VERDICT_UNKNOWN, VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS)


@dataclass(frozen=True)
class ProviderIdentity:
    """Which provider this is, and whether it ever leaves this Mac.

    `name` is a short, stable identifier (e.g. "local_feed",
    "virustotal") used as the `provider` column value wherever a
    lookup is persisted. `network` is the one flag enrich.py's privacy
    filter (indicators.py's is_sendable_to_network_provider()) keys
    off of — a provider that reads only local files (local_feed) sets
    this False and is therefore never subject to the private/local
    indicator skip, since nothing it does can leak information off this
    Mac. `schema_version` mirrors IntegrationIdentity's own field —
    bump only when this provider's OWN ProviderLookupResult shape
    changes in a way a caller needs to know about.
    """

    name: str
    network: bool
    schema_version: int = 1


@dataclass(frozen=True)
class ProviderLookupResult:
    """One provider's full, normalized outcome for one lookup.

    indicator_type/indicator_value — exactly what was looked up
        (already classified/normalized by indicators.py before this
        provider was ever called).
    provider       — ProviderIdentity.name of the provider that
        produced this result.
    queried_at     — when THIS lookup attempt happened (independent of
        when it's later persisted/read back from cache).
    status         — one of the STATUS_* constants above.
    verdict        — one of the VERDICT_* constants, or None when
        status != STATUS_OK (there is nothing to translate).
    score          — the provider's own raw reputation number, if any
        (e.g. a vote count, a 0-100 confidence score) — never
        normalized or compared across providers; None when the
        provider gave none.
    score_meaning  — a short, plain-language note of what `score` means
        for THIS specific provider (e.g. "count of security vendors
        flagging this file as malicious, out of N total") — required
        whenever `score` is not None, so a reader never has to guess
        what a bare number means.
    categories     — provider-supplied tags (e.g. ("malware", "c2")) —
        empty tuple, never None, when the provider gave none.
    raw_response   — the real (possibly truncated) normalized payload
        actually received from the provider — exact provenance, never
        fabricated; None when status prevented any response (e.g.
        UNAVAILABLE, SKIPPED_PRIVATE).
    source_query   — exactly what was requested (a URL/method, a local
        file path) — NEVER an API key or other secret.
    expires_at     — this lookup's own TTL-based cache expiration
        (ISO-8601), or None when the provider/enrich.py couldn't
        determine one (treated as "not cacheable — always re-query").
    detail         — short human-readable explanation, always
        populated, same "never make a caller guess why" discipline
        IntegrationHealth.detail already uses.
    """

    indicator_type: str
    indicator_value: str
    provider: str
    queried_at: str
    status: str
    verdict: "Optional[str]"
    score: "Optional[float]"
    score_meaning: "Optional[str]"
    categories: Tuple[str, ...]
    raw_response: "Optional[dict]"
    source_query: str
    expires_at: "Optional[str]"
    detail: str

    def __post_init__(self) -> None:
        if self.status not in _VALID_STATUSES:
            raise ValueError(f"invalid ProviderLookupResult.status: {self.status!r}")
        if self.verdict is not None and self.verdict not in _VALID_VERDICTS:
            raise ValueError(f"invalid ProviderLookupResult.verdict: {self.verdict!r}")
        if self.status != STATUS_OK and self.verdict is not None:
            raise ValueError(
                "verdict must be None unless status == STATUS_OK — a non-OK lookup has "
                "nothing for Secure to translate (this is what prevents 'not found' from "
                "ever being silently stored as a verdict)."
            )

    @property
    def found(self) -> bool:
        """True only when the provider was reached AND has a genuine
        record for this indicator. False for STATUS_NOT_FOUND just as
        much as for STATUS_ERROR/UNAVAILABLE — callers that only care
        about "is there something to show" use this; callers that need
        to distinguish "clean" from "no data" must inspect `status`
        directly, never infer it from `found`.
        """
        return self.status == STATUS_OK
