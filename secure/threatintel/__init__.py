"""
secure/threatintel/ — Phase 20: a provider-neutral threat-intelligence
ENRICHMENT layer. "Enrichment, not ground truth" (the phase's own
explicit framing) is enforced throughout: nothing here ever upgrades
Secure's own severity/confidence, blocks anything, or is treated as an
independent detection source — it only attaches externally-sourced
reputation context to indicators (IPs, domains, file hashes) Secure
already has some other reason to care about.

    indicators.py  — pure classification (IP/domain/hash), validation,
                    and the privacy filter (is_sendable_to_network_
                    provider()) that keeps private/local information
                    from ever reaching a network-capable provider.
    extract.py     — best-effort indicator extraction from a finding's
                    own rendered message text.
    base.py        — the generic, duck-typed provider interface
                    (ProviderIdentity, ProviderLookupResult, and the
                    LookupStatus/Verdict vocabularies) every provider
                    is built on — see that module's own docstring for
                    why "never silently turn 'not found' into safe" is
                    structural here, not just a convention.
    providers/     — concrete providers: local_feed.py (offline, zero
                    network) and virustotal.py (real network API,
                    gated behind an optional API key).
    registry.py    — the one place a new provider gets registered.
    enrich.py      — orchestration: cache-first lookups
                    (enrich_indicator(), the only path that can make a
                    real/network provider call) and cache-only explain
                    wiring (attach_cached_threat_intel(), read-only,
                    never triggers a network request).

Storage: one new table, `threat_intel_lookups` (secure/storage/
database.py, secure/storage/models/threatintel.py) — every lookup
ATTEMPT is its own row (indicator, provider, timestamp, result,
confidence/score, TTL/expiration, and exact provenance of what was
requested), never overwritten, so a lookup's full history is always
inspectable, not just its latest state.

CLI: `secure threatintel lookup|history|providers` — see
secure/cli/threatintel.py. `lookup` is the ONLY command that can make a
real external request; every other surface in this app (including
explain wiring) only ever reads what's already cached.
"""

from secure.threatintel.base import (
    STATUS_ERROR,
    STATUS_NOT_FOUND,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_SKIPPED_PRIVATE,
    STATUS_UNAVAILABLE,
    VERDICT_CLEAN,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    ProviderIdentity,
    ProviderLookupResult,
)
from secure.threatintel.enrich import (
    MAX_INDICATORS_PER_EXPLANATION,
    EnrichedLookup,
    EnrichmentResult,
    attach_cached_threat_intel,
    enrich_indicator,
)
from secure.threatintel.indicators import (
    DOMAIN,
    HASH,
    IP,
    INDICATOR_TYPES,
    classify_indicator,
    is_private_or_local_ip,
    is_sendable_to_network_provider,
    normalize_indicator,
)
from secure.threatintel.registry import build_providers

__all__ = [
    "STATUS_ERROR", "STATUS_NOT_FOUND", "STATUS_OK", "STATUS_RATE_LIMITED",
    "STATUS_SKIPPED_PRIVATE", "STATUS_UNAVAILABLE",
    "VERDICT_CLEAN", "VERDICT_MALICIOUS", "VERDICT_SUSPICIOUS", "VERDICT_UNKNOWN",
    "ProviderIdentity", "ProviderLookupResult",
    "MAX_INDICATORS_PER_EXPLANATION", "EnrichedLookup", "EnrichmentResult",
    "attach_cached_threat_intel", "enrich_indicator",
    "DOMAIN", "HASH", "IP", "INDICATOR_TYPES",
    "classify_indicator", "is_private_or_local_ip", "is_sendable_to_network_provider",
    "normalize_indicator",
    "build_providers",
]
