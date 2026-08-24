"""
secure/threatintel/enrich.py — orchestrates threat-intelligence
enrichment: cache-first lookups across every registered provider, the
privacy filter that keeps private/local indicators away from
network-capable providers, and TTL-based cache persistence. The only
file in this package that touches the database or calls a provider's
`.lookup()` — every other module here is pure classification/
normalization/translation logic.

Two entry points, deliberately serving different callers:

    enrich_indicator()  — performs REAL lookups (cache-first, but will
        make a genuine provider call, including a network request, on
        a cache miss). This is what `secure threatintel lookup` and any
        explicit, user-initiated "investigate this indicator" action
        calls — Phase 20's own "avoid unnecessary external disclosure"
        instruction is why this is never called implicitly just from
        viewing an alert.

    attach_cached_threat_intel() — CACHE-ONLY, read-only, makes no
        provider call and therefore no network request ever. This is
        what explain wiring uses (secure/explain/dispatch.py's own
        `explain()` stays 100% pure and I/O-free — this is a SEPARATE,
        optional step a caller applies to an already-built Explanation,
        never inside dispatch.py itself). Viewing an alert's explanation
        can therefore never silently trigger an external disclosure;
        only an explicit `secure threatintel lookup` call can.
"""

from __future__ import annotations

import dataclasses
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from secure.config import AppConfig
from secure.explain.explanation import EvidenceItem, Explanation
from secure.explain import vocab
from secure.threatintel import indicators as indicators_module
from secure.threatintel.base import (
    STATUS_NOT_FOUND,
    STATUS_OK,
    STATUS_SKIPPED_PRIVATE,
    ProviderLookupResult,
)
from secure.threatintel.extract import extract_indicators_from_text
from secure.threatintel.registry import build_providers
from secure.storage.models import (
    ThreatIntelLookupRecord,
    add_threat_intel_lookup,
    find_fresh_lookup,
    find_latest_lookups_for_indicator,
)

# A message can contain more hash-/IP-/domain-shaped substrings than
# are genuinely worth enriching (e.g. version numbers, unrelated
# addresses in a long correlation summary) — bounded the same
# "defensive cap, not a real-world expectation" way DEFAULT_MAX_LINES
# bounds log reads elsewhere in this codebase.
MAX_INDICATORS_PER_EXPLANATION = 5


@dataclass(frozen=True)
class EnrichedLookup:
    result: ProviderLookupResult
    from_cache: bool


@dataclass
class EnrichmentResult:
    indicator_type: str
    indicator_value: str
    lookups: Tuple[EnrichedLookup, ...] = field(default_factory=tuple)

    @property
    def any_malicious(self) -> bool:
        return any(lu.result.verdict == "malicious" for lu in self.lookups)

    @property
    def any_suspicious(self) -> bool:
        return any(lu.result.verdict == "suspicious" for lu in self.lookups)


def _record_to_result(record: ThreatIntelLookupRecord) -> ProviderLookupResult:
    return ProviderLookupResult(
        indicator_type=record.indicator_type,
        indicator_value=record.indicator_value,
        provider=record.provider,
        queried_at=record.queried_at,
        status=record.status,
        verdict=record.verdict,
        score=record.score,
        score_meaning=record.score_meaning,
        categories=record.categories,
        raw_response=record.raw_response,
        source_query=record.source_query,
        expires_at=record.expires_at,
        detail=record.detail or "",
    )


def _persist(conn: sqlite3.Connection, result: ProviderLookupResult) -> None:
    add_threat_intel_lookup(
        conn,
        indicator_type=result.indicator_type,
        indicator_value=result.indicator_value,
        provider=result.provider,
        queried_at=result.queried_at,
        status=result.status,
        verdict=result.verdict,
        score=result.score,
        score_meaning=result.score_meaning,
        categories=result.categories,
        raw_response=result.raw_response,
        source_query=result.source_query,
        expires_at=result.expires_at,
        detail=result.detail,
    )


def enrich_indicator(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    indicator_type: str,
    indicator_value: str,
    *,
    providers: "Optional[list]" = None,
    ttl_hours: "Optional[float]" = None,
    now: "Optional[datetime]" = None,
) -> EnrichmentResult:
    """Perform (or reuse a fresh cached) lookup across every registered
    provider for one indicator. Cache-first per provider — a fresh
    cached row means that provider's own `.lookup()` is never called
    again for this indicator until the cache entry expires.

    Privacy: a `network=True` provider is never even called for an
    indicator indicators.is_sendable_to_network_provider() says no to —
    a SKIPPED_PRIVATE result is recorded instead, with no external
    request made (see indicators.py's own module docstring).
    """
    now_dt = now or datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    ttl_hours = cfg.threat_intel_cache_ttl_hours if ttl_hours is None else ttl_hours
    value = indicators_module.normalize_indicator(indicator_type, indicator_value)
    active_providers = providers if providers is not None else build_providers(cfg)

    lookups: List[EnrichedLookup] = []

    for provider in active_providers:
        provider_name = provider.identity.name

        if provider.identity.network and not indicators_module.is_sendable_to_network_provider(
            indicator_type, value
        ):
            skipped = ProviderLookupResult(
                indicator_type=indicator_type, indicator_value=value, provider=provider_name,
                queried_at=now_iso, status=STATUS_SKIPPED_PRIVATE, verdict=None, score=None,
                score_meaning=None, categories=(), raw_response=None,
                source_query="(no request made — indicator looked private/local)",
                expires_at=None,
                detail=(
                    "This indicator appears to be private/local network information and was "
                    "deliberately not sent to this network-capable provider."
                ),
            )
            _persist(conn, skipped)
            lookups.append(EnrichedLookup(result=skipped, from_cache=False))
            continue

        cached = find_fresh_lookup(conn, indicator_type, value, provider_name, now=now_iso)
        if cached is not None:
            lookups.append(EnrichedLookup(result=_record_to_result(cached), from_cache=True))
            continue

        result = provider.lookup(indicator_type, value)
        expires_at = result.expires_at
        if expires_at is None and result.status in (STATUS_OK, STATUS_NOT_FOUND):
            expires_at = (now_dt + timedelta(hours=ttl_hours)).isoformat()
        result = dataclasses.replace(result, expires_at=expires_at)
        _persist(conn, result)
        lookups.append(EnrichedLookup(result=result, from_cache=False))

    return EnrichmentResult(indicator_type=indicator_type, indicator_value=value, lookups=tuple(lookups))


def _describe_cached_result(result: ProviderLookupResult) -> str:
    if result.status == STATUS_OK:
        score_note = f" (score: {result.score}, {result.score_meaning})" if result.score is not None else ""
        cat_note = f" [{', '.join(result.categories)}]" if result.categories else ""
        return (
            f"Threat intelligence ({result.provider}): {result.indicator_value} — verdict "
            f"{result.verdict}{score_note}{cat_note}. As of {result.queried_at}."
        )
    if result.status == STATUS_NOT_FOUND:
        return (
            f"Threat intelligence ({result.provider}): {result.indicator_value} — no record found. "
            "This means the provider has no data, not that it is confirmed safe."
        )
    if result.status == STATUS_SKIPPED_PRIVATE:
        return (
            f"Threat intelligence ({result.provider}): {result.indicator_value} looked private/local "
            "and was not sent to this provider."
        )
    return (
        f"Threat intelligence ({result.provider}): {result.indicator_value} — lookup status "
        f"{result.status} ({result.detail})."
    )


def attach_cached_threat_intel(conn: sqlite3.Connection, explanation: Explanation, text: str) -> Explanation:
    """Read-only, cache-only enrichment of an already-built Explanation.
    Never calls a provider, never makes a network request — see this
    module's own docstring for why that discipline matters here.

    For every candidate indicator found in `text` (bounded to
    MAX_INDICATORS_PER_EXPLANATION), adds one EvidenceItem per already-
    known provider result (however stale — staleness is stated
    honestly via the lookup's own `queried_at`, never hidden), or one
    EvidenceItem saying plainly that no lookup has been performed yet
    when nothing is cached. Returns a NEW Explanation (frozen dataclass)
    with these appended to `evidence`; the original is never mutated.
    """
    candidates = extract_indicators_from_text(text)[:MAX_INDICATORS_PER_EXPLANATION]
    if not candidates:
        return explanation

    new_items: List[EvidenceItem] = []
    for indicator_type, value in candidates:
        records = find_latest_lookups_for_indicator(conn, indicator_type, value)
        if not records:
            new_items.append(
                EvidenceItem(
                    f"No threat-intelligence lookup has been performed yet for {value} "
                    f"(detected as a possible {indicator_type} in this finding). Run "
                    f"`secure threatintel lookup {indicator_type} {value}` to check it.",
                    vocab.DERIVED_FACT,
                )
            )
            continue
        for record in records:
            result = _record_to_result(record)
            new_items.append(EvidenceItem(_describe_cached_result(result), vocab.DIRECT_OBSERVATION))

    if not new_items:
        return explanation
    return dataclasses.replace(explanation, evidence=explanation.evidence + tuple(new_items))
