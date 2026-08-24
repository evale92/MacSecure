"""
secure/threatintel/providers/virustotal.py — a real, network-capable
threat-intelligence provider (`identity.network = True`), gated behind
an optional API key (`AppConfig.virustotal_api_key`, empty by default
-> STATUS_UNAVAILABLE, never a crash — the same "absence is normal"
convention every other optional integration field in this app already
uses). Exists both as a genuinely useful provider and as concrete proof
that base.py's provider interface supports a real external network
source without any change to enrich.py, explain wiring, or the CLI —
Phase 20's own "additional reputable feeds... can be added later
without changing Secure's analysis layers" requirement.

Chosen specifically because VirusTotal's v3 API uses ONE consistent
shape (`GET /api/v3/{collection}/{id}`, an aggregate
`last_analysis_stats` vote count) across all three indicator types this
phase asks for — ip_addresses, domains, files (by hash) — making it the
highest-value single provider to build first.

This module never imports `urllib` directly — every actual network
call goes through `_http.http_get_json()` (see that module's own
docstring), so tests mock exactly one function and never make a real
network request. This dependency could not be exercised against the
real API in the sandbox this phase was built in (no network access, no
API key) — the same documented limitation yara-x's own requirements.txt
comment already accepts for a third-party dependency it couldn't
version-confirm in-sandbox; this is the analogous situation for an
external network call instead of an external package. Confirm against
a real API key before relying on this in production.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from secure.threatintel.base import (
    STATUS_ERROR,
    STATUS_NOT_FOUND,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    STATUS_UNAVAILABLE,
    VERDICT_CLEAN,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_UNKNOWN,
    ProviderIdentity,
    ProviderLookupResult,
)
from secure.threatintel.indicators import DOMAIN, HASH, IP
from secure.threatintel.providers._http import http_get_json

IDENTITY = ProviderIdentity(name="virustotal", network=True, schema_version=1)

_BASE_URL = "https://www.virustotal.com/api/v3"
_COLLECTIONS = {IP: "ip_addresses", DOMAIN: "domains", HASH: "files"}

# VirusTotal's own analysis-stats -> Secure's translated verdict.
# Translation only, per this module's own docstring — never a second,
# independent judgment about the indicator.


def _translate_verdict(stats: dict) -> "tuple[str, Optional[float], str]":
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    total = malicious + suspicious + harmless + undetected

    if malicious > 0:
        return (
            VERDICT_MALICIOUS, float(malicious),
            f"{malicious} of {total} VirusTotal-aggregated security vendors flagged this as malicious.",
        )
    if suspicious > 0:
        return (
            VERDICT_SUSPICIOUS, float(suspicious),
            f"{suspicious} of {total} VirusTotal-aggregated security vendors flagged this as suspicious.",
        )
    if total > 0:
        return (
            VERDICT_CLEAN, 0.0,
            f"0 of {total} VirusTotal-aggregated security vendors flagged this indicator.",
        )
    return VERDICT_UNKNOWN, None, "VirusTotal returned analysis data with no vendor votes recorded."


class VirusTotalProvider:
    identity = IDENTITY

    def __init__(self, api_key: str, timeout: float = 10.0):
        self._api_key = api_key
        self._timeout = timeout

    def lookup(self, indicator_type: str, indicator_value: str) -> ProviderLookupResult:
        now = datetime.now(timezone.utc).isoformat()
        collection = _COLLECTIONS.get(indicator_type)

        if not self._api_key:
            return ProviderLookupResult(
                indicator_type=indicator_type, indicator_value=indicator_value,
                provider=IDENTITY.name, queried_at=now, status=STATUS_UNAVAILABLE,
                verdict=None, score=None, score_meaning=None, categories=(), raw_response=None,
                source_query="(no request made — no API key configured)", expires_at=None,
                detail="No VirusTotal API key configured (AppConfig.virustotal_api_key).",
            )
        if collection is None:
            return ProviderLookupResult(
                indicator_type=indicator_type, indicator_value=indicator_value,
                provider=IDENTITY.name, queried_at=now, status=STATUS_ERROR,
                verdict=None, score=None, score_meaning=None, categories=(), raw_response=None,
                source_query="(no request made)", expires_at=None,
                detail=f"VirusTotal provider does not support indicator_type {indicator_type!r}.",
            )

        url = f"{_BASE_URL}/{collection}/{indicator_value}"
        # x-apikey is the ONLY place the secret is used, and it is never
        # placed in source_query/raw_response/detail — those record the
        # URL only, never the header — see base.py's own field docs on
        # source_query never containing a secret.
        result = http_get_json(url, headers={"x-apikey": self._api_key}, timeout=self._timeout)

        if result.status_code == 404:
            return ProviderLookupResult(
                indicator_type=indicator_type, indicator_value=indicator_value,
                provider=IDENTITY.name, queried_at=now, status=STATUS_NOT_FOUND,
                verdict=None, score=None, score_meaning=None, categories=(), raw_response=None,
                source_query=url, expires_at=None,
                detail="VirusTotal has no record for this indicator — not the same as confirmed clean.",
            )
        if result.status_code == 429:
            return ProviderLookupResult(
                indicator_type=indicator_type, indicator_value=indicator_value,
                provider=IDENTITY.name, queried_at=now, status=STATUS_RATE_LIMITED,
                verdict=None, score=None, score_meaning=None, categories=(), raw_response=None,
                source_query=url, expires_at=None, detail="VirusTotal rate limit exceeded for this request.",
            )
        if not result.ok or result.json is None:
            return ProviderLookupResult(
                indicator_type=indicator_type, indicator_value=indicator_value,
                provider=IDENTITY.name, queried_at=now, status=STATUS_ERROR,
                verdict=None, score=None, score_meaning=None, categories=(), raw_response=None,
                source_query=url, expires_at=None,
                detail=f"VirusTotal request failed: {result.error or 'unknown error'}.",
            )

        attributes = ((result.json.get("data") or {}).get("attributes")) or {}
        stats = attributes.get("last_analysis_stats") or {}
        verdict, score, score_meaning = _translate_verdict(stats)
        tags = tuple(attributes.get("tags") or ())

        return ProviderLookupResult(
            indicator_type=indicator_type, indicator_value=indicator_value,
            provider=IDENTITY.name, queried_at=now, status=STATUS_OK,
            verdict=verdict, score=score, score_meaning=score_meaning, categories=tags,
            raw_response={"last_analysis_stats": stats, "tags": list(tags)},
            source_query=url, expires_at=None,  # enrich.py applies the configured default TTL
            detail="VirusTotal returned an aggregated analysis result for this indicator.",
        )


def build_provider(api_key: str, timeout: float = 10.0) -> VirusTotalProvider:
    return VirusTotalProvider(api_key, timeout=timeout)
