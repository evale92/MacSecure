"""
secure/threatintel/providers/local_feed.py — a threat-intelligence
provider backed entirely by local files the user maintains/downloads
themselves (e.g. a periodically-refreshed OSINT IOC list such as
Feodo Tracker/URLhaus-style flat exports). Zero network calls of any
kind: `identity.network = False`, so this provider is never subject to
enrich.py's private/local indicator skip (see indicators.py) — there is
nothing to leak, since nothing ever leaves this Mac.

File format, one file per indicator type, all optional (a missing file
just means zero entries of that type — routine, not an error):

    <threat_intel_local_feed_dir>/ip_feed.txt
    <threat_intel_local_feed_dir>/domain_feed.txt
    <threat_intel_local_feed_dir>/hash_feed.txt

Each is a plain text file, one entry per line:

    value[,category[,severity]]

Blank lines and lines starting with `#` are ignored. `category`
defaults to "local_feed_match" when omitted; `severity` defaults to
"suspicious" (never "malicious" by default — an operator who wants
"malicious" must say so explicitly, since a local list's own
provenance/freshness is entirely the operator's responsibility, not
independently verified by Secure).

A match is normalized to VERDICT_SUSPICIOUS or VERDICT_MALICIOUS (per
the line's own declared severity); NO match is STATUS_NOT_FOUND — this
provider never returns "clean," since a local blocklist's silence about
an indicator says nothing about that indicator's actual reputation
(Phase 20's own "never silently turn 'not found' into safe").
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

from secure.threatintel.base import (
    STATUS_NOT_FOUND,
    STATUS_OK,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    ProviderIdentity,
    ProviderLookupResult,
)
from secure.threatintel.indicators import DOMAIN, HASH, IP

IDENTITY = ProviderIdentity(name="local_feed", network=False, schema_version=1)

_FEED_FILES = {IP: "ip_feed.txt", DOMAIN: "domain_feed.txt", HASH: "hash_feed.txt"}

_DEFAULT_CATEGORY = "local_feed_match"
_DEFAULT_SEVERITY = VERDICT_SUSPICIOUS
_SEVERITY_MAP = {"suspicious": VERDICT_SUSPICIOUS, "malicious": VERDICT_MALICIOUS}


def _parse_feed_line(line: str) -> "Optional[Tuple[str, str, str]]":
    """One (value, category, verdict) tuple, or None for a blank/
    comment line. Never raises on a malformed line — a bad line is
    simply skipped, the same "one bad item doesn't abort the batch"
    discipline every other loader in this codebase uses.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = [p.strip() for p in line.split(",")]
    value = parts[0]
    if not value:
        return None
    category = parts[1] if len(parts) > 1 and parts[1] else _DEFAULT_CATEGORY
    severity_raw = parts[2].lower() if len(parts) > 2 and parts[2] else "suspicious"
    verdict = _SEVERITY_MAP.get(severity_raw, _DEFAULT_SEVERITY)
    return value, category, verdict


def _load_feed(path: Path) -> Dict[str, Tuple[str, str]]:
    """value (normalized lowercase for domain/hash, exact for ip) ->
    (category, verdict). Returns {} for a missing file — routine.
    """
    if not path.is_file():
        return {}
    entries: Dict[str, Tuple[str, str]] = {}
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            parsed = _parse_feed_line(raw_line)
            if parsed is None:
                continue
            value, category, verdict = parsed
            entries[value] = (category, verdict)
    return entries


class LocalFeedProvider:
    """Constructed once per lookup pass (feed files are small and
    change infrequently — re-reading them is cheap and always
    reflects the operator's latest edits, rather than needing a
    separate "reload" command).
    """

    identity = IDENTITY

    def __init__(self, feed_dir: Path):
        self._feed_dir = feed_dir

    def lookup(self, indicator_type: str, indicator_value: str) -> ProviderLookupResult:
        now = datetime.now(timezone.utc).isoformat()
        filename = _FEED_FILES.get(indicator_type)
        path = self._feed_dir / filename if filename else None

        if path is None:
            return ProviderLookupResult(
                indicator_type=indicator_type, indicator_value=indicator_value,
                provider=IDENTITY.name, queried_at=now, status=STATUS_NOT_FOUND,
                verdict=None, score=None, score_meaning=None, categories=(),
                raw_response=None, source_query=f"local_feed: unsupported indicator_type {indicator_type!r}",
                expires_at=None, detail="This provider does not recognize this indicator type.",
            )

        entries = _load_feed(path)
        lookup_key = indicator_value.lower() if indicator_type != IP else indicator_value
        match = entries.get(lookup_key)

        if match is None:
            return ProviderLookupResult(
                indicator_type=indicator_type, indicator_value=indicator_value,
                provider=IDENTITY.name, queried_at=now, status=STATUS_NOT_FOUND,
                verdict=None, score=None, score_meaning=None, categories=(),
                raw_response=None, source_query=str(path),
                expires_at=None,
                detail=(
                    f"No entry for this indicator in {path} — this means the local feed "
                    "has no record, not that the indicator is confirmed safe."
                ),
            )

        category, verdict = match
        return ProviderLookupResult(
            indicator_type=indicator_type, indicator_value=indicator_value,
            provider=IDENTITY.name, queried_at=now, status=STATUS_OK,
            verdict=verdict, score=None, score_meaning=None, categories=(category,),
            raw_response={"matched_file": str(path), "category": category, "declared_verdict": verdict},
            source_query=str(path),
            expires_at=None,  # local feed freshness is the operator's own responsibility — see enrich.py's default-TTL fallback
            detail=f"Matched an entry in {path} (category: {category}).",
        )


def build_provider(feed_dir: Path) -> LocalFeedProvider:
    return LocalFeedProvider(feed_dir)
