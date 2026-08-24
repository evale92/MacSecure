"""
secure/threatintel/extract.py — best-effort extraction of candidate
indicators (IPs, domains, hashes) from a finding's own rendered
message text. Pure, no I/O.

Why text scanning rather than per-source-table field mapping: every
alert explainer already builds a rendered `record.message` string (see
secure/explain/*_explainers.py) that already contains the relevant
IP/domain/hash when one exists — Suricata's own alert message includes
"TCP traffic 1.2.3.4:51000 -> 5.6.7.8:443", Zeek/YARA-X/Sigma findings
similarly render their own subject into prose. Scanning that ONE
rendered string uniformly, rather than knowing every alert table's own
column layout, is what lets explain wiring enrich ANY finding type
today, and any FUTURE finding type, without a new per-source-table
extraction rule every time — directly serving Phase 20's own "design
this so it doesn't require changing Secure's analysis layers" spirit,
applied to indicator discovery as well as to the provider interface.

This is explicitly a best-effort scan, not a guaranteed-complete
extraction: it never fabricates an indicator that isn't literally
present in the text, and a message with no recognizable indicator
simply yields an empty list — never an error, never a guess.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from secure.threatintel.indicators import classify_indicator

# Longest-first so e.g. a 64-char sha256 substring is never
# accidentally re-matched as a shorter hash after being partially
# consumed by an md5-length pattern.
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b"
)


def extract_indicators_from_text(text: str) -> List[Tuple[str, str]]:
    """Return a de-duplicated, order-preserving list of (indicator_type,
    normalized_value) pairs found in `text`. Every candidate is passed
    through classify_indicator() itself (not just the regex) so the
    same validation rules used everywhere else in this package apply
    here too — a regex match that classify_indicator() rejects (e.g. an
    IPv4-shaped string that isn't actually a valid address) is silently
    dropped, never guessed at.
    """
    if not text:
        return []

    found: "list[Tuple[str, str]]" = []
    seen = set()

    for match in _HASH_RE.finditer(text):
        value = match.group(0)
        kind = classify_indicator(value)
        if kind and (kind, value.lower()) not in seen:
            seen.add((kind, value.lower()))
            found.append((kind, value.lower()))

    for match in _IP_RE.finditer(text):
        value = match.group(0)
        kind = classify_indicator(value)
        if kind and (kind, value) not in seen:
            seen.add((kind, value))
            found.append((kind, value))

    for match in _DOMAIN_RE.finditer(text):
        value = match.group(0)
        kind = classify_indicator(value)
        if kind and (kind, value.lower()) not in seen:
            seen.add((kind, value.lower()))
            found.append((kind, value.lower()))

    return found
