"""
integrations/yarax/parser.py — turns yara_x's own ScanResults object
into this integration's normalized ExternalObservation shape (see
secure/integrations/base.py). Pure/duck-typed only: no engine calls, no
database, no filesystem — directly testable with hand-built fake match
objects, no yara_x installation required (mirrors
secure/integrations/osquery/parser.py's own "pure normalization" split).

yara_x's exact Python object shapes are duck-typed defensively
(`getattr(..., default)`) rather than assumed, since this integration
was built without a working yara_x install available to verify against
in this environment (see docs/INTEGRATIONS.md's yara-x section) — a
slightly different attribute name on a future yara_x version degrades
to a missing/default field here, never a crash.
"""

from __future__ import annotations

from typing import List, Optional

from secure.integrations.base import ExternalObservation
from secure.integrations.yarax.rulesets import RulesetInfo

YARA_MATCH = "yara_match"

MAX_PATTERNS_PER_MATCH = 20
MAX_OFFSETS_PER_PATTERN = 5


def normalize_metadata(raw_metadata) -> dict:
    """yara_x has exposed rule metadata as a list of (key, value) pairs
    in some versions; normalize either that or an already-dict-like
    shape into a plain dict. Anything unrecognized normalizes to {}
    rather than raising — a rule's metadata being unreadable should
    degrade that one rule's severity default, never break the scan.
    """
    if not raw_metadata:
        return {}
    if isinstance(raw_metadata, dict):
        return dict(raw_metadata)
    try:
        return dict(raw_metadata)
    except (TypeError, ValueError):
        return {}


def normalize_patterns(raw_patterns) -> List[dict]:
    """Bounded, JSON-safe summary of which patterns matched and where —
    never the full match bytes (avoids ballooning storage on a
    pattern that matches thousands of times, and avoids persisting raw
    file content fragments beyond short (identifier, offset, length)
    provenance)."""
    normalized: List[dict] = []
    for pattern in list(raw_patterns or [])[:MAX_PATTERNS_PER_MATCH]:
        identifier = getattr(pattern, "identifier", None)
        raw_matches = list(getattr(pattern, "matches", None) or [])
        offsets = [
            {"offset": getattr(m, "offset", None), "length": getattr(m, "length", None)}
            for m in raw_matches[:MAX_OFFSETS_PER_PATTERN]
        ]
        normalized.append(
            {"identifier": identifier, "match_count": len(raw_matches), "offsets": offsets}
        )
    return normalized


def parse_scan_results(
    scan_results,
    *,
    file_path: str,
    file_hash: "Optional[str]",
    ruleset_info: RulesetInfo,
    collected_at: str,
) -> List[ExternalObservation]:
    """One ExternalObservation per matching rule. A scan with zero
    matches returns an empty list — no "no match" observation is
    recorded (mirrors secure/fileintegrity/scanner.py's own "LOW/nothing
    significant stays out of the append-only alert-shaped tables"
    philosophy; the underlying file-scanned-against-this-ruleset fact is
    still visible via the integration_runs row's own summary, without
    needing one row per non-event).
    """
    observations: List[ExternalObservation] = []
    matching_rules = list(getattr(scan_results, "matching_rules", None) or [])

    identity_source = file_hash or f"path:{file_path}"

    for rule in matching_rules:
        identifier = getattr(rule, "identifier", None) or "unknown_rule"
        namespace = getattr(rule, "namespace", None) or "default"
        tags = list(getattr(rule, "tags", None) or [])
        rule_meta = normalize_metadata(getattr(rule, "metadata", None))
        patterns = normalize_patterns(getattr(rule, "patterns", None))

        identity_key = f"{identity_source}:{ruleset_info.name}:{namespace}.{identifier}"
        source_query = f"ruleset={ruleset_info.version_label} rule={namespace}.{identifier}"

        observations.append(
            ExternalObservation(
                kind=YARA_MATCH,
                identity_key=identity_key,
                fields={
                    "file_path": file_path,
                    "file_hash": file_hash,
                    "rule_name": identifier,
                    "rule_namespace": namespace,
                    "rule_tags": tags,
                    "rule_meta": rule_meta,
                    "ruleset_name": ruleset_info.name,
                    "ruleset_source_path": ruleset_info.source_path,
                    "ruleset_hash": ruleset_info.source_hash,
                    "matched_patterns": patterns,
                },
                source_query=source_query,
                collected_at=collected_at,
            )
        )

    return observations
