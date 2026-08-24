"""
integrations/yarax/analysis.py — pure logic: turning one YARA rule
match's own metadata into Secure's severity vocabulary, and building
the plain-English caveat every match carries. No engine calls, no
database, no filesystem — every function here takes plain values and
returns plain values, directly testable without yara_x installed.

The core discipline this file exists to enforce (Phase 16's explicit
instruction): **a YARA match is a report that a file has certain
characteristics a rule looks for — never an automatic malware
classification.** Severity here answers "how seriously does Secure's
own scoring treat this," not "is this malicious" — that judgment stays
with the person reviewing it, same as every other finding in this app
(see secure/explain/__init__.py's confidence discipline).
"""

from __future__ import annotations

from typing import Optional

LOW = "low"
MEDIUM = "medium"
HIGH = "high"

_VALID_SEVERITIES = (LOW, MEDIUM, HIGH)

# Recognized rule metadata keys, checked in this order. Community/public
# YARA rulesets commonly carry one of these under `meta:` — when present
# and a recognized value, it's used AS THE RULE AUTHOR'S OWN estimate,
# not Secure's; when absent or unrecognized, Secure falls back to a
# deliberately non-committal default (see classify_yara_match_severity()).
_SEVERITY_META_KEYS = ("severity", "threat_level", "threatlevel")

# A coarse, deliberately conservative mapping for numeric/word variants
# real-world rulesets use for the above keys.
_SEVERITY_WORD_MAP = {
    "low": LOW, "info": LOW, "informational": LOW,
    "medium": MEDIUM, "med": MEDIUM, "moderate": MEDIUM, "suspicious": MEDIUM,
    "high": HIGH, "critical": HIGH, "malware": HIGH, "malicious": HIGH,
    "1": LOW, "2": MEDIUM, "3": HIGH,
}

DEFAULT_SEVERITY = MEDIUM


def classify_yara_match_severity(rule_meta: dict) -> str:
    """Severity for one rule match, derived only from that rule's own
    declared metadata (never from the file itself, never assumed).

    Checks `_SEVERITY_META_KEYS` in order (case-insensitive key match);
    the first recognized value wins. A ruleset with no severity-like
    metadata at all — very common; plenty of legitimate YARA rules just
    flag "matches this pattern" with no built-in severity opinion — gets
    `DEFAULT_SEVERITY` (medium): worth a look, but deliberately not
    alarmist by default, per "do not automatically classify every match
    as malware."
    """
    lowered = {str(k).lower(): v for k, v in rule_meta.items()}
    for key in _SEVERITY_META_KEYS:
        if key in lowered:
            value = str(lowered[key]).strip().lower()
            mapped = _SEVERITY_WORD_MAP.get(value)
            if mapped in _VALID_SEVERITIES:
                return mapped
    return DEFAULT_SEVERITY


def match_interpretation_note(rule_meta: dict, had_recognized_severity: bool) -> str:
    """The caveat attached to every match's evidence, regardless of
    severity — always present, never conditional on severity being
    high, because the "this is not a malware verdict" boundary applies
    equally to every match.
    """
    author = rule_meta.get("author") or rule_meta.get("Author")
    description = rule_meta.get("description") or rule_meta.get("Description")

    parts = [
        "A YARA rule match reports that a file has characteristics the "
        "rule's author chose to look for — it is not, by itself, a "
        "malware determination. Many legitimate files legitimately "
        "match rules aimed at packers, obfuscation techniques, or other "
        "broad heuristics."
    ]
    if not had_recognized_severity:
        parts.append(
            "This rule did not declare its own severity/threat-level metadata, "
            "so Secure used its own non-committal default rather than guessing."
        )
    if description:
        parts.append(f"Rule description: {description}")
    if author:
        parts.append(f"Rule author: {author}")
    return " ".join(parts)


def rule_meta_has_recognized_severity(rule_meta: dict) -> bool:
    lowered = {str(k).lower(): v for k, v in rule_meta.items()}
    for key in _SEVERITY_META_KEYS:
        if key in lowered:
            value = str(lowered[key]).strip().lower()
            if _SEVERITY_WORD_MAP.get(value) in _VALID_SEVERITIES:
                return True
    return False
