"""
integrations/sigma/analysis.py — pure logic: turning one matched Sigma
rule's own `level` field into Secure's severity vocabulary, and the
plain-English caveat every match carries. No database, no filesystem —
directly testable with plain values.

Phase 17's explicit instruction: "keep rule matches separate from
final Secure severity/confidence decisions." A Sigma rule's `level` is
the RULE AUTHOR's own opinion (informational/low/medium/high/critical)
— useful signal, but not blindly trusted as Secure's own severity, the
same non-passthrough discipline
secure/integrations/yarax/analysis.py's classify_yara_match_severity()
already applies to YARA rule metadata.
"""

from __future__ import annotations

LOW = "low"
MEDIUM = "medium"
HIGH = "high"

_VALID_SEVERITIES = (LOW, MEDIUM, HIGH)

# Sigma's own five-level vocabulary, mapped conservatively onto
# Secure's three. Never assumes higher than "low" when a rule's level
# is absent or unrecognized — the same "non-committal default rather
# than guessing" stance yarax/analysis.py takes, adapted to Sigma's
# own vocabulary (which, unlike YARA metadata, has a defined default of
# its own — informational/low — so Secure's default here is LOW, not
# yarax's MEDIUM; Sigma rules that carry no level at all are rare and
# Sigma's own spec treats an absent level as "informational").
_LEVEL_MAP = {
    "informational": LOW,
    "info": LOW,
    "low": LOW,
    "medium": MEDIUM,
    "med": MEDIUM,
    "high": HIGH,
    "critical": HIGH,
}

DEFAULT_SEVERITY = LOW


def classify_sigma_match_severity(level) -> str:
    """Severity for one matched rule, derived from that rule's own
    declared `level` (never from anything about the matched telemetry
    itself). Unrecognized or missing level -> DEFAULT_SEVERITY (low),
    never assumed higher.
    """
    if level is None:
        return DEFAULT_SEVERITY
    mapped = _LEVEL_MAP.get(str(level).strip().lower())
    return mapped if mapped in _VALID_SEVERITIES else DEFAULT_SEVERITY


def level_is_recognized(level) -> bool:
    if level is None:
        return False
    return str(level).strip().lower() in _LEVEL_MAP


def match_interpretation_note(rule_title: str, level, recognized: bool, description) -> str:
    """The caveat attached to every Sigma match, regardless of
    severity — a rule match reports that Secure's own telemetry
    satisfies that rule's condition, not an independent malware or
    intrusion determination.
    """
    parts = [
        f"Sigma rule '{rule_title}' matched telemetry Secure collected — this reports "
        "that the rule's condition was satisfied, not an independent malware or "
        "intrusion determination. Many legitimate activities can satisfy broad "
        "detection rules."
    ]
    if not recognized:
        parts.append(
            "This rule did not declare a recognized severity level, so Secure used "
            "its own non-committal default rather than guessing."
        )
    if description:
        parts.append(f"Rule description: {description}")
    return " ".join(parts)
