"""
integrations/suricata/analysis.py — pure logic: turning one Suricata
alert's own `severity` field into Secure's severity vocabulary. No
file I/O, no database — directly testable with plain integers.

Phase 18: "Do not reproduce Suricata detection logic inside Secure."
This module doesn't decide WHETHER traffic is suspicious — Suricata's
own rule engine already made that call by emitting the alert at all.
All this does is translate Suricata's own severity scale into Secure's
three-value vocabulary, the same "translate, don't reinterpret" stance
already applied to Sigma's `level` and YARA's rule metadata.

Suricata's own severity scale (verified against Suricata's own source,
output-json-alert.c: `jb_set_uint(js, "severity", pa->s->prio)` — the
EVE `alert.severity` field is a direct copy of the RULE's own priority
value from classification.config (or an explicit `priority:` rule
keyword), NOT a Secure-facing scale invented for this integration):
LOWER numbers mean HIGHER severity — 1 is the most severe
(classification.config's default for e.g. trojan-activity), 2 is
medium, 3 is Suricata's own default for a rule with no classtype at
all ("not otherwise classified"), and unclassified/higher numbers go
lower still. This is the OPPOSITE direction from Sigma's `level` or
common intuition ("bigger number = worse"), so getting the direction
right here matters — inverting it would silently turn Suricata's own
highest-priority alerts into Secure's LOW severity.
"""

from __future__ import annotations

from typing import Optional

LOW = "low"
MEDIUM = "medium"
HIGH = "high"

_VALID_SEVERITIES = (LOW, MEDIUM, HIGH)

DEFAULT_SEVERITY = LOW


def classify_suricata_severity(raw_severity) -> str:
    """Map Suricata's own `alert.severity` integer (1=highest ...
    3+/absent=lowest) onto Secure's low/medium/high. Missing or
    non-numeric severity defaults to LOW — never assumed higher than
    LOW when Suricata itself didn't provide a usable value, the same
    non-committal-default discipline yarax/sigma's own severity
    classifiers already apply to their own missing-metadata cases.
    """
    try:
        value = int(raw_severity)
    except (TypeError, ValueError):
        return DEFAULT_SEVERITY

    if value <= 1:
        return HIGH
    if value == 2:
        return MEDIUM
    return LOW
