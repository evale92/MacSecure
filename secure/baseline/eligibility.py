"""
secure/baseline/eligibility.py — Phase 14 poisoning-protection rules.

Pure function, no I/O: given what's already known about one entity at
the moment of one observation, decide whether that observation counts
toward "clean" baseline statistics, and exactly why. The reasoning is
deliberately forward-only — see classify_eligibility()'s docstring —
so a later review of an old finding can never retroactively launder a
long run of unresolved history into "normal" all at once (Phase 14
approval item 12's poisoning test: historical unresolved observations
"remain visible but do not retroactively become clean training data").
"""

from __future__ import annotations

from typing import Sequence, Tuple

from secure.baseline.constants import EXCLUDED_WEIGHT, FULL_WEIGHT, MEDIUM_ALERT_WEIGHT

# Eligibility reasons (Phase 14 approval item 6) — every observation
# gets exactly one of these, stored alongside it, so a later
# explanation can say precisely why it did or didn't train the
# baseline (see secure/storage/models.py's baseline_activity writer
# and the feature-stat writers in secure/baseline/engine.py, plus
# secure/explain/baseline_explainer.py).
ELIGIBLE = "eligible"
UNREVIEWED_HIGH_ALERT = "unreviewed_high_alert"
UNREVIEWED_CRITICAL_ALERT = "unreviewed_critical_alert"
UNREVIEWED_MEDIUM_ALERT_HALF_WEIGHT = "unreviewed_medium_alert_half_weight"
EXCLUDED_ENTITY = "excluded_entity"
PARTIAL_SENSOR_DATA = "partial_sensor_data"

ELIGIBILITY_REASONS = (
    ELIGIBLE,
    UNREVIEWED_HIGH_ALERT,
    UNREVIEWED_CRITICAL_ALERT,
    UNREVIEWED_MEDIUM_ALERT_HALF_WEIGHT,
    EXCLUDED_ENTITY,
    PARTIAL_SENSOR_DATA,
)

_WEIGHTS = {
    ELIGIBLE: FULL_WEIGHT,
    UNREVIEWED_HIGH_ALERT: EXCLUDED_WEIGHT,
    UNREVIEWED_CRITICAL_ALERT: EXCLUDED_WEIGHT,
    UNREVIEWED_MEDIUM_ALERT_HALF_WEIGHT: MEDIUM_ALERT_WEIGHT,
    EXCLUDED_ENTITY: EXCLUDED_WEIGHT,
    PARTIAL_SENSOR_DATA: EXCLUDED_WEIGHT,
}


def weight_for_reason(reason: str) -> float:
    """The numeric weight (1.0 / 0.5 / 0.0) a given eligibility reason implies."""
    return _WEIGHTS[reason]


def classify_eligibility(
    *,
    excluded: bool = False,
    partial_sensor_data: bool = False,
    unreviewed_alert_severities: Sequence[str] = (),
) -> Tuple[str, float]:
    """Decide the eligibility reason (and its weight) for ONE observation.

    Called at the moment an observation is recorded, using ONLY the
    state known at that moment — this is what makes eligibility
    forward-only. Reviewing an alert later changes what
    `unreviewed_alert_severities` will contain for FUTURE observations
    of this entity; it never rewrites a reason/weight already stored
    on a past observation.

    Priority order (first match wins):
      1. excluded_entity — the user explicitly excluded this entity
         from anomaly analysis (`secure baseline exclude`). Weight 0.0.
      2. partial_sensor_data — this scan could not fully see this
         entity (a permission error, an incomplete walk, a sensor that
         returned no data this run). An absence or presence observed
         under partial visibility must never be treated as a reliable
         "normal" data point. Weight 0.0.
      3. unreviewed_critical_alert / unreviewed_high_alert — an
         unresolved HIGH or CRITICAL finding exists for this entity
         right now. Frequency alone must never turn an unresolved
         serious finding into "normal" (approval items 6 and 12).
         Weight 0.0.
      4. unreviewed_medium_alert_half_weight — an unresolved MEDIUM
         finding exists; still counted, but at half weight rather than
         full exclusion. Weight 0.5.
      5. eligible — none of the above. Weight 1.0.
    """
    if excluded:
        return EXCLUDED_ENTITY, weight_for_reason(EXCLUDED_ENTITY)
    if partial_sensor_data:
        return PARTIAL_SENSOR_DATA, weight_for_reason(PARTIAL_SENSOR_DATA)

    severities = {str(s).strip().lower() for s in unreviewed_alert_severities}
    if "critical" in severities:
        return UNREVIEWED_CRITICAL_ALERT, weight_for_reason(UNREVIEWED_CRITICAL_ALERT)
    if "high" in severities:
        return UNREVIEWED_HIGH_ALERT, weight_for_reason(UNREVIEWED_HIGH_ALERT)
    if "medium" in severities:
        return (
            UNREVIEWED_MEDIUM_ALERT_HALF_WEIGHT,
            weight_for_reason(UNREVIEWED_MEDIUM_ALERT_HALF_WEIGHT),
        )

    return ELIGIBLE, weight_for_reason(ELIGIBLE)
