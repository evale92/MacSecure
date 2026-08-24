"""
secure/baseline/scoring.py — Phase 14's deterministic anomaly-score
components. Pure functions, no I/O, no randomness, no reference to the
current wall clock except through explicit `now` parameters.

Five components, exactly as approved (Phase 14 approval item 8), each
a plain number derived from a plain comparison against already-stored
statistics — never subjective prose:

    RARITY            (0-40)  how much of this entity's own rolling
                                activity for this feature belongs to
                                this specific value.
    RECENCY           (0-15)  a previously-common value gone quiet.
                                Mutually exclusive with RARITY's
                                "never seen" case — see
                                score_rarity_and_recency()'s docstring.
    BEHAVIOR_CHANGE   (0-20)  a specific, documented categorical
                                transition (signed->unsigned, etc.) —
                                never a generic field diff.
    SECURITY_CONTEXT  (0-15)  additive flags reusing EXISTING detector
                                output only (an unreviewed alert, an
                                unsigned binary, a network-exposed bind) —
                                scoring.py never re-derives detection.
    TIME_DEVIATION    (0-10)  gated by its own maturity requirement,
                                independent of the entity's overall
                                maturity_state — see
                                score_time_deviation()'s docstring.

On BEHAVIOR_CHANGE vs. SECURITY_CONTEXT double-counting (approval item
8's explicit warning): these can legitimately both contribute points
for the same observation, because they answer different questions.
Example — a persistence entry's backing executable was signed
yesterday and is unsigned today:
    BEHAVIOR_CHANGE fires (+20): the STATE CHANGED since last observed.
    SECURITY_CONTEXT fires (+5): the CURRENT state is unsigned, which
        is worth flagging regardless of history — an executable that
        has ALWAYS been unsigned also gets this +5, on every
        observation, forever, with no transition involved at all.
A process that has been unsigned since day one gets +5
(SECURITY_CONTEXT) but never +20 (BEHAVIOR_CHANGE, since there's no
transition) — the two components are independent facts, not two views
of the same fact, so both may contribute without inflating the score
for one real event.

Every function here takes the PRIOR statistics (before the current
observation is folded in) — see secure/baseline/engine.py, which is
responsible for scoring an observation BEFORE updating the stored
stats with it, never after.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional

from secure.baseline.constants import (
    ANOMALY_TIER_CRITICAL,
    ANOMALY_TIER_HIGH,
    ANOMALY_TIER_LOW,
    ANOMALY_TIER_MEDIUM,
    ANOMALY_TIER_NONE,
    BEHAVIOR_CHANGE_POINTS,
    IMMATURE_TIER_CAP,
    RARITY_LOW_SHARE,
    RARITY_LOW_SHARE_THRESHOLD,
    RARITY_MODERATE_SHARE,
    RARITY_MODERATE_SHARE_THRESHOLD,
    RARITY_NEVER_SEEN,
    RECENCY_QUIET_GAP_DAYS,
    RECENCY_QUIET_POINTS,
    RECENCY_STALE_GAP_DAYS,
    RECENCY_STALE_POINTS,
    SCORE_TIER_HIGH_MAX,
    SCORE_TIER_LOW_MAX,
    SCORE_TIER_MEDIUM_MAX,
    SCORE_TIER_NONE_MAX,
    SECURITY_CONTEXT_NETWORK_BIND_POINTS,
    SECURITY_CONTEXT_UNREVIEWED_ALERT_POINTS,
    SECURITY_CONTEXT_UNSIGNED_POINTS,
    SECURITY_CONTEXT_WEAK_WIFI_POINTS,
    STALE_TIER_CAP,
    TIME_DEVIATION_LOW_SHARE,
    TIME_DEVIATION_LOW_SHARE_THRESHOLD,
    TIME_DEVIATION_NEVER_SEEN,
    TIME_MIN_DISTINCT_DAYS,
    TIME_MIN_OBSERVATIONS,
)
from secure.baseline.maturity import ESTABLISHED, LEARNING, NO_BASELINE, STALE

# Mirrors secure.persistence.codesign's real signing_status vocabulary
# (SIGNED_APPLE="signed_apple", SIGNED_DEVELOPER="signed_developer",
# SIGNED_ADHOC="signed_adhoc", UNSIGNED="unsigned", UNKNOWN="unknown")
# as plain string literals rather than an import, since
# secure.persistence already imports FROM secure.baseline (see
# scanner.py's use of record_gap_observation/evaluate_and_record_
# feature_observation) — importing codesign.py's constants here would
# create a cycle. codesign.py's own docs: ad-hoc signatures are
# "treated as alert-worthy just like unsigned" (trivial for anything,
# including malware, to produce), so both count as "unsigned-like"
# here; "unknown" means codesign itself never ran and is handled
# upstream as partial_sensor_data, never reaching this function as an
# observed value at all.
_PROPERLY_SIGNED_STATUSES = {"signed_apple", "signed_developer"}
_UNSIGNED_LIKE_STATUSES = {"unsigned", "signed_adhoc"}


def _parse(iso_string: str) -> datetime:
    dt = datetime.fromisoformat(iso_string)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def score_rarity_and_recency(
    *,
    prior_value_weight: float,
    prior_total_feature_weight: float,
    prior_last_seen: "Optional[str]",
    now: "Optional[datetime]" = None,
) -> "Dict[str, int]":
    """RARITY + RECENCY for one feature_value, from the PRIOR rolling
    stats (before this observation is added). Returns
    {"rarity": int, "recency": int} — recency is always 0 when rarity
    is RARITY_NEVER_SEEN, since a value with zero prior weight has no
    "last seen" gap to measure (they describe the same fact from two
    angles, so only one may fire per approval item 8).
    """
    now = now or datetime.now(timezone.utc)

    if prior_value_weight <= 0:
        return {"rarity": RARITY_NEVER_SEEN, "recency": 0}

    share = prior_value_weight / prior_total_feature_weight if prior_total_feature_weight > 0 else 0.0
    if share < RARITY_LOW_SHARE_THRESHOLD:
        rarity = RARITY_LOW_SHARE
    elif share < RARITY_MODERATE_SHARE_THRESHOLD:
        rarity = RARITY_MODERATE_SHARE
    else:
        rarity = 0

    recency = 0
    if prior_last_seen is not None:
        gap_days = (now - _parse(prior_last_seen)).days
        if gap_days > RECENCY_STALE_GAP_DAYS:
            recency = RECENCY_STALE_POINTS
        elif gap_days > RECENCY_QUIET_GAP_DAYS:
            recency = RECENCY_QUIET_POINTS

    return {"rarity": rarity, "recency": recency}


def score_signing_status_behavior_change(previous_dominant: "Optional[str]", observed: "Optional[str]") -> int:
    """+BEHAVIOR_CHANGE_POINTS only for a properly-signed -> unsigned/
    ad-hoc transition ("signed_apple"/"signed_developer" -> "unsigned"/
    "signed_adhoc"). `previous_dominant` is the feature_value with the
    highest prior lifetime weight for this entity's
    feature_name="signing_status" (i.e. what this entity has USUALLY
    shown) — not merely the single most recent observation, so one
    already-unsigned re-observation right after an unsigned one
    doesn't get treated as a fresh "change".
    """
    if previous_dominant in _PROPERLY_SIGNED_STATUSES and observed in _UNSIGNED_LIKE_STATUSES:
        return BEHAVIOR_CHANGE_POINTS
    return 0


def score_bind_scope_behavior_change(previous_dominant: "Optional[str]", observed: "Optional[str]") -> int:
    """+BEHAVIOR_CHANGE_POINTS only for a localhost -> network bind-scope
    transition — matches secure.listening.bind_scope.classify_bind_scope()'s
    actual two-value vocabulary ("localhost"/"network"), not a
    three-tier network/private/loopback scheme.
    """
    if previous_dominant == "localhost" and observed == "network":
        return BEHAVIOR_CHANGE_POINTS
    return 0


def score_wifi_security_behavior_change(previous_dominant: "Optional[str]", observed: "Optional[str]") -> int:
    """+BEHAVIOR_CHANGE_POINTS only for a secured -> open/none security-type transition."""
    if previous_dominant not in (None, "open", "none") and observed in ("open", "none"):
        return BEHAVIOR_CHANGE_POINTS
    return 0


_BEHAVIOR_CHANGE_RULES = {
    "signing_status": score_signing_status_behavior_change,
    "bind_scope": score_bind_scope_behavior_change,
    "security": score_wifi_security_behavior_change,
}


def score_behavior_change(feature_name: str, previous_dominant: "Optional[str]", observed: "Optional[str]") -> int:
    """Dispatch to the documented rule for this feature_name, or 0 for
    every feature_name with no documented behavior-change rule —
    scoring.py never falls back to a generic diff.
    """
    rule = _BEHAVIOR_CHANGE_RULES.get(feature_name)
    if rule is None:
        return 0
    return rule(previous_dominant, observed)


def score_security_context(
    *,
    has_unreviewed_alert: bool = False,
    is_unsigned: bool = False,
    is_network_bind: bool = False,
    is_weak_wifi_security: bool = False,
) -> int:
    """Additive flags, each reusing an existing detector's output
    directly rather than re-deriving anything (is_weak_wifi_security
    reuses secure.wifi.security_level.classify_security()'s verdict,
    passed in by the caller — scoring.py never re-implements it). Every
    flag here reflects a CURRENT, persistent condition — fires on
    every observation while the condition holds, independent of
    whether it just changed (that's BEHAVIOR_CHANGE's job) — see this
    module's docstring.
    """
    points = 0
    if has_unreviewed_alert:
        points += SECURITY_CONTEXT_UNREVIEWED_ALERT_POINTS
    if is_unsigned:
        points += SECURITY_CONTEXT_UNSIGNED_POINTS
    if is_network_bind:
        points += SECURITY_CONTEXT_NETWORK_BIND_POINTS
    if is_weak_wifi_security:
        points += SECURITY_CONTEXT_WEAK_WIFI_POINTS
    return points


def is_time_dimension_mature(*, total_time_weight: float, distinct_days_observed: int) -> bool:
    """The TIME dimension has its OWN maturity gate, independent of the
    entity's overall maturity_state (approval item 9) — an entity's
    activity can be evenly spread through the day (fast temporal
    maturity) or lopsided (slow), regardless of how much overall
    history exists.
    """
    return (
        total_time_weight >= TIME_MIN_OBSERVATIONS
        and distinct_days_observed >= TIME_MIN_DISTINCT_DAYS
    )


def score_time_deviation(
    *, prior_bucket_weight: float, prior_total_time_weight: float, mature: bool
) -> int:
    """TIME_DEVIATION from the PRIOR time-of-day stats. Always 0 when
    `mature` is False — "do not score time deviation when historical
    coverage is insufficient" (approval item 9) — the caller
    (secure/explain/baseline_explainer.py) is responsible for saying
    so honestly rather than presenting a silent 0 as "normal timing".
    """
    if not mature:
        return 0
    if prior_bucket_weight <= 0:
        return TIME_DEVIATION_NEVER_SEEN
    share = (
        prior_bucket_weight / prior_total_time_weight if prior_total_time_weight > 0 else 0.0
    )
    if share < TIME_DEVIATION_LOW_SHARE_THRESHOLD:
        return TIME_DEVIATION_LOW_SHARE
    return 0


def tier_for_score(raw_score: int) -> str:
    """Map a 0-100 raw score to a named tier via plain numeric bounds."""
    if raw_score <= SCORE_TIER_NONE_MAX:
        return ANOMALY_TIER_NONE
    if raw_score <= SCORE_TIER_LOW_MAX:
        return ANOMALY_TIER_LOW
    if raw_score <= SCORE_TIER_MEDIUM_MAX:
        return ANOMALY_TIER_MEDIUM
    if raw_score <= SCORE_TIER_HIGH_MAX:
        return ANOMALY_TIER_HIGH
    return ANOMALY_TIER_CRITICAL


_TIER_RANK = {
    ANOMALY_TIER_NONE: 0,
    ANOMALY_TIER_LOW: 1,
    ANOMALY_TIER_MEDIUM: 2,
    ANOMALY_TIER_HIGH: 3,
    ANOMALY_TIER_CRITICAL: 4,
}


def apply_maturity_cap(tier: str, maturity_state: str) -> str:
    """Cap the tier based on baseline maturity — never a score
    multiplier (approval item 4 explicitly removed the previously
    proposed 0.7 multiplier for STALE baselines in favor of this kind
    of cap). NO_BASELINE/LEARNING can never exceed LOW; STALE can never
    exceed MEDIUM. ESTABLISHED applies no cap.
    """
    if maturity_state in (NO_BASELINE, LEARNING):
        cap = IMMATURE_TIER_CAP
    elif maturity_state == STALE:
        cap = STALE_TIER_CAP
    else:
        return tier
    if _TIER_RANK[tier] > _TIER_RANK[cap]:
        return cap
    return tier


def combine(components: "Dict[str, int]", maturity_state: str) -> "tuple[int, str]":
    """Sum every component into raw_score (0-100), map to a tier, then
    apply the maturity cap. Returns (raw_score, final_tier).
    """
    raw_score = sum(components.values())
    raw_score = max(0, min(100, raw_score))
    tier = tier_for_score(raw_score)
    tier = apply_maturity_cap(tier, maturity_state)
    return raw_score, tier
