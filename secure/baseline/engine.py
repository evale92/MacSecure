"""
secure/baseline/engine.py — orchestrates feature-level history and
deterministic anomaly scoring (Stage 3). Touches the database only by
calling secure.storage.models and secure.baseline.history functions —
no raw SQL lives here (same "scanner.py orchestrates, models.py holds
the SQL" split every other package in this project already uses).

Two independent things this module does:

    1. record/score feature observations for the THREE feature
       dimensions with no other history to read from (process/
       persistence signing_status, listening bind_scope, Wi-Fi
       security type) — see database.py's schema comment on
       baseline_feature_activity for why exactly these three, and
       ZERO BACKFILL: history for these three starts the moment this
       code first runs, never fabricated from prior entity state.
    2. score_process_destination_rarity() — the sibling-relative
       rarity comparison for `process_destination` entities (Phase 14
       extension approval item 7): a destination's rarity is judged
       against how much of the OWNING PROCESS's total destination
       activity it represents, not against its own single-value
       history (a process_destination entity only ever has one
       "destination" value by construction, so a within-entity
       comparison would be meaningless).

Scoring discipline used throughout: every score is computed from PRIOR
statistics (before the observation being scored is folded in) — so
scoring always happens before the corresponding record_*() call, never
after. evaluate_and_record_feature_observation() enforces this
ordering in one call so a caller can't get it backwards.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from secure.baseline import maturity, scoring, time_buckets
from secure.baseline.constants import ANOMALY_TIER_NONE, RARITY_NEVER_SEEN, ROLLING_WINDOW_DAYS
from secure.baseline.eligibility import classify_eligibility
from secure.baseline.history import record_entity_observation, unreviewed_alert_severities_for_entity
from secure.storage.models import (
    add_anomaly_event,
    add_baseline_feature_activity,
    add_baseline_run,
    find_baseline_entity,
    find_baseline_feature_maturity,
    get_baseline_feature_stat,
    list_baseline_entities,
    list_baseline_feature_stats,
    record_feature_maturity_observation,
    set_baseline_feature_maturity_state,
    upsert_baseline_feature_stat,
)

# The five named score components that belong in anomaly_events.score_breakdown
# — everything else in a score_feature_observation()/score_process_destination_rarity()
# breakdown dict (raw_score, tier, feature_maturity_state, previous_dominant,
# time_bucket, entity_maturity_state, sibling_count, process_name) is either
# already stored in its own column or is call-site bookkeeping that doesn't
# belong in the reproducible-from-named-rules JSON blob (see database.py's
# schema comment on anomaly_events).
_SCORE_COMPONENT_KEYS = ("rarity", "recency", "behavior_change", "security_context", "time_deviation")


def _score_components_only(breakdown: Dict) -> Dict:
    return {k: breakdown[k] for k in _SCORE_COMPONENT_KEYS if k in breakdown}


def _build_expected_summary(feature_name: str, breakdown: Dict) -> str:
    """One deterministic sentence describing what the baseline expected,
    built only from fields score_feature_observation()/
    score_process_destination_rarity() already computed — never a
    second interpretation layer, never prose pulled from elsewhere."""
    previous_dominant = breakdown.get("previous_dominant")
    if previous_dominant is None:
        return f"No prior {feature_name} history exists for this entity yet."
    if breakdown["rarity"] == RARITY_NEVER_SEEN:
        return (
            f"This {feature_name} value has not been observed before; "
            f"the historically dominant value is {previous_dominant!r}."
        )
    return f"Historically dominant {feature_name} value: {previous_dominant!r}."


def maybe_record_anomaly_event(
    conn: sqlite3.Connection,
    run_id: str,
    entity_type: str,
    entity_key: str,
    feature_name: str,
    observed_value: "Optional[str]",
    observed_at: str,
    breakdown: Dict,
    maturity_state_at_time: str,
    eligible_weight_total_at_time: float,
    eligible_distinct_days_at_time: int,
    *,
    source_table: "Optional[str]" = None,
    source_id: "Optional[int]" = None,
):
    """Persist one anomaly finding from an already-computed breakdown —
    never re-scores anything. Returns None (and writes nothing) when
    the tier is 'none': a clean/expected observation is not a noisy
    audit row (Stage 4 approval item 1). Idempotent via
    add_anomaly_event()'s (run_id, entity_type, entity_key,
    feature_name) dedup key — see that function's docstring.
    """
    tier = breakdown["tier"]
    if tier == ANOMALY_TIER_NONE:
        return None

    expected_summary = _build_expected_summary(feature_name, breakdown)
    event, _was_new = add_anomaly_event(
        conn, run_id, entity_type, entity_key, feature_name, observed_value, observed_at,
        expected_summary, _score_components_only(breakdown), breakdown["raw_score"], tier,
        maturity_state_at_time, eligible_weight_total_at_time, eligible_distinct_days_at_time,
        source_table=source_table, source_id=source_id,
    )
    return event

# feature_name -> which scoring.score_*_behavior_change rule applies,
# already dispatched generically by scoring.score_behavior_change() —
# kept here only as the single source of truth for which THREE feature
# dimensions this engine is allowed to log/score at all (Phase 14
# extension approval item 4: "do not opportunistically start logging
# every available field").
SUPPORTED_FEATURES = {
    ("persistence", "signing_status"),
    ("listening", "bind_scope"),
    ("wifi", "security"),
}


def _now(now: "Optional[datetime]") -> datetime:
    return now or datetime.now(timezone.utc)


def _parse(iso_string: str) -> datetime:
    dt = datetime.fromisoformat(iso_string)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _prior_feature_value_stats(
    conn: sqlite3.Connection, entity_type: str, entity_key: str, feature_name: str, feature_value: str
) -> "tuple[float, float, Optional[str]]":
    """(prior_value_weight, prior_total_feature_weight, prior_last_seen)
    for one feature_value, from whatever baseline_feature_stats already
    holds (i.e. NOT including the observation about to be scored).
    """
    all_stats = list_baseline_feature_stats(conn, entity_type, entity_key, feature_name)
    total = sum(s.rolling_weight_total for s in all_stats)
    this_value = next((s for s in all_stats if s.feature_value == feature_value), None)
    if this_value is None:
        return 0.0, total, None
    return this_value.rolling_weight_total, total, this_value.last_seen


def _previous_dominant_value(
    conn: sqlite3.Connection, entity_type: str, entity_key: str, feature_name: str
) -> "Optional[str]":
    """The feature_value with the highest LIFETIME weight for this
    (entity, feature_name) — "what this entity has usually shown" —
    used by behavior-change scoring so a single re-observation of an
    already-unsigned binary isn't treated as a fresh transition.
    """
    all_stats = list_baseline_feature_stats(conn, entity_type, entity_key, feature_name)
    if not all_stats:
        return None
    dominant = max(all_stats, key=lambda s: s.lifetime_weight_total)
    return dominant.feature_value if dominant.lifetime_weight_total > 0 else None


def _prior_time_bucket_stats(
    conn: sqlite3.Connection, entity_type: str, entity_key: str, bucket: str
) -> "tuple[float, float, bool]":
    from secure.storage.models import get_baseline_time_stat

    stat = get_baseline_time_stat(conn, entity_type, entity_key)
    if stat is None:
        return 0.0, 0.0, False
    bucket_weight = getattr(stat, f"{bucket}_weight")
    mature = scoring.is_time_dimension_mature(
        total_time_weight=stat.total_weight, distinct_days_observed=stat.distinct_days_observed
    )
    return bucket_weight, stat.total_weight, mature


def score_feature_observation(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_key: str,
    feature_name: str,
    feature_value: str,
    observed_at: str,
    *,
    is_unsigned: bool = False,
    is_network_bind: bool = False,
    is_weak_wifi_security: bool = False,
    now: "Optional[datetime]" = None,
) -> Dict:
    """Score one feature observation against PRIOR stats. Must be called
    BEFORE the observation is recorded (see evaluate_and_record_feature_observation()).
    Returns a breakdown dict: {"rarity", "recency", "behavior_change",
    "security_context", "time_deviation", "raw_score", "tier",
    "feature_maturity_state"}.
    """
    now = _now(now)

    prior_value_weight, prior_total_weight, prior_last_seen = _prior_feature_value_stats(
        conn, entity_type, entity_key, feature_name, feature_value
    )
    rarity_recency = scoring.score_rarity_and_recency(
        prior_value_weight=prior_value_weight,
        prior_total_feature_weight=prior_total_weight,
        prior_last_seen=prior_last_seen,
        now=now,
    )

    previous_dominant = _previous_dominant_value(conn, entity_type, entity_key, feature_name)
    behavior_change = scoring.score_behavior_change(feature_name, previous_dominant, feature_value)

    unreviewed = unreviewed_alert_severities_for_entity(conn, entity_type, entity_key)
    has_unreviewed = any(s.lower() in ("medium", "high", "critical") for s in unreviewed)
    security_context = scoring.score_security_context(
        has_unreviewed_alert=has_unreviewed, is_unsigned=is_unsigned, is_network_bind=is_network_bind,
        is_weak_wifi_security=is_weak_wifi_security,
    )

    bucket, _is_weekend = time_buckets.classify(observed_at)
    bucket_weight, total_time_weight, mature = _prior_time_bucket_stats(conn, entity_type, entity_key, bucket)
    time_deviation = scoring.score_time_deviation(
        prior_bucket_weight=bucket_weight, prior_total_time_weight=total_time_weight, mature=mature
    )

    feature_maturity_row = find_baseline_feature_maturity(conn, entity_type, entity_key, feature_name)
    feature_maturity_state = feature_maturity_row.maturity_state if feature_maturity_row else maturity.NO_BASELINE

    components = {
        "rarity": rarity_recency["rarity"],
        "recency": rarity_recency["recency"],
        "behavior_change": behavior_change,
        "security_context": security_context,
        "time_deviation": time_deviation,
    }
    raw_score, tier = scoring.combine(components, feature_maturity_state)

    return {
        **components,
        "raw_score": raw_score,
        "tier": tier,
        "feature_maturity_state": feature_maturity_state,
        "previous_dominant": previous_dominant,
        "time_bucket": bucket,
    }


def _update_feature_stats_after_activity(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_key: str,
    feature_name: str,
    feature_value: str,
    observed_at: str,
    weight: float,
    now: datetime,
) -> None:
    """Increment lifetime counters in place; recompute rolling counters
    from baseline_feature_activity via a bounded query scoped to this
    one (entity, feature_name, feature_value) — cheap, and avoids the
    fragile incremental-decrement math a "rolling window" would
    otherwise need (see baseline_feature_stats' schema comment).
    """
    existing = get_baseline_feature_stat(conn, entity_type, entity_key, feature_name, feature_value)
    observed_date = observed_at[:10]

    if existing is None:
        lifetime_weight_total = weight
        lifetime_distinct_days = 1
        first_seen = observed_at
    else:
        is_new_day = existing.last_seen[:10] != observed_date
        lifetime_weight_total = existing.lifetime_weight_total + weight
        lifetime_distinct_days = existing.lifetime_distinct_days + (1 if is_new_day else 0)
        first_seen = existing.first_seen

    cutoff = (now - timedelta(days=ROLLING_WINDOW_DAYS)).isoformat()
    rows = conn.execute(
        "SELECT observed_at, weight FROM baseline_feature_activity "
        "WHERE entity_type = ? AND entity_key = ? AND feature_name = ? AND feature_value = ? "
        "AND eligible = 1 AND observed_at >= ?",
        (entity_type, entity_key, feature_name, feature_value, cutoff),
    ).fetchall()
    rolling_weight_total = sum(r["weight"] for r in rows)
    rolling_distinct_days = len({r["observed_at"][:10] for r in rows})

    upsert_baseline_feature_stat(
        conn, entity_type, entity_key, feature_name, feature_value,
        lifetime_weight_total, lifetime_distinct_days,
        rolling_weight_total, rolling_distinct_days,
        first_seen, observed_at,
    )


def evaluate_and_record_feature_observation(
    conn: sqlite3.Connection,
    run_id: str,
    entity_type: str,
    entity_key: str,
    feature_name: str,
    feature_value: "Optional[str]",
    observed_at: str,
    *,
    partial_sensor_data: bool = False,
    is_unsigned: bool = False,
    is_network_bind: bool = False,
    is_weak_wifi_security: bool = False,
    source_table: "Optional[str]" = None,
    source_id: "Optional[int]" = None,
    now: "Optional[datetime]" = None,
    counters: "Optional[BaselineRunCounters]" = None,
) -> "Optional[Dict]":
    """Score (against PRIOR stats), then record, one feature
    observation. This is the single call persistence/scanner.py,
    listening/scanner.py, and wifi/scanner.py each make for their one
    supported feature — see SUPPORTED_FEATURES.

    `feature_value=None` (or `partial_sensor_data=True`) means the
    sensor genuinely could not determine a value this scan — always
    logged as ineligible with reason "partial_sensor_data", NEVER
    scored (there is nothing meaningful to compare) and NEVER folded
    into baseline_feature_stats. Returns None in that case; otherwise
    returns the score_feature_observation() breakdown (Stage 3, formula
    untouched) plus one Stage 4 addition: "anomaly_event_id", the id of
    the anomaly_events row this observation produced, or None when the
    tier was 'none' (no row written — see maybe_record_anomaly_event()).

    `counters`, when passed, is updated in place with this call's
    outcome (Stage 4B — see BaselineRunCounters) so a scanner's loop
    doesn't have to re-derive "was this incomplete/skipped/scored/
    anomalous" classification a second time itself; passing nothing
    (the default) makes this call behave exactly as it did in Stage 3.

    Respects the PARENT entity's EXCLUDE/FREEZE state (Stage 4 approval
    item 8), looked up via baseline_entities(entity_type, entity_key) —
    the same (entity_type, entity_key) this feature belongs to. Most
    entity_types feeding feature observations (persistence/listening/
    wifi) have no baseline_entities row unless a user has explicitly
    excluded/frozen them via `secure baseline exclude|freeze`, so this
    is a no-op lookup (nothing found -> excluded=False, frozen=False)
    until an operator acts. EXCLUDE forces PARTIAL/eligible-weight-zero
    the same way an unresolved alert does (never scored, never folds
    into stats). FREEZE still scores (comparisons continue against
    whatever was frozen) and still logs raw activity, but skips
    advancing baseline_feature_maturity/baseline_feature_stats.
    """
    if (entity_type, feature_name) not in SUPPORTED_FEATURES:
        raise ValueError(
            f"{feature_name!r} on entity_type {entity_type!r} is not one of the three "
            "Phase 14 feature dimensions with dedicated history logging — see "
            "SUPPORTED_FEATURES. Do not opportunistically log additional fields "
            "(Phase 14 extension approval item 4)."
        )

    now = _now(now)
    unavailable = partial_sensor_data or feature_value is None

    parent_entity = find_baseline_entity(conn, entity_type, entity_key)
    excluded = parent_entity.excluded if parent_entity else False
    frozen = parent_entity.frozen if parent_entity else False

    if excluded or unavailable:
        unreviewed = ()
    else:
        unreviewed = unreviewed_alert_severities_for_entity(conn, entity_type, entity_key)
    reason, weight = classify_eligibility(
        excluded=excluded, partial_sensor_data=unavailable, unreviewed_alert_severities=unreviewed,
    )

    breakdown = None
    prior_feature_row = None
    if not unavailable and weight > 0:
        # Captured BEFORE record_feature_maturity_observation() below
        # mutates it — this is the "at time" snapshot Stage 4's
        # anomaly_events row needs (maturity_state_at_time/
        # eligible_weight_total_at_time/eligible_distinct_days_at_time),
        # not a second query re-deriving anything score_feature_
        # observation() already computed.
        prior_feature_row = find_baseline_feature_maturity(conn, entity_type, entity_key, feature_name)
        # Score against PRIOR stats before anything below updates them.
        # When frozen, those PRIOR stats are exactly what stays frozen —
        # scoring proceeds completely normally, only the WRITE side
        # below is skipped.
        breakdown = score_feature_observation(
            conn, entity_type, entity_key, feature_name, feature_value, observed_at,
            is_unsigned=is_unsigned, is_network_bind=is_network_bind,
            is_weak_wifi_security=is_weak_wifi_security, now=now,
        )

    add_baseline_feature_activity(
        conn, run_id, entity_type, entity_key, feature_name, feature_value,
        observed_at, eligible=(weight > 0), eligibility_reason=reason, weight=weight,
        source_table=source_table, source_id=source_id,
    )

    if not frozen:
        feature_row = record_feature_maturity_observation(
            conn, entity_type, entity_key, feature_name, observed_at,
            eligible=(weight > 0), weight=weight,
        )
        new_state = maturity.compute_maturity(
            eligible_weight_total=feature_row.eligible_weight_total,
            eligible_distinct_days=feature_row.eligible_distinct_days,
            first_eligible_observed_at=feature_row.first_eligible_observed_at,
            last_eligible_observed_at=feature_row.last_eligible_observed_at,
            last_observed_at=feature_row.last_observed_at,
            now=now,
        )
        if new_state != feature_row.maturity_state:
            set_baseline_feature_maturity_state(conn, feature_row.id, new_state)

        if not unavailable and weight > 0:
            _update_feature_stats_after_activity(
                conn, entity_type, entity_key, feature_name, feature_value, observed_at, weight, now
            )

    if breakdown is not None:
        eligible_weight_total_at_time = prior_feature_row.eligible_weight_total if prior_feature_row else 0.0
        eligible_distinct_days_at_time = prior_feature_row.eligible_distinct_days if prior_feature_row else 0
        anomaly_event = maybe_record_anomaly_event(
            conn, run_id, entity_type, entity_key, feature_name, feature_value, observed_at,
            breakdown, breakdown["feature_maturity_state"],
            eligible_weight_total_at_time, eligible_distinct_days_at_time,
            source_table=source_table, source_id=source_id,
        )
        breakdown = {**breakdown, "anomaly_event_id": anomaly_event.id if anomaly_event else None}

    if counters is not None:
        counters.features_evaluated += 1
        if unavailable:
            counters.incomplete_inputs += 1
            counters.comparisons_skipped += 1
        elif weight <= 0:
            counters.comparisons_skipped += 1
        elif frozen:
            counters.comparisons_skipped += 1  # scored, but deliberately not "updated"
            if breakdown is not None and breakdown.get("anomaly_event_id") is not None:
                counters.anomalies_generated += 1
        else:
            counters.features_updated += 1
            if breakdown is not None and breakdown.get("anomaly_event_id") is not None:
                counters.anomalies_generated += 1

    return breakdown


def score_process_destination_rarity(
    conn: sqlite3.Connection, entity_key: str, *, now: "Optional[datetime]" = None
) -> "Optional[Dict]":
    """Sibling-relative rarity for a `process_destination` entity
    (Phase 14 extension approval item 7): compares this destination's
    PRIOR eligible_weight_total against the sum across every
    `process_destination` entity sharing the same process_name prefix
    ("Chrome::" siblings) — this destination's share of the OWNING
    PROCESS's total observed destination activity, not a meaningless
    within-entity comparison (a process_destination entity only ever
    has one destination value by construction).

    Reuses scoring.score_rarity_and_recency() unmodified — the formula
    is identical, only the two input numbers are gathered differently
    (cross-entity sibling sum instead of within-entity feature-value
    sum). Returns None if entity_key has no "::" separator (malformed).
    """
    if "::" not in entity_key:
        return None
    process_name = entity_key.split("::", 1)[0]
    now = _now(now)

    siblings = [
        e for e in list_baseline_entities(conn, "process_destination")
        if e.entity_key.startswith(f"{process_name}::")
    ]
    total_weight = sum(s.eligible_weight_total for s in siblings)
    this_entity = next((s for s in siblings if s.entity_key == entity_key), None)
    this_weight = this_entity.eligible_weight_total if this_entity else 0.0
    this_last_seen = this_entity.last_eligible_observed_at if this_entity else None

    rarity_recency = scoring.score_rarity_and_recency(
        prior_value_weight=this_weight,
        prior_total_feature_weight=total_weight,
        prior_last_seen=this_last_seen,
        now=now,
    )

    entity_maturity_state = this_entity.maturity_state if this_entity else maturity.NO_BASELINE
    raw_score, tier = scoring.combine(rarity_recency, entity_maturity_state)

    return {
        **rarity_recency,
        "raw_score": raw_score,
        "tier": tier,
        "entity_maturity_state": entity_maturity_state,
        "sibling_count": len(siblings),
        "process_name": process_name,
    }


def _build_process_destination_summary(breakdown: Dict) -> str:
    """One deterministic sentence for a process_destination anomaly —
    NOT built by _build_expected_summary(), since that function talks
    about a feature VALUE changing over time (previous_dominant), which
    doesn't apply here: a process_destination entity only ever has one
    destination by construction (Phase 14 extension approval item 7).
    This is a share-of-activity story instead.
    """
    process_name = breakdown["process_name"]
    sibling_count = breakdown["sibling_count"]
    if sibling_count == 0:
        return f"{process_name!r} has no other known destinations to compare this one against yet."
    if breakdown["rarity"] == RARITY_NEVER_SEEN:
        return (
            f"This destination has not been observed before for {process_name!r}, "
            f"which has {sibling_count} other known destination(s)."
        )
    return (
        f"This destination represents an unusual share of {process_name!r}'s "
        f"observed destination activity ({sibling_count} known destinations total)."
    )


def evaluate_and_record_process_destination_observation(
    conn: sqlite3.Connection,
    run_id: str,
    entity_key: str,
    observed_at: str,
    *,
    source_table: "Optional[str]" = None,
    source_id: "Optional[int]" = None,
    counters: "Optional[BaselineRunCounters]" = None,
    now: "Optional[datetime]" = None,
) -> "Optional[Dict]":
    """Score (against PRIOR sibling stats), then record, one
    process_destination observation — the entity-level counterpart to
    evaluate_and_record_feature_observation() for the ONE entity_type
    Stage 3 approved sibling-relative rarity scoring for (approval item
    7). connections/scanner.py is expected to call this once per
    distinct (process, destination) pair per scan (Stage 4C).

    Returns None if entity_key is malformed (no "::" separator — see
    score_process_destination_rarity()); otherwise the breakdown dict,
    plus "anomaly_event_id" same as the feature-level function.
    """
    now = _now(now)

    # Captured BEFORE record_entity_observation() below mutates it —
    # the "at time" snapshot for anomaly_events, same discipline as
    # evaluate_and_record_feature_observation()'s prior_feature_row.
    prior_entity_row = find_baseline_entity(conn, "process_destination", entity_key)

    breakdown = score_process_destination_rarity(conn, entity_key, now=now)
    if breakdown is None:
        return None

    excluded = prior_entity_row.excluded if prior_entity_row else False
    unreviewed = (
        () if excluded
        else unreviewed_alert_severities_for_entity(conn, "process_destination", entity_key)
    )
    reason, weight = classify_eligibility(excluded=excluded, unreviewed_alert_severities=unreviewed)

    record_entity_observation(
        conn, run_id, "process_destination", entity_key, observed_at, counters=counters,
    )

    anomaly_event = None
    if weight > 0:
        maturity_state_at_time = prior_entity_row.maturity_state if prior_entity_row else maturity.NO_BASELINE
        eligible_weight_total_at_time = prior_entity_row.eligible_weight_total if prior_entity_row else 0.0
        eligible_distinct_days_at_time = prior_entity_row.eligible_distinct_days if prior_entity_row else 0
        observed_value = entity_key.split("::", 1)[1] if "::" in entity_key else entity_key

        tier = breakdown["tier"]
        if tier != ANOMALY_TIER_NONE:
            expected_summary = _build_process_destination_summary(breakdown)
            anomaly_event, _was_new = add_anomaly_event(
                conn, run_id, "process_destination", entity_key, "destination", observed_value,
                observed_at, expected_summary, _score_components_only(breakdown),
                breakdown["raw_score"], tier, maturity_state_at_time,
                eligible_weight_total_at_time, eligible_distinct_days_at_time,
                source_table=source_table, source_id=source_id,
            )
            if counters is not None:
                counters.anomalies_generated += 1

    return {**breakdown, "anomaly_event_id": anomaly_event.id if anomaly_event else None}


# ---------- Stage 4B: baseline_runs lifecycle ----------


@dataclass
class BaselineRunCounters:
    """Mutable counters one module's scan accumulates while it makes
    its baseline/anomaly evaluation calls, then hands to
    finalize_baseline_run() once at the end of the scan — same "local
    counters, one INSERT with final values" shape
    secure/fileintegrity/scanner.py already uses for
    file_integrity_scans.

    Pass the SAME instance into every record_gap_observation()/
    evaluate_and_record_feature_observation() call made during one
    scan; both update it in place. `errors` is appended to directly by
    the caller's own try/except around each item (evaluation code
    itself doesn't swallow exceptions — a scanner decides per item
    whether to keep going after one fails, matching every other
    module's "one bad record doesn't abort the whole scan" pattern).
    """

    entities_evaluated: int = 0
    entities_updated: int = 0
    features_evaluated: int = 0
    features_updated: int = 0
    anomalies_generated: int = 0
    comparisons_skipped: int = 0
    incomplete_inputs: int = 0
    entities_skipped_cap: int = 0
    errors: List[str] = field(default_factory=list)

    def record_error(self, message: str) -> None:
        self.errors.append(message)


def finalize_baseline_run(
    conn: sqlite3.Connection,
    run_id: str,
    started_at: datetime,
    counters: BaselineRunCounters,
    *,
    now: "Optional[datetime]" = None,
) -> None:
    """Write the one baseline_runs row for this scan's baseline/anomaly
    evaluation pass. Called once, at the very end of a scanner's scan
    function, after every record_gap_observation()/
    evaluate_and_record_feature_observation() call for this run_id has
    already updated `counters` in place.

    Status (Stage 4 approval item 2/12 — "a partially evaluated
    baseline pass must not look identical to a clean complete pass"):
      'failed'  — at least one error was recorded AND nothing was
                  actually updated (entities_updated + features_updated
                  == 0). The pass produced nothing trustworthy.
      'partial' — at least one error occurred, or at least one
                  observation was skipped specifically because a
                  sensor/parser could not determine a value
                  (incomplete_inputs > 0). Routine eligibility
                  exclusions (an unresolved alert making an otherwise-
                  available observation ineligible) do NOT by
                  themselves make a pass 'partial' — poisoning
                  protection working as intended is not degradation.
      'success' — neither of the above. Includes the legitimate case of
                  zero items to evaluate this pass (e.g. Wi-Fi not
                  connected) — nothing went wrong, there was simply
                  nothing to do.
    """
    completed_at = _now(now)
    duration_seconds = (completed_at - started_at).total_seconds()
    errors_count = len(counters.errors)
    total_updated = counters.entities_updated + counters.features_updated

    if errors_count > 0 and total_updated == 0:
        status = "failed"
    elif errors_count > 0 or counters.incomplete_inputs > 0:
        status = "partial"
    else:
        status = "success"

    add_baseline_run(
        conn,
        run_id,
        started_at.isoformat(),
        completed_at.isoformat(),
        duration_seconds,
        entities_evaluated=counters.entities_evaluated,
        entities_updated=counters.entities_updated,
        features_evaluated=counters.features_evaluated,
        features_updated=counters.features_updated,
        anomalies_generated=counters.anomalies_generated,
        comparisons_skipped_insufficient_history=counters.comparisons_skipped,
        entities_skipped_cap=counters.entities_skipped_cap,
        incomplete_inputs=counters.incomplete_inputs,
        errors_count=errors_count,
        error_summary=counters.errors[:20] or None,
        status=status,
    )
