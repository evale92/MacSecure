"""
secure/baseline/maturity.py — Phase 14 baseline maturity state machine.

Pure function, no I/O, no database access — given the summary counters
already stored on a baseline_entities row (see
secure.storage.models.BaselineEntityRecord), decide which of four
maturity states applies. See constants.py for every threshold used
here, and PROJECT_NOTES.md's Phase 14 entry for why "many scans in a
short period" is deliberately NOT enough to reach ESTABLISHED on its
own.

States:
    NO_BASELINE — no eligible observations yet.
    LEARNING    — some eligible history, but not enough breadth yet
                  (fails at least one of the three ESTABLISHED gates).
    ESTABLISHED — enough eligible history (count + distinct days +
                  calendar span), and recently active.
    STALE       — hasn't been observed (eligible or not) recently
                  enough to trust a comparison against it, regardless
                  of how much history exists. History is never erased
                  on this transition — see engine.py, which only ever
                  updates counters forward, never resets them.
"""

from __future__ import annotations

from datetime import datetime, timezone

from secure.baseline.constants import (
    MIN_ELIGIBLE_DISTINCT_DAYS,
    MIN_ELIGIBLE_OBSERVATIONS,
    MIN_ELIGIBLE_SPAN_DAYS,
    STALE_AFTER_DAYS,
)

NO_BASELINE = "no_baseline"
LEARNING = "learning"
ESTABLISHED = "established"
STALE = "stale"

MATURITY_STATES = (NO_BASELINE, LEARNING, ESTABLISHED, STALE)


def _parse(iso_string: str) -> datetime:
    dt = datetime.fromisoformat(iso_string)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def compute_maturity(
    *,
    eligible_weight_total: float,
    eligible_distinct_days: int,
    first_eligible_observed_at: "str | None",
    last_eligible_observed_at: "str | None",
    last_observed_at: "str | None",
    now: "datetime | None" = None,
) -> str:
    """Return one of MATURITY_STATES for an entity's current stats.

    All *_at parameters are ISO-8601 strings (datetime.isoformat()),
    matching every timestamp already stored elsewhere in this project.
    `now` is an explicit parameter, never read internally from
    datetime.now() — this keeps the function deterministic and
    testable without monkeypatching the clock (Phase 14 approval item
    20, "deterministic scoring").

    Order of evaluation matters:
      1. No eligible history at all -> NO_BASELINE, regardless of any
         ineligible (poisoned/excluded/partial) observations that may
         exist.
      2. Gone quiet for STALE_AFTER_DAYS -> STALE, even if the
         eligible-history gates below would otherwise be satisfied —
         recency is a precondition for trusting any comparison, not
         just one more optional signal.
      3. All three ESTABLISHED gates (count, distinct days, calendar
         span) satisfied together -> ESTABLISHED.
      4. Otherwise -> LEARNING.
    """
    now = now or datetime.now(timezone.utc)

    if (
        eligible_weight_total <= 0
        or first_eligible_observed_at is None
        or last_eligible_observed_at is None
    ):
        return NO_BASELINE

    if last_observed_at is not None:
        gap_days = (now - _parse(last_observed_at)).days
        if gap_days > STALE_AFTER_DAYS:
            return STALE

    span_days = (
        _parse(last_eligible_observed_at) - _parse(first_eligible_observed_at)
    ).days

    if (
        eligible_weight_total >= MIN_ELIGIBLE_OBSERVATIONS
        and eligible_distinct_days >= MIN_ELIGIBLE_DISTINCT_DAYS
        and span_days >= MIN_ELIGIBLE_SPAN_DAYS
    ):
        return ESTABLISHED

    return LEARNING
