"""
baseline.py — Behavioral Baselining and Anomaly Detection (Phase 14): baseline_entities/activity/feature_stats/time_stats, anomaly_events, baseline_runs, baseline_feature_activity/maturity — see secure/baseline/.

Split out of the original secure/storage/models.py (Phase 14.5 Stage C)
purely mechanically — behavior, SQL, and function signatures are
unchanged; only the file this code lives in changed. See
secure/storage/models/__init__.py for the full original module
docstring and the re-export surface that preserves
`from secure.storage.models import X` for every name.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

# ---------- Behavioral Baselining and Anomaly Detection (Phase 14) ----------
#
# This module still only stores and retrieves rows — the maturity state
# machine (secure/baseline/maturity.py) and poisoning-eligibility rules
# (secure/baseline/eligibility.py) are pure logic that live outside
# this file and are simply handed their answers to store. The one
# exception is the small, mechanical "is this a new calendar day for
# this entity" comparison inside record_baseline_observation() below,
# which is the same class of simple derived-field bookkeeping
# upsert_device()/upsert_bluetooth_device() already do in this file
# (merging a non-empty hostname, incrementing times_seen) — not a
# maturity/eligibility decision itself.


@dataclass
class BaselineEntityRecord:
    id: int
    entity_type: str
    entity_key: str
    maturity_state: str
    first_observed_at: "str | None"
    last_observed_at: "str | None"
    first_eligible_observed_at: "str | None"
    last_eligible_observed_at: "str | None"
    observation_count: int
    distinct_days_observed: int
    eligible_weight_total: float
    eligible_distinct_days: int
    excluded: bool
    frozen: bool
    created_at: str
    updated_at: str


def _row_to_baseline_entity(row: sqlite3.Row) -> BaselineEntityRecord:
    data = dict(row)
    data["excluded"] = bool(data["excluded"])
    data["frozen"] = bool(data["frozen"])
    return BaselineEntityRecord(**data)


def get_or_create_baseline_entity(
    conn: sqlite3.Connection, entity_type: str, entity_key: str
) -> "tuple[BaselineEntityRecord, bool]":
    """Look up one entity's baseline row, creating it (NO_BASELINE, all
    counters zero) if it doesn't exist yet. Returns (record, was_new).

    A brand-new entity always starts at NO_BASELINE regardless of how
    confident its first observation looks — see maturity.py.
    """
    existing = conn.execute(
        "SELECT * FROM baseline_entities WHERE entity_type = ? AND entity_key = ?",
        (entity_type, entity_key),
    ).fetchone()
    if existing is not None:
        return _row_to_baseline_entity(existing), False

    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO baseline_entities "
        "(entity_type, entity_key, maturity_state, observation_count, "
        "distinct_days_observed, eligible_weight_total, eligible_distinct_days, "
        "excluded, frozen, created_at, updated_at) "
        "VALUES (?, ?, 'no_baseline', 0, 0, 0, 0, 0, 0, ?, ?)",
        (entity_type, entity_key, now, now),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM baseline_entities WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return _row_to_baseline_entity(row), True


def count_baseline_entities(conn: sqlite3.Connection, entity_type: "str | None" = None) -> int:
    """Count baseline entities, optionally scoped to one entity_type —
    what a per-entity_type cap check (see ENTITY_CAPS in
    secure/baseline/constants.py) compares against before creating a
    genuinely new entity."""
    if entity_type is None:
        row = conn.execute("SELECT COUNT(*) AS n FROM baseline_entities").fetchone()
    else:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM baseline_entities WHERE entity_type = ?",
            (entity_type,),
        ).fetchone()
    return int(row["n"])


def count_baseline_entities_by_maturity(
    conn: sqlite3.Connection, entity_type: "str | None" = None
) -> "dict[str, int]":
    """Maturity-state breakdown for `secure baseline status` — e.g.
    {"no_baseline": 3, "learning": 12, "established": 40, "stale": 1}.
    States with zero entities are simply absent from the dict rather
    than listed at 0."""
    if entity_type is None:
        rows = conn.execute(
            "SELECT maturity_state, COUNT(*) AS n FROM baseline_entities "
            "GROUP BY maturity_state"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT maturity_state, COUNT(*) AS n FROM baseline_entities "
            "WHERE entity_type = ? GROUP BY maturity_state",
            (entity_type,),
        ).fetchall()
    return {row["maturity_state"]: int(row["n"]) for row in rows}


def count_baseline_entities_excluded(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM baseline_entities WHERE excluded = 1"
    ).fetchone()
    return int(row["n"])


def count_baseline_entities_frozen(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM baseline_entities WHERE frozen = 1"
    ).fetchone()
    return int(row["n"])


def record_baseline_observation(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_key: str,
    observed_at: str,
    eligible: bool,
    weight: float,
) -> BaselineEntityRecord:
    """Apply one observation to an entity's lifetime counters. Creates
    the entity row first if needed (see get_or_create_baseline_entity).

    Does NOT compute or write maturity_state — that's a pure-logic
    decision (secure/baseline/maturity.py's compute_maturity()) made by
    the caller (secure/baseline/engine.py) using the counters this
    function returns, then written back via set_baseline_entity_maturity().
    Keeping that decision out of this file is deliberate: this module
    only stores what it's told, per the "ONLY place with SQL" rule at
    the top of this file — the maturity RULES themselves belong to
    secure/baseline/, not here.

    `observed_at` must be an ISO-8601 timestamp; calls are expected in
    chronological order per entity, same assumption every other
    *_events/*_observations writer in this file already makes.
    """
    entity, _ = get_or_create_baseline_entity(conn, entity_type, entity_key)
    now = datetime.now(timezone.utc).isoformat()

    observed_date = observed_at[:10]
    is_new_lifetime_day = (
        entity.last_observed_at is None or entity.last_observed_at[:10] != observed_date
    )
    new_first_observed_at = entity.first_observed_at or observed_at
    new_last_observed_at = observed_at
    new_observation_count = entity.observation_count + 1
    new_distinct_days_observed = entity.distinct_days_observed + (
        1 if is_new_lifetime_day else 0
    )

    new_eligible_weight_total = entity.eligible_weight_total
    new_eligible_distinct_days = entity.eligible_distinct_days
    new_first_eligible_observed_at = entity.first_eligible_observed_at
    new_last_eligible_observed_at = entity.last_eligible_observed_at

    if eligible and weight > 0:
        is_new_eligible_day = (
            entity.last_eligible_observed_at is None
            or entity.last_eligible_observed_at[:10] != observed_date
        )
        new_eligible_weight_total = entity.eligible_weight_total + weight
        new_eligible_distinct_days = entity.eligible_distinct_days + (
            1 if is_new_eligible_day else 0
        )
        new_first_eligible_observed_at = entity.first_eligible_observed_at or observed_at
        new_last_eligible_observed_at = observed_at

    conn.execute(
        "UPDATE baseline_entities SET "
        "first_observed_at = ?, last_observed_at = ?, "
        "first_eligible_observed_at = ?, last_eligible_observed_at = ?, "
        "observation_count = ?, distinct_days_observed = ?, "
        "eligible_weight_total = ?, eligible_distinct_days = ?, updated_at = ? "
        "WHERE id = ?",
        (
            new_first_observed_at, new_last_observed_at,
            new_first_eligible_observed_at, new_last_eligible_observed_at,
            new_observation_count, new_distinct_days_observed,
            new_eligible_weight_total, new_eligible_distinct_days, now,
            entity.id,
        ),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM baseline_entities WHERE id = ?", (entity.id,)).fetchone()
    return _row_to_baseline_entity(row)


def set_baseline_entity_maturity(conn: sqlite3.Connection, entity_id: int, maturity_state: str) -> None:
    conn.execute(
        "UPDATE baseline_entities SET maturity_state = ? WHERE id = ?",
        (maturity_state, entity_id),
    )
    conn.commit()


def set_baseline_entity_excluded(conn: sqlite3.Connection, entity_id: int, excluded: bool) -> None:
    conn.execute(
        "UPDATE baseline_entities SET excluded = ? WHERE id = ?",
        (1 if excluded else 0, entity_id),
    )
    conn.commit()


def set_baseline_entity_frozen(conn: sqlite3.Connection, entity_id: int, frozen: bool) -> None:
    conn.execute(
        "UPDATE baseline_entities SET frozen = ? WHERE id = ?",
        (1 if frozen else 0, entity_id),
    )
    conn.commit()


def list_baseline_entities(
    conn: sqlite3.Connection,
    entity_type: "str | None" = None,
    *,
    maturity_state: "str | None" = None,
    excluded: "bool | None" = None,
    frozen: "bool | None" = None,
) -> "list[BaselineEntityRecord]":
    """List baseline entities, optionally filtered. All filters combine
    with AND; each is optional and independent, for `secure baseline
    list` (Stage 4D) — deliberately just simple equality filters, not a
    query builder, matching the "do not overbuild filtering" guidance
    used elsewhere in Stage 4."""
    clauses = []
    params: list = []
    if entity_type is not None:
        clauses.append("entity_type = ?")
        params.append(entity_type)
    if maturity_state is not None:
        clauses.append("maturity_state = ?")
        params.append(maturity_state)
    if excluded is not None:
        clauses.append("excluded = ?")
        params.append(1 if excluded else 0)
    if frozen is not None:
        clauses.append("frozen = ?")
        params.append(1 if frozen else 0)
    where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
    rows = conn.execute(
        f"SELECT * FROM baseline_entities {where}ORDER BY entity_type, entity_key", params
    ).fetchall()
    return [_row_to_baseline_entity(row) for row in rows]


def find_baseline_entity(
    conn: sqlite3.Connection, entity_type: str, entity_key: str
) -> "BaselineEntityRecord | None":
    row = conn.execute(
        "SELECT * FROM baseline_entities WHERE entity_type = ? AND entity_key = ?",
        (entity_type, entity_key),
    ).fetchone()
    return _row_to_baseline_entity(row) if row else None


def find_baseline_entity_by_id(conn: sqlite3.Connection, entity_id: int) -> "BaselineEntityRecord | None":
    row = conn.execute("SELECT * FROM baseline_entities WHERE id = ?", (entity_id,)).fetchone()
    return _row_to_baseline_entity(row) if row else None


def delete_baseline_entity(conn: sqlite3.Connection, entity_type: str, entity_key: str) -> bool:
    """Reset one entity's learned baseline: removes its baseline_entities
    row plus its feature/time statistics and gap-filling activity log.
    Deliberately does NOT touch anomaly_events — past anomaly findings
    are historical evidence, same as alerts, and are never erased by a
    baseline reset (Phase 14 approval item 15: "never silently reset
    history"). Scoped to exactly one (entity_type, entity_key); never
    call this in a loop over "all entities" without the caller having
    obtained explicit, per-entity or explicit --all confirmation first
    (see `secure baseline reset` in cli.py).

    Returns True if an entity row existed and was removed, False if
    there was nothing to reset.
    """
    existing = conn.execute(
        "SELECT id FROM baseline_entities WHERE entity_type = ? AND entity_key = ?",
        (entity_type, entity_key),
    ).fetchone()
    if existing is None:
        return False
    conn.execute(
        "DELETE FROM baseline_entities WHERE entity_type = ? AND entity_key = ?",
        (entity_type, entity_key),
    )
    conn.execute(
        "DELETE FROM baseline_feature_stats WHERE entity_type = ? AND entity_key = ?",
        (entity_type, entity_key),
    )
    conn.execute(
        "DELETE FROM baseline_time_stats WHERE entity_type = ? AND entity_key = ?",
        (entity_type, entity_key),
    )
    conn.execute(
        "DELETE FROM baseline_activity WHERE entity_type = ? AND entity_key = ?",
        (entity_type, entity_key),
    )
    conn.commit()
    return True


def reset_baseline_entity(conn: sqlite3.Connection, entity_type: str, entity_key: str) -> bool:
    """`secure baseline reset` (Stage 4 approval item 8): re-initialize
    ONE entity's DERIVED baseline knowledge back to a just-created,
    NO_BASELINE state, without destroying anything raw or forensic.

    Deliberately different from delete_baseline_entity() above (which
    predates the Stage 4 extension's precise reset semantics and is
    kept only for its one real remaining use: cleaning up an empty,
    never-observed row created moments earlier when an entity_type's
    cap is hit — see history.py). A real reset must:
      - KEEP the baseline_entities row itself (same id/created_at) —
        the row's very existence, and when it was first created, is
        itself forensic information; only its counters/maturity_state
        reset to pristine values, back to what get_or_create_baseline_
        entity() would produce for a brand-new entity.
      - KEEP excluded/frozen exactly as they were — those are operator
        controls (input), not derived statistics (output); a reset
        does not implicitly re-include or unfreeze anything.
      - DELETE baseline_feature_stats/baseline_feature_maturity/
        baseline_time_stats rows for this entity — pure derived
        summaries with no independent forensic value once the raw
        activity log (below) still exists to reconstruct them from.
      - PRESERVE baseline_activity, baseline_feature_activity, AND
        anomaly_events untouched — the raw observation log and past
        anomaly findings are exactly the "forensic records" Stage 4
        approval item 8 says must never be silently destroyed. Reset
        does not retroactively reprocess this preserved raw history
        back into the (now-cleared) derived tables either — per the
        zero-backfill principle, baseline knowledge only ever builds
        forward from the moment of each observation, including the
        moment right after a reset.

    Returns False if no entity row exists for (entity_type, entity_key).
    """
    existing = conn.execute(
        "SELECT id FROM baseline_entities WHERE entity_type = ? AND entity_key = ?",
        (entity_type, entity_key),
    ).fetchone()
    if existing is None:
        return False

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "UPDATE baseline_entities SET "
        "maturity_state = 'no_baseline', first_observed_at = NULL, last_observed_at = NULL, "
        "first_eligible_observed_at = NULL, last_eligible_observed_at = NULL, "
        "observation_count = 0, distinct_days_observed = 0, "
        "eligible_weight_total = 0, eligible_distinct_days = 0, updated_at = ? "
        "WHERE entity_type = ? AND entity_key = ?",
        (now, entity_type, entity_key),
    )
    conn.execute(
        "DELETE FROM baseline_feature_stats WHERE entity_type = ? AND entity_key = ?",
        (entity_type, entity_key),
    )
    conn.execute(
        "DELETE FROM baseline_feature_maturity WHERE entity_type = ? AND entity_key = ?",
        (entity_type, entity_key),
    )
    conn.execute(
        "DELETE FROM baseline_time_stats WHERE entity_type = ? AND entity_key = ?",
        (entity_type, entity_key),
    )
    conn.commit()
    return True


@dataclass
class BaselineActivityRecord:
    id: int
    created_at: str
    run_id: str
    entity_type: str
    entity_key: str
    eligibility_reason: str
    weight: float


def _row_to_baseline_activity(row: sqlite3.Row) -> BaselineActivityRecord:
    return BaselineActivityRecord(**dict(row))


def add_baseline_activity(
    conn: sqlite3.Connection,
    run_id: str,
    entity_type: str,
    entity_key: str,
    eligibility_reason: str,
    weight: float,
) -> int:
    """Append one gap-filling observation row — used ONLY for entity
    types with no existing history table of their own ("inventory",
    "process"); see the schema comment on baseline_activity in
    database.py for why every other entity_type is read from its
    existing *_events/*_observations table instead of duplicated here.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO baseline_activity "
        "(created_at, run_id, entity_type, entity_key, eligibility_reason, weight) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (created_at, run_id, entity_type, entity_key, eligibility_reason, weight),
    )
    conn.commit()
    return cursor.lastrowid


def list_baseline_activity(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_key: str,
) -> "list[BaselineActivityRecord]":
    rows = conn.execute(
        "SELECT * FROM baseline_activity WHERE entity_type = ? AND entity_key = ? "
        "ORDER BY created_at",
        (entity_type, entity_key),
    ).fetchall()
    return [_row_to_baseline_activity(row) for row in rows]


@dataclass
class BaselineFeatureStatRecord:
    id: int
    entity_type: str
    entity_key: str
    feature_name: str
    feature_value: str
    lifetime_weight_total: float
    lifetime_distinct_days: int
    rolling_weight_total: float
    rolling_distinct_days: int
    first_seen: str
    last_seen: str
    updated_at: str


def _row_to_baseline_feature_stat(row: sqlite3.Row) -> BaselineFeatureStatRecord:
    return BaselineFeatureStatRecord(**dict(row))


def upsert_baseline_feature_stat(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_key: str,
    feature_name: str,
    feature_value: str,
    lifetime_weight_total: float,
    lifetime_distinct_days: int,
    rolling_weight_total: float,
    rolling_distinct_days: int,
    first_seen: str,
    last_seen: str,
) -> BaselineFeatureStatRecord:
    """Replace the full stored statistics for one (entity, feature_name,
    feature_value) with values the caller has already computed (see
    secure/baseline/engine.py) — this is a whole-row replace, not an
    increment, since rolling_* is recomputed from source history each
    time rather than maintained via incremental decrement (see the
    schema comment on baseline_feature_stats in database.py).
    """
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO baseline_feature_stats "
        "(entity_type, entity_key, feature_name, feature_value, "
        "lifetime_weight_total, lifetime_distinct_days, rolling_weight_total, "
        "rolling_distinct_days, first_seen, last_seen, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(entity_type, entity_key, feature_name, feature_value) DO UPDATE SET "
        "lifetime_weight_total = excluded.lifetime_weight_total, "
        "lifetime_distinct_days = excluded.lifetime_distinct_days, "
        "rolling_weight_total = excluded.rolling_weight_total, "
        "rolling_distinct_days = excluded.rolling_distinct_days, "
        "last_seen = excluded.last_seen, "
        "updated_at = excluded.updated_at",
        (
            entity_type, entity_key, feature_name, feature_value,
            lifetime_weight_total, lifetime_distinct_days,
            rolling_weight_total, rolling_distinct_days,
            first_seen, last_seen, now,
        ),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM baseline_feature_stats WHERE entity_type = ? AND entity_key = ? "
        "AND feature_name = ? AND feature_value = ?",
        (entity_type, entity_key, feature_name, feature_value),
    ).fetchone()
    return _row_to_baseline_feature_stat(row)


def list_baseline_feature_stats(
    conn: sqlite3.Connection, entity_type: str, entity_key: str, feature_name: "str | None" = None
) -> "list[BaselineFeatureStatRecord]":
    if feature_name is None:
        rows = conn.execute(
            "SELECT * FROM baseline_feature_stats WHERE entity_type = ? AND entity_key = ? "
            "ORDER BY feature_name, rolling_weight_total DESC",
            (entity_type, entity_key),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM baseline_feature_stats WHERE entity_type = ? AND entity_key = ? "
            "AND feature_name = ? ORDER BY rolling_weight_total DESC",
            (entity_type, entity_key, feature_name),
        ).fetchall()
    return [_row_to_baseline_feature_stat(row) for row in rows]


def get_baseline_feature_stat(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_key: str,
    feature_name: str,
    feature_value: str,
) -> "BaselineFeatureStatRecord | None":
    row = conn.execute(
        "SELECT * FROM baseline_feature_stats WHERE entity_type = ? AND entity_key = ? "
        "AND feature_name = ? AND feature_value = ?",
        (entity_type, entity_key, feature_name, feature_value),
    ).fetchone()
    return _row_to_baseline_feature_stat(row) if row else None


@dataclass
class BaselineTimeStatRecord:
    id: int
    entity_type: str
    entity_key: str
    night_weight: float
    morning_weight: float
    afternoon_weight: float
    evening_weight: float
    weekday_weight: float
    weekend_weight: float
    distinct_days_observed: int
    total_weight: float
    updated_at: str


def _row_to_baseline_time_stat(row: sqlite3.Row) -> BaselineTimeStatRecord:
    return BaselineTimeStatRecord(**dict(row))


def upsert_baseline_time_stat(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_key: str,
    night_weight: float,
    morning_weight: float,
    afternoon_weight: float,
    evening_weight: float,
    weekday_weight: float,
    weekend_weight: float,
    distinct_days_observed: int,
    total_weight: float,
) -> BaselineTimeStatRecord:
    """Whole-row replace of one entity's time-of-day distribution — same
    "caller computes it, this just stores it" shape as
    upsert_baseline_feature_stat()."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO baseline_time_stats "
        "(entity_type, entity_key, night_weight, morning_weight, afternoon_weight, "
        "evening_weight, weekday_weight, weekend_weight, distinct_days_observed, "
        "total_weight, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(entity_type, entity_key) DO UPDATE SET "
        "night_weight = excluded.night_weight, "
        "morning_weight = excluded.morning_weight, "
        "afternoon_weight = excluded.afternoon_weight, "
        "evening_weight = excluded.evening_weight, "
        "weekday_weight = excluded.weekday_weight, "
        "weekend_weight = excluded.weekend_weight, "
        "distinct_days_observed = excluded.distinct_days_observed, "
        "total_weight = excluded.total_weight, "
        "updated_at = excluded.updated_at",
        (
            entity_type, entity_key, night_weight, morning_weight, afternoon_weight,
            evening_weight, weekday_weight, weekend_weight, distinct_days_observed,
            total_weight, now,
        ),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM baseline_time_stats WHERE entity_type = ? AND entity_key = ?",
        (entity_type, entity_key),
    ).fetchone()
    return _row_to_baseline_time_stat(row)


def get_baseline_time_stat(
    conn: sqlite3.Connection, entity_type: str, entity_key: str
) -> "BaselineTimeStatRecord | None":
    row = conn.execute(
        "SELECT * FROM baseline_time_stats WHERE entity_type = ? AND entity_key = ?",
        (entity_type, entity_key),
    ).fetchone()
    return _row_to_baseline_time_stat(row) if row else None


@dataclass
class AnomalyEventRecord:
    id: int
    created_at: str
    run_id: str
    entity_type: str
    entity_key: str
    feature_name: str
    observed_value: "str | None"
    observed_at: str
    expected_summary: str
    score_breakdown: dict  # parsed from JSON — {component_name: points}
    anomaly_score: int
    anomaly_tier: str
    maturity_state_at_time: str
    eligible_weight_total_at_time: float
    eligible_distinct_days_at_time: int
    source_table: "str | None"
    source_id: "int | None"
    known: bool


def _row_to_anomaly_event(row: sqlite3.Row) -> AnomalyEventRecord:
    data = dict(row)
    data["known"] = bool(data["known"])
    data["score_breakdown"] = json.loads(data["score_breakdown"])
    return AnomalyEventRecord(**data)


def find_anomaly_event(
    conn: sqlite3.Connection, run_id: str, entity_type: str, entity_key: str, feature_name: str
) -> "AnomalyEventRecord | None":
    """Look up an anomaly event by its idempotence key (matches
    idx_anomaly_events_dedup) — used by add_anomaly_event() to decide
    whether a call is a genuine new finding or a repeat evaluation of
    the same (run_id, entity, feature) that must not duplicate."""
    row = conn.execute(
        "SELECT * FROM anomaly_events WHERE run_id = ? AND entity_type = ? "
        "AND entity_key = ? AND feature_name = ?",
        (run_id, entity_type, entity_key, feature_name),
    ).fetchone()
    return _row_to_anomaly_event(row) if row else None


def add_anomaly_event(
    conn: sqlite3.Connection,
    run_id: str,
    entity_type: str,
    entity_key: str,
    feature_name: str,
    observed_value: "str | None",
    observed_at: str,
    expected_summary: str,
    score_breakdown: dict,
    anomaly_score: int,
    anomaly_tier: str,
    maturity_state_at_time: str,
    eligible_weight_total_at_time: float,
    eligible_distinct_days_at_time: int,
    source_table: "str | None" = None,
    source_id: "int | None" = None,
) -> "tuple[AnomalyEventRecord, bool]":
    """Record one anomaly finding. `known` always starts at 0
    (unreviewed) — same reviewable-queue pattern as every *_alerts
    table, reused here rather than inventing a second one (see
    `secure anomalies mark` in cli.py).

    Idempotent on (run_id, entity_type, entity_key, feature_name) —
    see idx_anomaly_events_dedup's schema comment. A repeat call for a
    key that already exists returns the EXISTING row unchanged (was_new
    = False) rather than inserting a duplicate or overwriting it; the
    first evaluation for a given scan pass always wins. Checked with a
    SELECT before the INSERT (same style as get_or_create_baseline_entity)
    rather than relying on the UNIQUE index to raise.
    """
    existing = find_anomaly_event(conn, run_id, entity_type, entity_key, feature_name)
    if existing is not None:
        return existing, False

    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO anomaly_events "
        "(created_at, run_id, entity_type, entity_key, feature_name, observed_value, "
        "observed_at, expected_summary, score_breakdown, anomaly_score, anomaly_tier, "
        "maturity_state_at_time, eligible_weight_total_at_time, "
        "eligible_distinct_days_at_time, source_table, source_id, known) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        (
            created_at, run_id, entity_type, entity_key, feature_name, observed_value,
            observed_at, expected_summary, json.dumps(score_breakdown), anomaly_score,
            anomaly_tier, maturity_state_at_time, eligible_weight_total_at_time,
            eligible_distinct_days_at_time, source_table, source_id,
        ),
    )
    conn.commit()
    return find_anomaly_event(conn, run_id, entity_type, entity_key, feature_name), True


def list_anomaly_events(
    conn: sqlite3.Connection,
    entity_type: "str | None" = None,
    entity_key: "str | None" = None,
    *,
    tier: "str | None" = None,
    known: "bool | None" = None,
    since: "str | None" = None,
    limit: int = 100,
) -> "list[AnomalyEventRecord]":
    """List anomaly findings, most recent first. All filters are
    optional and combine with AND: `entity_type`+`entity_key` together
    scope to one entity (matches the original Stage 1 signature),
    `tier` matches anomaly_tier exactly, `known` matches review state,
    `since` is an ISO-8601 string compared against `observed_at` (a
    "recent time window" filter — deliberately just a lower bound, not
    a full range-query builder, per Stage 4 approval item 6: "do not
    overbuild filtering in this stage").
    """
    clauses = []
    params: list = []
    if entity_type is not None and entity_key is not None:
        clauses.append("entity_type = ? AND entity_key = ?")
        params.extend([entity_type, entity_key])
    elif entity_type is not None:
        clauses.append("entity_type = ?")
        params.append(entity_type)
    if tier is not None:
        clauses.append("anomaly_tier = ?")
        params.append(tier)
    if known is not None:
        clauses.append("known = ?")
        params.append(1 if known else 0)
    if since is not None:
        clauses.append("observed_at >= ?")
        params.append(since)

    where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
    rows = conn.execute(
        f"SELECT * FROM anomaly_events {where}ORDER BY id DESC LIMIT ?",
        (*params, limit),
    ).fetchall()
    return [_row_to_anomaly_event(row) for row in rows]


def count_anomaly_events(
    conn: sqlite3.Connection, *, tier: "str | None" = None, known: "bool | None" = None
) -> int:
    clauses = []
    params: list = []
    if tier is not None:
        clauses.append("anomaly_tier = ?")
        params.append(tier)
    if known is not None:
        clauses.append("known = ?")
        params.append(1 if known else 0)
    where = f"WHERE {' AND '.join(clauses)} " if clauses else ""
    row = conn.execute(f"SELECT COUNT(*) AS n FROM anomaly_events {where}", params).fetchone()
    return row["n"]


def find_anomaly_event_by_id(conn: sqlite3.Connection, event_id: int) -> "AnomalyEventRecord | None":
    row = conn.execute("SELECT * FROM anomaly_events WHERE id = ?", (event_id,)).fetchone()
    return _row_to_anomaly_event(row) if row else None


def set_anomaly_event_known(conn: sqlite3.Connection, event_id: int, known: bool) -> None:
    conn.execute(
        "UPDATE anomaly_events SET known = ? WHERE id = ?",
        (1 if known else 0, event_id),
    )
    conn.commit()


@dataclass
class BaselineRunRecord:
    id: int
    run_id: str
    started_at: str
    completed_at: "str | None"
    duration_seconds: "float | None"
    entities_evaluated: int
    entities_updated: int
    features_evaluated: int
    features_updated: int
    anomalies_generated: int
    comparisons_skipped_insufficient_history: int
    entities_skipped_cap: int
    incomplete_inputs: int
    errors_count: int
    error_summary: "list | None"  # parsed from JSON — short list of error strings
    status: str  # 'success' | 'partial' | 'failed'


def _row_to_baseline_run(row: sqlite3.Row) -> BaselineRunRecord:
    data = dict(row)
    data["error_summary"] = json.loads(data["error_summary"]) if data["error_summary"] else None
    return BaselineRunRecord(**data)


def add_baseline_run(
    conn: sqlite3.Connection,
    run_id: str,
    started_at: str,
    completed_at: "str | None",
    duration_seconds: "float | None",
    entities_evaluated: int = 0,
    entities_updated: int = 0,
    features_evaluated: int = 0,
    features_updated: int = 0,
    anomalies_generated: int = 0,
    comparisons_skipped_insufficient_history: int = 0,
    entities_skipped_cap: int = 0,
    incomplete_inputs: int = 0,
    errors_count: int = 0,
    error_summary: "list | None" = None,
    status: str = "success",
) -> int:
    """Record one baseline-engine maintenance/update pass — same
    "insert once with final values after the pass completes" shape as
    add_file_integrity_scan(). `status` is computed by the caller
    (secure/baseline/engine.py's finalize_baseline_run(), never derived
    a second time by a reader) — see baseline_runs' schema comment for
    what distinguishes 'success' / 'partial' / 'failed'."""
    cursor = conn.execute(
        "INSERT INTO baseline_runs "
        "(run_id, started_at, completed_at, duration_seconds, entities_evaluated, "
        "entities_updated, features_evaluated, features_updated, anomalies_generated, "
        "comparisons_skipped_insufficient_history, entities_skipped_cap, "
        "incomplete_inputs, errors_count, error_summary, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            run_id, started_at, completed_at, duration_seconds, entities_evaluated,
            entities_updated, features_evaluated, features_updated, anomalies_generated,
            comparisons_skipped_insufficient_history, entities_skipped_cap,
            incomplete_inputs, errors_count,
            json.dumps(error_summary) if error_summary else None, status,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def list_baseline_runs(
    conn: sqlite3.Connection, *, status: "str | None" = None, limit: int = 20
) -> "list[BaselineRunRecord]":
    if status is not None:
        rows = conn.execute(
            "SELECT * FROM baseline_runs WHERE status = ? ORDER BY id DESC LIMIT ?",
            (status, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM baseline_runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_baseline_run(row) for row in rows]


def count_baseline_runs(conn: sqlite3.Connection, *, status: "str | None" = None) -> int:
    if status is not None:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM baseline_runs WHERE status = ?", (status,)
        ).fetchone()
    else:
        row = conn.execute("SELECT COUNT(*) AS n FROM baseline_runs").fetchone()
    return row["n"]


def find_latest_baseline_run(conn: sqlite3.Connection) -> "BaselineRunRecord | None":
    row = conn.execute("SELECT * FROM baseline_runs ORDER BY id DESC LIMIT 1").fetchone()
    return _row_to_baseline_run(row) if row else None


# ---------- Feature-level history extension (Phase 14, Stage 3) ----------
#
# baseline_feature_activity/baseline_feature_maturity exist ONLY for
# feature dimensions with no other per-scan log to read from —
# currently exactly three: process/persistence signing_status,
# listening bind_scope, and Wi-Fi security type (see the schema
# comments in database.py). ZERO BACKFILL: every row here starts from
# the moment this logging shipped; nothing is fabricated from an
# entity's pre-existing history.


@dataclass
class BaselineFeatureActivityRecord:
    id: int
    created_at: str
    run_id: str
    entity_type: str
    entity_key: str
    feature_name: str
    feature_value: "str | None"
    observed_at: str
    eligible: bool
    eligibility_reason: str
    weight: float
    source_table: "str | None"
    source_id: "int | None"


def _row_to_baseline_feature_activity(row: sqlite3.Row) -> BaselineFeatureActivityRecord:
    data = dict(row)
    data["eligible"] = bool(data["eligible"])
    return BaselineFeatureActivityRecord(**data)


def add_baseline_feature_activity(
    conn: sqlite3.Connection,
    run_id: str,
    entity_type: str,
    entity_key: str,
    feature_name: str,
    feature_value: "str | None",
    observed_at: str,
    eligible: bool,
    eligibility_reason: str,
    weight: float,
    source_table: "str | None" = None,
    source_id: "int | None" = None,
) -> int:
    """Append one raw feature observation. `feature_value=None` means
    the sensor genuinely could not determine a value this scan — always
    paired with eligible=False, eligibility_reason="partial_sensor_data"
    by the caller (see secure/baseline/engine.py) — never logged as an
    ordinary observed category.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO baseline_feature_activity "
        "(created_at, run_id, entity_type, entity_key, feature_name, feature_value, "
        "observed_at, eligible, eligibility_reason, weight, source_table, source_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            created_at, run_id, entity_type, entity_key, feature_name, feature_value,
            observed_at, 1 if eligible else 0, eligibility_reason, weight,
            source_table, source_id,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def list_baseline_feature_activity(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_key: str,
    feature_name: str,
) -> "list[BaselineFeatureActivityRecord]":
    rows = conn.execute(
        "SELECT * FROM baseline_feature_activity "
        "WHERE entity_type = ? AND entity_key = ? AND feature_name = ? "
        "ORDER BY observed_at",
        (entity_type, entity_key, feature_name),
    ).fetchall()
    return [_row_to_baseline_feature_activity(row) for row in rows]


@dataclass
class BaselineFeatureMaturityRecord:
    id: int
    entity_type: str
    entity_key: str
    feature_name: str
    maturity_state: str
    first_observed_at: "str | None"
    last_observed_at: "str | None"
    first_eligible_observed_at: "str | None"
    last_eligible_observed_at: "str | None"
    observation_count: int
    eligible_weight_total: float
    eligible_distinct_days: int
    updated_at: str


def _row_to_baseline_feature_maturity(row: sqlite3.Row) -> BaselineFeatureMaturityRecord:
    return BaselineFeatureMaturityRecord(**dict(row))


def get_or_create_baseline_feature_maturity(
    conn: sqlite3.Connection, entity_type: str, entity_key: str, feature_name: str
) -> "tuple[BaselineFeatureMaturityRecord, bool]":
    existing = conn.execute(
        "SELECT * FROM baseline_feature_maturity "
        "WHERE entity_type = ? AND entity_key = ? AND feature_name = ?",
        (entity_type, entity_key, feature_name),
    ).fetchone()
    if existing is not None:
        return _row_to_baseline_feature_maturity(existing), False

    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "INSERT INTO baseline_feature_maturity "
        "(entity_type, entity_key, feature_name, maturity_state, observation_count, "
        "eligible_weight_total, eligible_distinct_days, updated_at) "
        "VALUES (?, ?, ?, 'no_baseline', 0, 0, 0, ?)",
        (entity_type, entity_key, feature_name, now),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM baseline_feature_maturity WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return _row_to_baseline_feature_maturity(row), True


def record_feature_maturity_observation(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_key: str,
    feature_name: str,
    observed_at: str,
    eligible: bool,
    weight: float,
) -> BaselineFeatureMaturityRecord:
    """Same counter-update mechanics as
    secure.storage.models.record_baseline_observation(), scoped to one
    (entity, feature_name) pair instead of the whole entity. Does NOT
    compute or write maturity_state — see
    set_baseline_feature_maturity_state() and
    secure.baseline.maturity.compute_maturity(), the same pure function
    baseline_entities' maturity is computed with.
    """
    feature, _ = get_or_create_baseline_feature_maturity(conn, entity_type, entity_key, feature_name)
    now = datetime.now(timezone.utc).isoformat()

    observed_date = observed_at[:10]
    is_new_day = feature.last_observed_at is None or feature.last_observed_at[:10] != observed_date
    new_first_observed_at = feature.first_observed_at or observed_at
    new_observation_count = feature.observation_count + 1

    new_eligible_weight_total = feature.eligible_weight_total
    new_eligible_distinct_days = feature.eligible_distinct_days
    new_first_eligible_observed_at = feature.first_eligible_observed_at
    new_last_eligible_observed_at = feature.last_eligible_observed_at

    if eligible and weight > 0:
        is_new_eligible_day = (
            feature.last_eligible_observed_at is None
            or feature.last_eligible_observed_at[:10] != observed_date
        )
        new_eligible_weight_total = feature.eligible_weight_total + weight
        new_eligible_distinct_days = feature.eligible_distinct_days + (1 if is_new_eligible_day else 0)
        new_first_eligible_observed_at = feature.first_eligible_observed_at or observed_at
        new_last_eligible_observed_at = observed_at

    conn.execute(
        "UPDATE baseline_feature_maturity SET "
        "first_observed_at = ?, last_observed_at = ?, "
        "first_eligible_observed_at = ?, last_eligible_observed_at = ?, "
        "observation_count = ?, eligible_weight_total = ?, eligible_distinct_days = ?, "
        "updated_at = ? WHERE id = ?",
        (
            new_first_observed_at, observed_at,
            new_first_eligible_observed_at, new_last_eligible_observed_at,
            new_observation_count, new_eligible_weight_total, new_eligible_distinct_days,
            now, feature.id,
        ),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM baseline_feature_maturity WHERE id = ?", (feature.id,)).fetchone()
    return _row_to_baseline_feature_maturity(row)


def set_baseline_feature_maturity_state(conn: sqlite3.Connection, feature_id: int, maturity_state: str) -> None:
    conn.execute(
        "UPDATE baseline_feature_maturity SET maturity_state = ? WHERE id = ?",
        (maturity_state, feature_id),
    )
    conn.commit()


def find_baseline_feature_maturity(
    conn: sqlite3.Connection, entity_type: str, entity_key: str, feature_name: str
) -> "BaselineFeatureMaturityRecord | None":
    row = conn.execute(
        "SELECT * FROM baseline_feature_maturity "
        "WHERE entity_type = ? AND entity_key = ? AND feature_name = ?",
        (entity_type, entity_key, feature_name),
    ).fetchone()
    return _row_to_baseline_feature_maturity(row) if row else None


def list_baseline_feature_maturity(
    conn: sqlite3.Connection, entity_type: str, entity_key: str
) -> "list[BaselineFeatureMaturityRecord]":
    rows = conn.execute(
        "SELECT * FROM baseline_feature_maturity WHERE entity_type = ? AND entity_key = ? "
        "ORDER BY feature_name",
        (entity_type, entity_key),
    ).fetchall()
    return [_row_to_baseline_feature_maturity(row) for row in rows]
