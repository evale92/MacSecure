from __future__ import annotations

import argparse
from secure.baseline.constants import (
    ANOMALY_TIERS,
    DEFAULT_ENTITY_CAP,
    ENTITY_CAPS,
)
from secure.baseline.entities import ENTITY_TYPES
from secure.storage.database import Database
from secure.storage.models import (
    count_anomaly_events,
    count_baseline_entities,
    count_baseline_entities_by_maturity,
    count_baseline_entities_excluded,
    count_baseline_entities_frozen,
    count_baseline_runs,
    find_baseline_entity,
    find_latest_baseline_run,
    get_or_create_baseline_entity,
    list_anomaly_events,
    list_baseline_entities,
    list_baseline_feature_maturity,
    reset_baseline_entity,
    set_baseline_entity_excluded,
    set_baseline_entity_frozen,
)
from secure.cli import _bootstrap, logger

def cmd_baseline_status(args: argparse.Namespace) -> int:
    """`secure baseline status` (Stage 4D) — an at-a-glance operator
    view of the whole Phase 14 baseline subsystem: how many entities
    exist and at what maturity, how many are excluded/frozen, anomaly
    counts by tier, the most recent baseline run, how many runs were
    partial/failed, and per-entity_type cap usage — reaching a cap is
    never silent (see ENTITY_CAPS in secure/baseline/constants.py).
    """
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        conn = db.conn
        total_entities = count_baseline_entities(conn)
        maturity_counts = count_baseline_entities_by_maturity(conn)
        excluded_count = count_baseline_entities_excluded(conn)
        frozen_count = count_baseline_entities_frozen(conn)
        cap_usage = {
            et: (count_baseline_entities(conn, et), ENTITY_CAPS.get(et, DEFAULT_ENTITY_CAP))
            for et in ENTITY_TYPES
        }
        total_anomalies = count_anomaly_events(conn)
        tier_counts = {tier: count_anomaly_events(conn, tier=tier) for tier in ANOMALY_TIERS}
        unreviewed_anomalies = count_anomaly_events(conn, known=False)
        latest_run = find_latest_baseline_run(conn)
        total_runs = count_baseline_runs(conn)
        partial_runs = count_baseline_runs(conn, status="partial")
        failed_runs = count_baseline_runs(conn, status="failed")

    print("Baseline status")
    print(f"Total entities: {total_entities}")
    print()
    print("By maturity:")
    if maturity_counts:
        for state, n in sorted(maturity_counts.items()):
            print(f"  {state:14} {n}")
    else:
        print("  (none yet)")
    print()
    print(f"Excluded: {excluded_count}   Frozen: {frozen_count}")
    print()
    print("Per entity_type cap usage:")
    for et in ENTITY_TYPES:
        n, cap = cap_usage[et]
        marker = "  <-- near/at cap" if cap and n / cap >= 0.9 else ""
        print(f"  {et:20} {n:>6} / {cap}{marker}")
    print()
    print(f"Anomaly events: {total_anomalies} total ({unreviewed_anomalies} awaiting review)")
    for tier in ANOMALY_TIERS:
        print(f"  {tier:10} {tier_counts[tier]}")
    print()
    if latest_run is None:
        print("No baseline runs recorded yet.")
    else:
        print(f"Most recent baseline run: {latest_run.run_id} ({latest_run.status})")
        print(f"  started:   {latest_run.started_at}")
        print(f"  completed: {latest_run.completed_at or '(never completed)'}")
        print(
            f"  entities:  {latest_run.entities_evaluated} evaluated, "
            f"{latest_run.entities_updated} updated"
        )
        print(
            f"  features:  {latest_run.features_evaluated} evaluated, "
            f"{latest_run.features_updated} updated"
        )
        print(f"  anomalies generated: {latest_run.anomalies_generated}")
        if latest_run.incomplete_inputs:
            print(f"  incomplete inputs: {latest_run.incomplete_inputs}")
        if latest_run.entities_skipped_cap:
            print(
                "  entities skipped (entity_type cap reached): "
                f"{latest_run.entities_skipped_cap}"
            )
        if latest_run.errors_count:
            print(f"  errors: {latest_run.errors_count}")
            if latest_run.error_summary:
                for err in latest_run.error_summary:
                    print(f"    - {err}")
    print()
    print(f"Baseline run history: {total_runs} total ({partial_runs} partial, {failed_runs} failed)")

    return 0


def cmd_baseline_list(args: argparse.Namespace) -> int:
    """`secure baseline list` (Stage 4D) — list baseline entities,
    optionally filtered. Deliberately just plain equality filters (no
    query builder), matching the "do not overbuild filtering" guidance
    used for `secure anomalies list` too.
    """
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        entities = list_baseline_entities(
            db.conn,
            entity_type=args.entity_type,
            maturity_state=args.maturity,
            excluded=args.excluded,
            frozen=args.frozen,
        )

    if not entities:
        print("No baseline entities match those filters.")
        return 0

    for e in entities:
        flags = []
        if e.excluded:
            flags.append("EXCLUDED")
        if e.frozen:
            flags.append("FROZEN")
        flag_str = f"  [{', '.join(flags)}]" if flags else ""
        print(
            f"{e.entity_type:20} {e.entity_key:40} {e.maturity_state:12} "
            f"obs={e.observation_count:<5} eligible_weight={e.eligible_weight_total:g}{flag_str}"
        )

    return 0


def cmd_baseline_show(args: argparse.Namespace) -> int:
    """`secure baseline show <entity_type> <entity_key>` (Stage 4D) —
    one entity's full baseline detail: entity-level counters (if any —
    feature-only entity_types like persistence/listening/wifi never
    get one from a scanner, only from an operator action like
    exclude/freeze), every tracked feature's own maturity, and its most
    recent anomaly events.
    """
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        conn = db.conn
        entity = find_baseline_entity(conn, args.entity_type, args.entity_key)
        features = list_baseline_feature_maturity(conn, args.entity_type, args.entity_key)
        anomalies = list_anomaly_events(conn, args.entity_type, args.entity_key, limit=10)

    print(f"{args.entity_type} / {args.entity_key}")
    print()
    if entity is None:
        print(
            "No entity-level baseline record yet (this entity_type may only be "
            "tracked at the feature level until an operator action like exclude/"
            "freeze/reset creates one)."
        )
    else:
        print(f"Maturity:     {entity.maturity_state}")
        print(f"Excluded:     {entity.excluded}   Frozen: {entity.frozen}")
        print(f"Observations: {entity.observation_count} ({entity.distinct_days_observed} distinct days)")
        print(
            f"Eligible weight: {entity.eligible_weight_total:g} "
            f"({entity.eligible_distinct_days} distinct eligible days)"
        )
        print(f"First observed:  {entity.first_observed_at or '(never)'}")
        print(f"Last observed:   {entity.last_observed_at or '(never)'}")
        print(f"First eligible:  {entity.first_eligible_observed_at or '(never)'}")
        print(f"Last eligible:   {entity.last_eligible_observed_at or '(never)'}")
    print()

    if features:
        print("Feature maturity:")
        for f in features:
            print(
                f"  {f.feature_name:20} {f.maturity_state:12} "
                f"eligible_weight={f.eligible_weight_total:g} "
                f"({f.eligible_distinct_days} distinct days)  "
                f"last_observed={f.last_observed_at or '(never)'}"
            )
        print()

    if anomalies:
        print("Recent anomaly events (up to 10):")
        for a in anomalies:
            tag = "KNOWN" if a.known else "UNKNOWN"
            print(
                f"  [{tag:7}] #{a.id:<4} [{a.anomaly_tier.upper():8}] score {a.anomaly_score} "
                f"— {a.feature_name}={a.observed_value} — {a.observed_at}"
            )
            print(f"            {a.expected_summary}")
    else:
        print("No anomaly events recorded for this entity.")

    return 0


def _set_baseline_flag(
    args: argparse.Namespace,
    *,
    excluded: "bool | None" = None,
    frozen: "bool | None" = None,
    verb: str,
    event: str,
) -> int:
    """Shared body for exclude/include/freeze/unfreeze — all four are
    "flip one flag on the entity row, creating the row first if this
    entity_type has never had one" (see get_or_create_baseline_entity's
    docstring; feature-only entity_types like persistence/listening/
    wifi need this to establish a row before their first operator
    action).
    """
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        entity, _ = get_or_create_baseline_entity(db.conn, args.entity_type, args.entity_key)
        if excluded is not None:
            set_baseline_entity_excluded(db.conn, entity.id, excluded)
        if frozen is not None:
            set_baseline_entity_frozen(db.conn, entity.id, frozen)

    print(f"{verb} {args.entity_type} '{args.entity_key}'.")
    logger.info(verb, extra={"event": event, "component": "cli"})
    return 0


def cmd_baseline_exclude(args: argparse.Namespace) -> int:
    return _set_baseline_flag(
        args, excluded=True, verb="Excluded", event="baseline_exclude"
    )


def cmd_baseline_include(args: argparse.Namespace) -> int:
    return _set_baseline_flag(
        args, excluded=False, verb="Included (un-excluded)", event="baseline_include"
    )


def cmd_baseline_freeze(args: argparse.Namespace) -> int:
    return _set_baseline_flag(
        args, frozen=True, verb="Froze", event="baseline_freeze"
    )


def cmd_baseline_unfreeze(args: argparse.Namespace) -> int:
    return _set_baseline_flag(
        args, frozen=False, verb="Unfroze", event="baseline_unfreeze"
    )


def cmd_baseline_reset(args: argparse.Namespace) -> int:
    """`secure baseline reset` (Stage 4D/4G) — clear one entity's
    learned baseline back to no_baseline (see
    reset_baseline_entity()'s docstring for exactly what is and isn't
    touched: raw observation history and past anomaly findings are
    always preserved). Never resets everything via an omitted entity —
    that requires the explicit `--all` flag, and `--all` itself is
    inert without `--yes` (it only previews what would happen), so a
    bare `secure baseline reset` can never accidentally wipe every
    entity's baseline.
    """
    cfg = _bootstrap()

    if args.all:
        if args.entity_type is not None or args.entity_key is not None:
            print(
                "Don't combine --all with a specific entity_type/entity_key — "
                "use one or the other."
            )
            return 1
        with Database(cfg.database_path()) as db:
            candidates = list_baseline_entities(db.conn, entity_type=args.all_entity_type)
            if not args.yes:
                scope = f" of type '{args.all_entity_type}'" if args.all_entity_type else ""
                print(
                    f"This would reset {len(candidates)} "
                    f"entit{'y' if len(candidates) == 1 else 'ies'}{scope}."
                )
                print(
                    "Maturity/statistics would be cleared back to no_baseline; raw "
                    "observation history and past anomaly findings are always preserved."
                )
                print("Re-run with --all --yes to actually do this.")
                return 1
            reset_count = 0
            for entity in candidates:
                if reset_baseline_entity(db.conn, entity.entity_type, entity.entity_key):
                    reset_count += 1
        print(f"Reset {reset_count} entit{'y' if reset_count == 1 else 'ies'}.")
        logger.info(
            "Reset baseline entities (--all)",
            extra={"event": "baseline_reset_all", "component": "cli"},
        )
        return 0

    if args.entity_type is None or args.entity_key is None:
        print(
            "Provide both entity_type and entity_key (e.g. `secure baseline reset "
            "process /usr/bin/curl`), or use --all --yes to reset more than one."
        )
        return 1

    with Database(cfg.database_path()) as db:
        get_or_create_baseline_entity(db.conn, args.entity_type, args.entity_key)
        reset_baseline_entity(db.conn, args.entity_type, args.entity_key)

    print(
        f"Reset baseline for {args.entity_type} '{args.entity_key}' — maturity back "
        "to no_baseline; raw history and past anomalies preserved."
    )
    logger.info(
        "Reset one baseline entity",
        extra={"event": "baseline_reset", "component": "cli"},
    )
    return 0
