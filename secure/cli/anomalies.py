from __future__ import annotations

import argparse
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from secure.storage.database import Database
from secure.storage.models import (
    find_anomaly_event_by_id,
    find_baseline_entity,
    list_anomaly_events,
    set_anomaly_event_known,
)
from secure.cli import _bootstrap, _record_anomaly_review_change, logger

def cmd_anomalies_list(args: argparse.Namespace) -> int:
    """`secure anomalies list` (Stage 4E) — filters: tier, entity_type,
    known/unknown, and a recent-time window (--since-hours). Kept
    deliberately minimal per Stage 4 approval item 6 ("do not overbuild
    filtering in this stage") — combine with `secure baseline show` for
    a specific entity's full picture.
    """
    cfg = _bootstrap()

    since = None
    if args.since_hours is not None:
        since = (datetime.now(timezone.utc) - timedelta(hours=args.since_hours)).isoformat()
    known = True if args.known else (False if args.unknown else None)

    with Database(cfg.database_path()) as db:
        events = list_anomaly_events(
            db.conn, entity_type=args.entity_type, tier=args.tier,
            known=known, since=since, limit=args.limit,
        )

    if not events:
        print("No anomaly events match those filters.")
        return 0

    for e in events:
        tag = "KNOWN" if e.known else "UNKNOWN"
        print(
            f"[{tag:7}] #{e.id:<5} [{e.anomaly_tier.upper():8}] score {e.anomaly_score:<3} "
            f"{e.entity_type}/{e.entity_key} — {e.feature_name}={e.observed_value} — {e.observed_at}"
        )

    return 0


def cmd_anomalies_show(args: argparse.Namespace) -> int:
    """`secure anomalies show <id>` (Stage 4E) — full score breakdown,
    expected-summary, source reference, and the entity's CURRENT
    baseline state alongside what it was AT THE TIME this anomaly was
    scored (surfaced as caveats when the two have since diverged — e.g.
    the entity has since been excluded/frozen, or matured further).
    Deliberately does not duplicate Product Phase 13's narrative
    explanation prose — that integration is Stage 5 (secure/explain/).
    """
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        conn = db.conn
        event = find_anomaly_event_by_id(conn, args.event_id)
        if event is None:
            print(f"No anomaly event found with id {args.event_id}. Run `secure anomalies list` to see recorded events.")
            return 1
        entity = find_baseline_entity(conn, event.entity_type, event.entity_key)

    tag = "KNOWN" if event.known else "UNKNOWN"
    print(f"Anomaly #{event.id} [{tag}] [{event.anomaly_tier.upper()}] score {event.anomaly_score}")
    print(f"Entity:      {event.entity_type} / {event.entity_key}")
    print(f"Feature:     {event.feature_name} = {event.observed_value}")
    print(f"Observed at: {event.observed_at}")
    print(f"Recorded:    {event.created_at}  (run {event.run_id})")
    if event.source_table:
        print(f"Source:      {event.source_table}#{event.source_id}")
    print()
    print(f"Expected: {event.expected_summary}")
    print()
    print("Score breakdown:")
    for component, points in event.score_breakdown.items():
        print(f"  {component:18} {points}")
    print()
    print(f"Maturity at time of observation: {event.maturity_state_at_time}")
    print(
        f"Eligible weight at time: {event.eligible_weight_total_at_time:g} "
        f"({event.eligible_distinct_days_at_time} distinct days)"
    )

    caveats = []
    if entity is None:
        caveats.append(
            "no entity-level baseline record exists for this entity right now "
            "(feature-only entity_types never get one from a scanner — only "
            "an operator action like exclude/freeze/reset creates one)"
        )
    else:
        if entity.excluded:
            caveats.append("this entity is currently EXCLUDED from baseline scoring")
        if entity.frozen:
            caveats.append("this entity is currently FROZEN (baseline not adapting)")
        if entity.maturity_state != event.maturity_state_at_time:
            caveats.append(
                f"this entity's maturity has since changed to '{entity.maturity_state}' "
                f"(was '{event.maturity_state_at_time}' at the time)"
            )
    if caveats:
        print()
        print("Caveats:")
        for c in caveats:
            print(f"  - {c}")

    return 0


def cmd_anomalies_mark(args: argparse.Namespace) -> int:
    """`secure anomalies mark <id> known|unknown` (Stage 4E/4F) — same
    known/unknown review-state pattern as every other `mark`/`mark-alert`
    command in this file, plus append-only review history via
    _record_anomaly_review_change() whenever the state actually changes
    (a no-op re-mark writes nothing new, same as every alert source).
    """
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        event = find_anomaly_event_by_id(db.conn, args.event_id)
        if event is None:
            print(
                f"No anomaly event found with id {args.event_id}. "
                "Run `secure anomalies list` to see recorded events."
            )
            return 1
        if event.known != known:
            _record_anomaly_review_change(db.conn, event=event, was_known=event.known, now_known=known)
        set_anomaly_event_known(db.conn, event.id, known)

    print(
        f"Marked anomaly #{args.event_id} ({event.entity_type}/{event.entity_key}, "
        f"{event.feature_name}) as {args.status}."
    )
    logger.info(
        "Marked an anomaly event known/unknown",
        extra={"event": "anomaly_mark", "component": "cli"},
    )
    return 0
