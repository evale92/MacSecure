from __future__ import annotations

import argparse
from secure.correlate import correlate
from secure.correlate.chain_scanner import run_chain_correlation
from secure.storage.database import Database
from secure.storage.models import (
    find_correlation_alert_by_id,
    find_correlation_chain_alert_by_id,
    list_correlation_alerts,
    list_correlation_chain_alerts,
    set_correlation_alert_known,
    set_correlation_chain_alert_known,
)
from secure.cli import _bootstrap, _record_alert_review_change, logger

def cmd_correlate_run(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        result = correlate(
            db.conn,
            window_seconds=args.window,
            lookback_hours=args.lookback_hours,
            triggered_by=None,
        )

    print(
        f"Correlation pass at {result.scanned_at} (run id: {result.run_id}) — "
        f"window {result.window_seconds:.0f}s, lookback {result.lookback_hours:.0f}h"
    )
    print(f"Signals considered: {result.signals_considered}")
    print(
        f"Time-clusters found: {result.clusters_considered} "
        f"({result.cross_module_clusters} spanning 2+ modules)"
    )
    if result.already_known_clusters:
        print(f"Already on record from an earlier run: {result.already_known_clusters}")
    print()

    if result.new_alerts:
        print(f"NEW CORRELATION ALERTS ({len(result.new_alerts)}):")
        for alert in sorted(result.new_alerts, key=lambda a: a.id, reverse=True):
            print(
                f"  #{alert.id} [{alert.severity.upper()}] score {alert.score} — "
                f"{alert.module_count} modules, {alert.signal_count} signals "
                f"({alert.cluster_start} to {alert.cluster_end})"
            )
        print()
        print("Details: secure correlate list")
        print("Review these, then: secure correlate mark-alert <id> known|unknown")
    else:
        print("No new cross-module correlation clusters this run.")

    logger.info(
        "Ran a correlation pass",
        extra={"event": "correlate", "component": "cli"},
    )
    return 1 if result.new_alerts else 0


def cmd_correlate_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        alerts = list_correlation_alerts(db.conn)

    if not alerts:
        print(
            "No correlation alerts recorded yet. Run `secure correlate run` "
            "(or `secure run-all`, which runs every scan and then correlates)."
        )
        return 0

    for alert in alerts:
        tag = "KNOWN" if alert.known else "UNKNOWN"
        print(
            f"[{tag:7}] #{alert.id:<4} [{alert.severity.upper():13}] score {alert.score} — "
            f"{alert.module_count} modules, {alert.signal_count} signals — {alert.created_at}"
        )
        print(f"          {alert.cluster_start} to {alert.cluster_end}")
        for line in alert.explanation.splitlines():
            print(f"          {line}")
        print()

    return 0


def cmd_correlate_mark_alert(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        alert = find_correlation_alert_by_id(db.conn, args.alert_id)
        if alert is None:
            print(
                f"No correlation alert found with id {args.alert_id}. "
                "Run `secure correlate list` to see recorded alerts."
            )
            return 1
        if alert.known != known:
            _record_alert_review_change(
                db.conn, source_table="correlation_alerts", alert_id=alert.id,
                subject=f"{alert.module_count}-module cluster",
                severity=alert.severity, was_known=alert.known, now_known=known,
            )
        set_correlation_alert_known(db.conn, alert.id, known)

    print(f"Marked #{args.alert_id} as {args.status}.")
    logger.info(
        "Marked a correlation alert known/unknown",
        extra={"event": "correlate_mark_alert", "component": "cli"},
    )
    return 0


# ---------- Phase 22: provenance-aware CHAIN correlation ----------
#
# A separate, parallel command family — "secure correlate chains ..." —
# not a replacement for anything above. Nothing above this comment
# calls into chains.py/chain_scanner.py, and nothing below reads or
# writes correlation_alerts.


def cmd_correlate_chains_run(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        result = run_chain_correlation(db.conn, lookback_hours=args.lookback_hours)

    print(
        f"Chain correlation pass at {result.scanned_at} (run id: {result.run_id}) — "
        f"lookback {result.lookback_hours:.0f}h"
    )
    print(f"Candidate starting nodes: {result.candidate_start_count}")
    print(f"Chains scored this pass: {result.chains_scored}")
    if result.already_known_chains:
        print(f"Already on record from an earlier run: {result.already_known_chains}")
    print()

    if result.new_alerts:
        print(f"NEW CHAIN ALERTS ({len(result.new_alerts)}):")
        for alert in sorted(result.new_alerts, key=lambda a: a.id, reverse=True):
            print(
                f"  #{alert.id} [{alert.severity.upper()}] confidence {alert.confidence} "
                f"score {alert.score} — {alert.independent_fact_count} independent fact(s), "
                f"{alert.module_count} module(s), {alert.meaningful_relationship_count} "
                "meaningful relationship(s)"
            )
        print()
        print("Details: secure correlate chains list")
        print("Review these, then: secure correlate chains mark-alert <id> known|unknown")
    else:
        print("No new evidence chains this run.")

    logger.info(
        "Ran a chain correlation pass",
        extra={"event": "correlate_chains", "component": "cli"},
    )
    return 1 if result.new_alerts else 0


def cmd_correlate_chains_list(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        alerts = list_correlation_chain_alerts(db.conn)

    if not alerts:
        print(
            "No chain alerts recorded yet. Run `secure correlate chains run` "
            "(or `secure run-all`, which runs every scan; chain correlation still "
            "needs its own explicit `chains run` pass — see Phase 22 in PROJECT_NOTES.md)."
        )
        return 0

    for alert in alerts:
        tag = "KNOWN" if alert.known else "UNKNOWN"
        print(
            f"[{tag:7}] #{alert.id:<4} [{alert.severity.upper():13}] "
            f"confidence {alert.confidence:20} score {alert.score} — "
            f"{alert.independent_fact_count} fact(s), {alert.module_count} module(s), "
            f"{alert.meaningful_relationship_count} meaningful relationship(s) — {alert.created_at}"
        )
        print(f"          start: {alert.start_source_table}:{alert.start_source_id}")
        for line in alert.explanation.splitlines():
            print(f"          {line}")
        print()

    return 0


def cmd_correlate_chains_mark_alert(args: argparse.Namespace) -> int:
    cfg = _bootstrap()
    known = args.status == "known"

    with Database(cfg.database_path()) as db:
        alert = find_correlation_chain_alert_by_id(db.conn, args.alert_id)
        if alert is None:
            print(
                f"No chain alert found with id {args.alert_id}. "
                "Run `secure correlate chains list` to see recorded alerts."
            )
            return 1
        if alert.known != known:
            _record_alert_review_change(
                db.conn, source_table="correlation_chain_alerts", alert_id=alert.id,
                subject=f"{alert.independent_fact_count}-fact chain",
                severity=alert.severity, was_known=alert.known, now_known=known,
            )
        set_correlation_chain_alert_known(db.conn, alert.id, known)

    print(f"Marked #{args.alert_id} as {args.status}.")
    logger.info(
        "Marked a chain alert known/unknown",
        extra={"event": "correlate_chains_mark_alert", "component": "cli"},
    )
    return 0
