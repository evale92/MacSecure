"""Feedback CLI commands (Phase 62)."""

from __future__ import annotations
import argparse
import json
import sys
from datetime import datetime

from secure.feedback.store import FeedbackStore
from secure.storage.alerting_schema import init_alerting_schema
import sqlite3


def cmd_feedback_submit(args: argparse.Namespace) -> int:
    """Submit feedback on an alert decision."""
    conn = sqlite3.connect(f"{sys.argv[0]}/../../../.secure/secure.db")
    init_alerting_schema(conn)

    store = FeedbackStore(conn)

    # Validate inputs
    if args.verdict not in ("true_positive", "false_positive", "unclear"):
        print(f"Error: verdict must be true_positive, false_positive, or unclear", file=sys.stderr)
        return 1

    if not -2 <= args.severity_adjustment <= 2:
        print(f"Error: severity_adjustment must be between -2 and 2", file=sys.stderr)
        return 1

    feedback_id = store.record_feedback(
        decision_id=args.decision_id,
        verdict=args.verdict,
        reason=args.reason or "",
        severity_adjustment=args.severity_adjustment or 0,
        feedback_by=args.feedback_by or "user",
    )

    if args.json:
        print(json.dumps({
            "feedback_id": feedback_id,
            "decision_id": args.decision_id,
            "verdict": args.verdict,
            "timestamp": datetime.now().isoformat(),
        }))
    else:
        print(f"Feedback recorded (id={feedback_id})")

    conn.close()
    return 0


def cmd_feedback_review(args: argparse.Namespace) -> int:
    """Review recent feedback."""
    conn = sqlite3.connect(f"{sys.argv[0]}/../../../.secure/secure.db")
    init_alerting_schema(conn)

    store = FeedbackStore(conn)
    feedback_list = store.get_recent_feedback(limit=args.limit or 50)

    if not feedback_list:
        print("No feedback found")
        conn.close()
        return 0

    if args.json:
        print(json.dumps([
            {
                "feedback_id": f.feedback_id,
                "decision_id": f.decision_id,
                "verdict": f.verdict,
                "reason": f.reason,
                "severity_adjustment": f.severity_adjustment,
                "feedback_by": f.feedback_by,
                "timestamp": f.feedback_at.isoformat(),
            }
            for f in feedback_list
        ]))
    else:
        for f in feedback_list:
            print(f"[{f.feedback_id}] decision={f.decision_id} verdict={f.verdict} ({f.feedback_by})")
            if f.reason:
                print(f"    Reason: {f.reason}")
            if f.severity_adjustment != 0:
                print(f"    Severity adj: {f.severity_adjustment:+d}")

    conn.close()
    return 0


def cmd_feedback_stats(args: argparse.Namespace) -> int:
    """Show feedback statistics."""
    conn = sqlite3.connect(f"{sys.argv[0]}/../../../.secure/secure.db")
    init_alerting_schema(conn)

    store = FeedbackStore(conn)

    stats = store.get_feedback_stats(alert_type=args.alert_type)
    counts = store.count_by_verdict()

    if not stats:
        print("No feedback data available")
        conn.close()
        return 0

    if args.json:
        print(json.dumps({
            "alert_type": stats.alert_type,
            "total_feedback": stats.total_feedback,
            "true_positives": stats.true_positives,
            "false_positives": stats.false_positives,
            "unclear": stats.unclear,
            "avg_severity_delta": stats.avg_severity_delta,
            "confidence": stats.confidence,
        }))
    else:
        print(f"Feedback for {stats.alert_type}:")
        print(f"  Total: {stats.total_feedback}")
        print(f"  True positives: {stats.true_positives} ({100*stats.true_positives/stats.total_feedback:.1f}%)")
        print(f"  False positives: {stats.false_positives} ({100*stats.false_positives/stats.total_feedback:.1f}%)")
        print(f"  Unclear: {stats.unclear} ({100*stats.unclear/stats.total_feedback:.1f}%)")
        print(f"  Avg severity adjustment: {stats.avg_severity_delta:+.2f}")
        print(f"  Confidence: {stats.confidence:.1%} (based on {stats.total_feedback} samples)")

    conn.close()
    return 0
