"""
Remediation storage models — database access for outcomes and policies.

Phase 50 adds learning loop storage: reading efficacy outcomes for playbook tuning.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from secure.remediation.outcomes import RemediationOutcome, OutcomeStatus, PreScanSnapshot, PostScanSnapshot


def insert_outcome(conn, outcome: RemediationOutcome, execution_id: str) -> bool:
    """Insert an outcome record. Returns True if successful."""
    try:
        pre_scan_json = json.dumps({
            "scan_id": outcome.pre_scan.scan_id,
            "timestamp": outcome.pre_scan.timestamp.isoformat(),
            "finding_count": outcome.pre_scan.finding_count,
            "anomaly_score": outcome.pre_scan.anomaly_score,
        }) if outcome.pre_scan else None

        post_scan_json = json.dumps({
            "scan_id": outcome.post_scan.scan_id,
            "timestamp": outcome.post_scan.timestamp.isoformat(),
            "elapsed_seconds": outcome.post_scan.elapsed_seconds,
            "finding_count": outcome.post_scan.finding_count,
            "anomaly_score": outcome.post_scan.anomaly_score,
        }) if outcome.post_scan else None

        conn.execute("""
            INSERT INTO remediation_outcomes
            (outcome_id, execution_id, action_id, created_at, measured_at,
             pre_scan_json, post_scan_json, status, findings_reduced,
             anomaly_score_change, services_disabled, destinations_isolated,
             time_to_effect, effectiveness, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            outcome.outcome_id,
            execution_id,
            outcome.action_id,
            outcome.created_at.isoformat(),
            outcome.measured_at.isoformat() if outcome.measured_at else None,
            pre_scan_json,
            post_scan_json,
            outcome.status.value,
            outcome.findings_reduced,
            outcome.anomaly_score_change,
            outcome.services_disabled,
            outcome.destinations_isolated,
            outcome.time_to_effect,
            outcome.effectiveness,
            outcome.reason,
        ))
        conn.commit()
        return True
    except Exception:
        return False


def get_outcomes_for_action(conn, action_id: str, days: int = 90) -> list[RemediationOutcome]:
    """Read all outcomes for an action, optionally within a time window (days)."""
    cursor = conn.execute("""
        SELECT outcome_id, execution_id, action_id, created_at, measured_at,
               pre_scan_json, post_scan_json, status, findings_reduced,
               anomaly_score_change, services_disabled, destinations_isolated,
               time_to_effect, effectiveness, reason
        FROM remediation_outcomes
        WHERE action_id = ?
        AND datetime(created_at) >= datetime('now', ?)
        ORDER BY created_at DESC
    """, (action_id, f"-{days} days"))

    outcomes = []
    for row in cursor.fetchall():
        pre_scan = None
        if row[5]:
            d = json.loads(row[5])
            pre_scan = PreScanSnapshot(
                scan_id=d["scan_id"],
                timestamp=datetime.fromisoformat(d["timestamp"]),
                finding_count=d["finding_count"],
                anomaly_score=d["anomaly_score"],
            )

        post_scan = None
        if row[6]:
            d = json.loads(row[6])
            post_scan = PostScanSnapshot(
                scan_id=d["scan_id"],
                timestamp=datetime.fromisoformat(d["timestamp"]),
                elapsed_seconds=d["elapsed_seconds"],
                finding_count=d["finding_count"],
                anomaly_score=d["anomaly_score"],
            )

        outcome = RemediationOutcome(
            outcome_id=row[0],
            execution_id=row[1],
            action_id=row[2],
            created_at=datetime.fromisoformat(row[3]),
            measured_at=datetime.fromisoformat(row[4]) if row[4] else None,
            pre_scan=pre_scan,
            post_scan=post_scan,
            status=OutcomeStatus(row[7]),
            findings_reduced=row[8],
            anomaly_score_change=row[9],
            services_disabled=row[10],
            destinations_isolated=row[11],
            time_to_effect=row[12],
            effectiveness=row[13],
            reason=row[14],
        )
        outcomes.append(outcome)

    return outcomes
