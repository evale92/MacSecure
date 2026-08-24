"""
correlate/scanner.py — orchestrates one correlation pass: collect
signals from every other module's tables, cluster them by time, keep
only clusters that span 2+ distinct modules, score and annotate each
one, and store the new ones. This is the "scan_*" entry point for this
package, same shape as every other package's scanner.py — except there
is nothing to shell out to (see signals.py's module docstring for why
this is the first "scanner" in this app that only reads the database).
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from secure.correlate.analysis import (
    DEFAULT_WINDOW_SECONDS,
    apply_weak_signal_cap,
    build_explanation,
    cluster_signals,
    correlation_score,
    distinct_modules,
    fingerprint_for_cluster,
    max_strength,
    severity_for_score,
)
from secure.correlate.context import apply_context, get_boot_time
from secure.correlate.signals import collect_signals
from secure.storage.models import CorrelationAlertRecord, add_correlation_alert

DEFAULT_LOOKBACK_HOURS = 24.0


@dataclass
class CorrelationResult:
    run_id: str
    scanned_at: str
    window_seconds: float
    lookback_hours: float
    triggered_by: Optional[str]
    signals_considered: int
    clusters_considered: int
    cross_module_clusters: int
    new_alerts: List[CorrelationAlertRecord] = field(default_factory=list)
    # Cross-module clusters that scored this run but were already on
    # record from an earlier run over overlapping history — proof the
    # idempotent fingerprint dedup worked, not an error.
    already_known_clusters: int = 0


def correlate(
    conn: sqlite3.Connection,
    window_seconds: float = DEFAULT_WINDOW_SECONDS,
    lookback_hours: float = DEFAULT_LOOKBACK_HOURS,
    triggered_by: Optional[str] = None,
) -> CorrelationResult:
    """Run one correlation pass over everything already recorded in the
    database within the last `lookback_hours`. Never touches the
    outside world — every signal considered was already written by some
    other scan (see signals.collect_signals()). Safe to re-run
    repeatedly over overlapping history: each cluster's fingerprint is
    content-addressed from its exact member rows, so a cluster already
    on record from an earlier run is silently skipped rather than
    re-inserted (see already_known_clusters on the returned result).
    """
    run_id = uuid.uuid4().hex[:12]
    scanned_at = datetime.now(timezone.utc).isoformat()

    signals = collect_signals(conn, lookback_hours=lookback_hours)
    raw_clusters = cluster_signals(signals, window_seconds=window_seconds)
    cross_module_clusters = [c for c in raw_clusters if len(distinct_modules(c)) >= 2]

    boot_time = get_boot_time()

    new_alerts: List[CorrelationAlertRecord] = []
    already_known = 0

    for cluster in cross_module_clusters:
        raw_score = correlation_score(cluster)
        strongest = max_strength(cluster)
        adjusted_score, context_notes = apply_context(
            cluster, raw_score, triggered_by, boot_time, strongest
        )
        severity = severity_for_score(adjusted_score)
        severity = apply_weak_signal_cap(severity, cluster)
        explanation = build_explanation(cluster, raw_score, adjusted_score, severity, context_notes)
        fingerprint = fingerprint_for_cluster(cluster)

        record, was_new = add_correlation_alert(
            conn,
            run_id=run_id,
            fingerprint=fingerprint,
            window_seconds=window_seconds,
            cluster_start=cluster[0].timestamp.isoformat(),
            cluster_end=cluster[-1].timestamp.isoformat(),
            module_count=len(distinct_modules(cluster)),
            signal_count=len(cluster),
            score=adjusted_score,
            severity=severity,
            triggered_by=triggered_by,
            context_notes=context_notes,
            explanation=explanation,
            members=[signal.as_dict() for signal in cluster],
        )
        if was_new:
            new_alerts.append(record)
        else:
            already_known += 1

    return CorrelationResult(
        run_id=run_id,
        scanned_at=scanned_at,
        window_seconds=window_seconds,
        lookback_hours=lookback_hours,
        triggered_by=triggered_by,
        signals_considered=len(signals),
        clusters_considered=len(raw_clusters),
        cross_module_clusters=len(cross_module_clusters),
        new_alerts=new_alerts,
        already_known_clusters=already_known,
    )
