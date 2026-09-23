"""
Detection Pipeline Orchestrator — Phase 54 integration.

Orchestrates the complete flow: baseline anomalies → correlation →
alert decision → remediation routing.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from secure.alerting.compose import compose
from secure.alerting.decide import decide_alert
from secure.alerting.store import AlertDecisionStore
from secure.baseline.scoring import tier_for_score
from secure.multi_device.cross_device import CrossDeviceFindingCorrelator, CorrelatedFinding
from secure.storage.models import (
    list_anomaly_events,
    find_baseline_entity,
)


@dataclass
class AnomalyEventSummary:
    """Simplified view of an anomaly event for pipeline use."""
    event_id: int
    run_id: str
    entity_type: str
    entity_path: str
    feature_name: str
    feature_value: str
    observed_at: datetime
    anomaly_tier: str
    raw_score: int
    expected_summary: str
    score_breakdown: Dict
    device_id: Optional[str] = None


@dataclass
class DetectionPipelineEvent:
    """Tracks a detection through the full pipeline."""
    anomaly_summary: AnomalyEventSummary
    correlation_id: Optional[str] = None
    correlated_finding: Optional[CorrelatedFinding] = None
    alert_decision: Optional[dict] = None
    error: Optional[str] = None
    processed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class DetectionPipeline:
    """Orchestrates baseline → correlation → alert → remediation."""

    def __init__(self, db_conn: sqlite3.Connection):
        self.db_conn = db_conn
        self.alert_store = AlertDecisionStore(db_conn)
        self.correlator = CrossDeviceFindingCorrelator()

    def fetch_recent_anomalies(self, minutes: int = 5) -> List[AnomalyEventSummary]:
        """Fetch anomaly events from the last N minutes."""
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        events = list_anomaly_events(self.db_conn)

        summaries = []
        for event in events:
            # Parse observed_at if it's a string
            if isinstance(event.observed_at, str):
                obs_time = datetime.fromisoformat(event.observed_at)
            else:
                obs_time = event.observed_at

            if obs_time >= cutoff:
                summaries.append(AnomalyEventSummary(
                    event_id=event.id,
                    run_id=event.run_id,
                    entity_type=event.entity_type,
                    entity_path=event.entity_key,
                    feature_name=event.feature_name,
                    feature_value=event.observed_value,
                    observed_at=obs_time,
                    anomaly_tier=event.anomaly_tier,
                    raw_score=event.anomaly_score,
                    expected_summary=event.expected_summary,
                    score_breakdown=event.score_breakdown or {},
                    device_id=getattr(event, 'device_id', None),
                ))

        return summaries

    def correlate_anomalies(self, anomalies: List[AnomalyEventSummary]) -> Dict[str, CorrelatedFinding]:
        """Group anomalies by entity type and correlate across devices."""
        # Group findings by entity type for correlation
        for anomaly in anomalies:
            finding = {
                "finding_type": f"{anomaly.entity_type}.{anomaly.feature_name}",
                "entity_path": anomaly.entity_path,
                "feature_value": anomaly.feature_value,
                "raw_score": anomaly.raw_score,
                "timestamp": anomaly.observed_at,
            }

            device_id = anomaly.device_id or "localhost"
            self.correlator.add_device_findings(device_id, [finding])

        # Correlate across devices
        correlated = self.correlator.correlate_findings(
            min_device_count=1,  # Include single-device findings
            time_window_hours=24,
        )

        # Index by finding type
        by_type = {}
        for cf in correlated:
            by_type[cf.finding_type] = cf

        return by_type

    def process_anomaly(
        self,
        anomaly: AnomalyEventSummary,
        correlated_findings: Dict[str, CorrelatedFinding],
    ) -> DetectionPipelineEvent:
        """Process a single anomaly through the alert decision pipeline."""

        event = DetectionPipelineEvent(
            anomaly_summary=anomaly,
            correlation_id=None,
            correlated_finding=None,
        )

        try:
            # Get correlation data if available
            finding_type = f"{anomaly.entity_type}.{anomaly.feature_name}"
            correlated = correlated_findings.get(finding_type)
            peer_count = 0  # Default: no peers saw this finding
            if correlated:
                event.correlation_id = correlated.correlation_id
                event.correlated_finding = correlated
                peer_count = correlated.device_count - 1 if correlated.device_count > 0 else 0

            # Compose alert context from Phase 48/49/50 with peer count from correlation
            alert_context = compose(use_defaults=True, peer_device_count=peer_count)

            # Make alert decision
            decision = decide_alert(
                source_table="anomaly_events",
                source_id=anomaly.event_id,
                entity_type=anomaly.entity_type,
                entity_path=anomaly.entity_path,
                base_severity=anomaly.anomaly_tier.upper(),
                event_timestamp=anomaly.observed_at,
                context=alert_context,
            )

            # Store decision
            event.alert_decision = {
                "verdict": decision.verdict,
                "final_severity": decision.final_severity,
                "reasoning": decision.reasoning,
                "base_severity": decision.base_severity,
            }

            self.alert_store.store_decision(
                decision,
                entity_type=anomaly.entity_type,
                entity_path=anomaly.entity_path,
                correlation_id=event.correlation_id,
                device_count=len(event.correlated_finding.device_ids) if event.correlated_finding else 1,
            )

        except Exception as e:
            event.error = str(e)

        return event


def run_detection_pipeline(
    db_conn: sqlite3.Connection,
    lookback_minutes: int = 5,
) -> List[DetectionPipelineEvent]:
    """Run the full detection pipeline on recent anomalies.

    Args:
        db_conn: Database connection
        lookback_minutes: How far back to fetch anomalies

    Returns:
        List of DetectionPipelineEvent records
    """
    pipeline = DetectionPipeline(db_conn)

    # Fetch recent anomalies
    anomalies = pipeline.fetch_recent_anomalies(minutes=lookback_minutes)
    if not anomalies:
        return []

    # Correlate across devices
    correlated = pipeline.correlate_anomalies(anomalies)

    # Process each anomaly
    results = []
    for anomaly in anomalies:
        event = pipeline.process_anomaly(anomaly, correlated)
        results.append(event)

    return results
