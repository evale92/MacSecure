"""
Detection Pipeline — Phase 54: Integration with Detection Pipeline.

Wires the baseline anomaly detection system (Phase 14) through correlation
(Phase 49), alert decision (Phase 53), and remediation (Phase 48).

Flow:
  1. Fetch recent anomaly events from baseline
  2. Group by entity type and correlate across devices
  3. Compose AlertContext from Phase 48/49/50 state
  4. Call decide_alert() to make alert decisions
  5. Store decisions and queue remediation
"""

from secure.detection_pipeline.orchestrator import (
    DetectionPipelineEvent,
    run_detection_pipeline,
)

__all__ = ["DetectionPipelineEvent", "run_detection_pipeline"]
