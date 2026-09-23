"""Feedback models for Phase 55."""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class AlertFeedback:
    """User feedback on an alert decision."""
    feedback_id: int
    decision_id: int
    verdict: str  # "true_positive" | "false_positive" | "unclear"
    reason: str  # Why user tagged this way
    severity_adjustment: int  # -2 to +2: was alert severity wrong?
    feedback_at: datetime
    feedback_by: str  # User identifier


@dataclass(frozen=True)
class FeedbackStats:
    """Summary of feedback for an alert type."""
    alert_type: str
    total_feedback: int
    true_positives: int
    false_positives: int
    unclear: int
    avg_severity_delta: float
    confidence: float  # 0-1 based on sample size
