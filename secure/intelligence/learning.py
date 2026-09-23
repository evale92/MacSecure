"""Learning loop — generate threshold proposals from remediation outcomes (Phase 50.3).

Sits above remediation tier; reads outcomes table, never imports remediation code.
All proposals are recommendations only — never auto-applied.
"""

from __future__ import annotations

import math
from typing import Optional

from secure.intelligence.models import (
    EfficacySummary, ThresholdProposal, PROPOSE_RAISE, PROPOSE_LOWER, PROPOSE_HOLD
)

MIN_SAMPLES = 10
HARD_MIN_THRESHOLD = 20
HARD_MAX_THRESHOLD = 95
GRID_STEP = 10
CONFIDENCE_TARGET = 0.40


def _wilson_lower_bound(successes: int, total: int, confidence: float = 0.95) -> float:
    """Calculate Wilson score interval lower bound.

    Used instead of raw rate because with small n, raw rate is wildly optimistic.
    With n=10, Wilson lower bound is much more realistic.
    """
    if total == 0:
        return 0.0

    p_hat = successes / total
    z = 1.96 if confidence == 0.95 else 2.576

    denominator = 1 + (z * z) / total
    center = (p_hat + (z * z) / (2 * total)) / denominator
    margin = z * math.sqrt(p_hat * (1 - p_hat) / total + (z * z) / (4 * total * total)) / denominator

    lower = center - margin
    return max(0.0, lower)


class LearningEngine:
    """Generate playbook threshold proposals from efficacy history."""

    def __init__(self):
        """Initialize learning engine."""
        pass

    def analyze_action_efficacy(
        self,
        action_id: str,
        outcomes: list,
    ) -> EfficacySummary:
        """Analyze all outcomes for an action and generate summary.

        Args:
            action_id: ID of the remediation action
            outcomes: List of RemediationOutcome objects from storage

        Returns:
            EfficacySummary with honest denominator (all measured, not just successful)
        """
        measured = 0
        effective = 0
        ineffective = 0
        inconclusive = 0

        for outcome in outcomes:
            if outcome.post_scan is not None:
                measured += 1
                if outcome.effectiveness in ("high", "medium"):
                    effective += 1
                elif outcome.effectiveness == "none":
                    ineffective += 1
                else:
                    inconclusive += 1

        if measured == 0:
            return EfficacySummary(
                action_id=action_id,
                measured=0,
                effective=0,
                ineffective=0,
                inconclusive=0,
                success_rate=0.0,
                success_rate_lower=0.0,
                avg_findings_reduced=0.0,
                avg_time_to_effect=0.0,
            )

        success_rate = effective / measured
        success_rate_lower = _wilson_lower_bound(effective, measured)

        avg_reduced = sum(o.findings_reduced for o in outcomes if o.post_scan) / measured
        avg_time = sum(o.time_to_effect for o in outcomes if o.post_scan) / measured

        return EfficacySummary(
            action_id=action_id,
            measured=measured,
            effective=effective,
            ineffective=ineffective,
            inconclusive=inconclusive,
            success_rate=success_rate,
            success_rate_lower=success_rate_lower,
            avg_findings_reduced=avg_reduced,
            avg_time_to_effect=avg_time,
        )

    def propose_threshold_adjustment(
        self,
        playbook_id: str,
        current_threshold: float,
        efficacy: EfficacySummary,
        shadow_scores: Optional[list[float]] = None,
    ) -> ThresholdProposal:
        """Generate a threshold proposal for a playbook.

        Args:
            playbook_id: ID of the playbook to adjust
            current_threshold: Current anomaly_score threshold
            efficacy: EfficacySummary for outcomes
            shadow_scores: Optional list of anomaly scores from evaluations

        Returns:
            ThresholdProposal with direction (RAISE/LOWER/HOLD) and proposed value
        """
        if efficacy.measured < MIN_SAMPLES:
            return ThresholdProposal(
                playbook_id=playbook_id,
                parameter="anomaly_score",
                current_value=current_threshold,
                proposed_value=current_threshold,
                direction=PROPOSE_HOLD,
                samples=efficacy.measured,
                evidence=f"insufficient samples (n={efficacy.measured}, need {MIN_SAMPLES})",
                confidence_lower=0.0,
            )

        lower_bound = efficacy.success_rate_lower

        # Playbook is ineffective — propose raising threshold
        if lower_bound < CONFIDENCE_TARGET:
            for grid_point in range(int(current_threshold) + GRID_STEP, HARD_MAX_THRESHOLD + 1, GRID_STEP):
                if grid_point <= HARD_MAX_THRESHOLD:
                    proposed = float(grid_point)
                    break
            else:
                proposed = float(HARD_MAX_THRESHOLD)

            return ThresholdProposal(
                playbook_id=playbook_id,
                parameter="anomaly_score",
                current_value=current_threshold,
                proposed_value=min(proposed, HARD_MAX_THRESHOLD),
                direction=PROPOSE_RAISE,
                samples=efficacy.measured,
                evidence=f"efficacy low ({lower_bound:.2%} lower bound < {CONFIDENCE_TARGET:.0%} target); {efficacy.ineffective} ineffective outcomes",
                confidence_lower=lower_bound,
            )

        # Shadow evaluation: propose lowering if safe
        if shadow_scores:
            for grid_point in range(int(current_threshold) - GRID_STEP, HARD_MIN_THRESHOLD - 1, -GRID_STEP):
                if grid_point >= HARD_MIN_THRESHOLD:
                    shadow_in_range = sum(1 for s in shadow_scores if grid_point <= s < current_threshold)
                    if shadow_in_range >= MIN_SAMPLES:
                        proposed = float(grid_point)
                        return ThresholdProposal(
                            playbook_id=playbook_id,
                            parameter="anomaly_score",
                            current_value=current_threshold,
                            proposed_value=proposed,
                            direction=PROPOSE_LOWER,
                            samples=shadow_in_range,
                            evidence=f"shadow evaluation: {shadow_in_range} scans in [{grid_point}, {current_threshold}) with efficacy >= {CONFIDENCE_TARGET:.0%}",
                            confidence_lower=lower_bound,
                        )

        return ThresholdProposal(
            playbook_id=playbook_id,
            parameter="anomaly_score",
            current_value=current_threshold,
            proposed_value=current_threshold,
            direction=PROPOSE_HOLD,
            samples=efficacy.measured,
            evidence=f"efficacy healthy ({lower_bound:.2%} lower bound >= {CONFIDENCE_TARGET:.0%} target); no shadow data available to lower",
            confidence_lower=lower_bound,
        )
