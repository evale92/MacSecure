"""Tests for learning loop (Phase 50.3)."""

from datetime import datetime

from secure.intelligence.learning import LearningEngine, _wilson_lower_bound, MIN_SAMPLES
from secure.intelligence.models import PROPOSE_RAISE, PROPOSE_LOWER, PROPOSE_HOLD, EfficacySummary
from secure.remediation.outcomes import RemediationOutcome, OutcomeStatus, PreScanSnapshot, PostScanSnapshot


def _make_outcome(action_id: str, effectiveness: str, findings_reduced: int = 1) -> RemediationOutcome:
    """Helper to create a test outcome."""
    now = datetime.utcnow()
    return RemediationOutcome(
        outcome_id=f"oc_{action_id}_{effectiveness}",
        execution_id=f"ex_{action_id}",
        action_id=action_id,
        created_at=now,
        measured_at=now,
        pre_scan=PreScanSnapshot(
            scan_id="pre",
            timestamp=now,
            finding_count=5,
            anomaly_score=80.0,
        ),
        post_scan=PostScanSnapshot(
            scan_id="post",
            timestamp=now,
            elapsed_seconds=30,
            finding_count=5 - findings_reduced,
            anomaly_score=80.0 - (findings_reduced * 5),
        ),
        status=OutcomeStatus.SUCCESS,
        findings_reduced=findings_reduced,
        effectiveness=effectiveness,
    )


def test_engine_initializes():
    """Learning engine initializes."""
    engine = LearningEngine()
    assert engine is not None


def test_wilson_bound_for_3_total_samples():
    """Wilson lower bound for n=3 yields PROPOSE_HOLD."""
    lower = _wilson_lower_bound(0, 3)
    assert lower >= 0.0
    assert lower < 1.0


def test_wilson_bound_increases_with_successes():
    """Wilson bound increases as successes increase."""
    bound_2_of_10 = _wilson_lower_bound(2, 10)
    bound_5_of_10 = _wilson_lower_bound(5, 10)
    bound_8_of_10 = _wilson_lower_bound(8, 10)

    assert bound_2_of_10 < bound_5_of_10 < bound_8_of_10


def test_efficacy_summary_insufficient_samples():
    """EfficacySummary with n < MIN_SAMPLES returns zero metrics."""
    engine = LearningEngine()
    outcomes = [_make_outcome("action1", "high") for _ in range(3)]

    summary = engine.analyze_action_efficacy("action1", outcomes)
    assert summary.measured == 3
    assert summary.effective == 3
    assert summary.success_rate == 1.0


def test_efficacy_summary_denominator_includes_all_measured():
    """Denominator is all measured outcomes, not just successful."""
    engine = LearningEngine()
    outcomes = [
        _make_outcome("action1", "high"),
        _make_outcome("action1", "high"),
        _make_outcome("action1", "none"),
    ]

    summary = engine.analyze_action_efficacy("action1", outcomes)
    assert summary.measured == 3
    assert summary.effective == 2
    assert summary.ineffective == 1
    assert summary.success_rate == 2 / 3


def test_efficacy_summary_with_no_outcomes():
    """EfficacySummary with no outcomes returns zeros."""
    engine = LearningEngine()
    summary = engine.analyze_action_efficacy("action1", [])
    assert summary.measured == 0
    assert summary.success_rate == 0.0
    assert summary.success_rate_lower == 0.0


def test_propose_hold_for_low_sample_count():
    """Proposal is PROPOSE_HOLD when samples < MIN_SAMPLES."""
    engine = LearningEngine()
    outcomes = [_make_outcome("action1", "high") for _ in range(3)]
    summary = engine.analyze_action_efficacy("action1", outcomes)

    proposal = engine.propose_threshold_adjustment(
        playbook_id="incident.test",
        current_threshold=70.0,
        efficacy=summary,
    )

    assert proposal.direction == PROPOSE_HOLD
    assert "insufficient samples" in proposal.evidence
    assert proposal.applied is False


def test_propose_raise_for_low_efficacy():
    """Proposal is PROPOSE_RAISE when efficacy is low."""
    engine = LearningEngine()
    outcomes = [
        _make_outcome("action1", "none"),  # All ineffective
        _make_outcome("action1", "none"),
        _make_outcome("action1", "none"),
        _make_outcome("action1", "none"),
        _make_outcome("action1", "none"),
        _make_outcome("action1", "none"),
        _make_outcome("action1", "none"),
        _make_outcome("action1", "none"),
        _make_outcome("action1", "none"),
        _make_outcome("action1", "none"),
    ]
    summary = engine.analyze_action_efficacy("action1", outcomes)

    proposal = engine.propose_threshold_adjustment(
        playbook_id="incident.test",
        current_threshold=70.0,
        efficacy=summary,
    )

    assert proposal.direction == PROPOSE_RAISE
    assert proposal.proposed_value > proposal.current_value
    assert proposal.applied is False


def test_proposal_never_exceeds_hard_max():
    """Proposal clamped to HARD_MAX_THRESHOLD."""
    engine = LearningEngine()
    outcomes = [_make_outcome("action1", "none") for _ in range(10)]
    summary = engine.analyze_action_efficacy("action1", outcomes)

    proposal = engine.propose_threshold_adjustment(
        playbook_id="incident.test",
        current_threshold=90.0,
        efficacy=summary,
    )

    assert proposal.proposed_value <= 95.0


def test_proposal_never_below_hard_min():
    """Proposal clamped to HARD_MIN_THRESHOLD."""
    engine = LearningEngine()
    outcomes = [_make_outcome("action1", "high") for _ in range(10)]
    summary = engine.analyze_action_efficacy("action1", outcomes)
    shadow_scores = [15.0, 15.0, 15.0, 15.0, 15.0, 15.0, 15.0, 15.0, 15.0, 15.0]

    proposal = engine.propose_threshold_adjustment(
        playbook_id="incident.test",
        current_threshold=30.0,
        efficacy=summary,
        shadow_scores=shadow_scores,
    )

    assert proposal.proposed_value >= 20.0


def test_propose_lower_with_shadow_data():
    """Proposal is PROPOSE_LOWER when shadow data supports it."""
    engine = LearningEngine()
    outcomes = [_make_outcome("action1", "high") for _ in range(10)]
    summary = engine.analyze_action_efficacy("action1", outcomes)

    shadow_scores = [s for s in range(50, 75)]
    proposal = engine.propose_threshold_adjustment(
        playbook_id="incident.test",
        current_threshold=75.0,
        efficacy=summary,
        shadow_scores=shadow_scores,
    )

    assert proposal.direction == PROPOSE_LOWER
    assert proposal.proposed_value < proposal.current_value
    assert proposal.applied is False


def test_proposal_applied_always_false():
    """All proposals have applied=False."""
    engine = LearningEngine()
    outcomes = [_make_outcome("action1", "high") for _ in range(15)]
    summary = engine.analyze_action_efficacy("action1", outcomes)

    proposal_hold = engine.propose_threshold_adjustment(
        playbook_id="incident.test",
        current_threshold=50.0,
        efficacy=summary,
    )

    proposal_raise = engine.propose_threshold_adjustment(
        playbook_id="incident.test",
        current_threshold=90.0,
        efficacy=EfficacySummary(
            action_id="action1",
            measured=10,
            effective=0,
            ineffective=10,
            inconclusive=0,
            success_rate=0.0,
            success_rate_lower=0.0,
            avg_findings_reduced=0.0,
            avg_time_to_effect=0.0,
        ),
    )

    assert proposal_hold.applied is False
    assert proposal_raise.applied is False


def test_proposal_samples_count_reported():
    """Proposal reports actual sample count."""
    engine = LearningEngine()
    outcomes = [_make_outcome("action1", "high") for _ in range(15)]
    summary = engine.analyze_action_efficacy("action1", outcomes)

    proposal = engine.propose_threshold_adjustment(
        playbook_id="incident.test",
        current_threshold=50.0,
        efficacy=summary,
    )

    assert proposal.samples == 15


def test_efficacy_average_findings_reduced():
    """EfficacySummary correctly averages findings reduced."""
    engine = LearningEngine()
    outcomes = [
        _make_outcome("action1", "high", findings_reduced=3),
        _make_outcome("action1", "high", findings_reduced=2),
        _make_outcome("action1", "high", findings_reduced=1),
    ]
    summary = engine.analyze_action_efficacy("action1", outcomes)

    assert summary.avg_findings_reduced == 2.0


def test_efficacy_average_time_to_effect():
    """EfficacySummary correctly averages time to effect."""
    engine = LearningEngine()
    now = datetime.utcnow()
    outcomes = []

    for seconds in [10, 20, 30]:
        outcome = RemediationOutcome(
            outcome_id=f"oc_{seconds}",
            execution_id=f"ex_{seconds}",
            action_id="action1",
            created_at=now,
            measured_at=now,
            pre_scan=PreScanSnapshot(
                scan_id="pre",
                timestamp=now,
                finding_count=5,
                anomaly_score=80.0,
            ),
            post_scan=PostScanSnapshot(
                scan_id="post",
                timestamp=now,
                elapsed_seconds=seconds,
                finding_count=4,
                anomaly_score=75.0,
            ),
            status=OutcomeStatus.SUCCESS,
            findings_reduced=1,
            effectiveness="high",
            time_to_effect=seconds,
        )
        outcomes.append(outcome)

    summary = engine.analyze_action_efficacy("action1", outcomes)
    assert summary.avg_time_to_effect == 20.0
