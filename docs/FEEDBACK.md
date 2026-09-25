# Phase 62: Feedback Learning Loop

## Scope

Wire human feedback into the alert pipeline for continuous learning. Record true/false positive verdicts and severity adjustments. Build per-alert-type feedback history to inform future confidence scoring (Phase 64). CLI interface for operators to submit feedback.

## What Phase 62 Deliberately Does NOT Do

- **Not automatic threshold tuning.** Feedback is recorded and queried; confidence thresholds (0.8 "high", etc) remain static constants. Phase 64 uses the feedback data but does not learn or adjust band boundaries.
- **Not compliance auditing.** Does not log who provided feedback, when, or from where. Feedback verdict (true/false positive) is recorded; reasoning is optional free text.
- **Not feedback validation.** Accepts any verdict string. No enforcement that feedback matches the alert's actual severity or outcome.
- **Not weighted feedback.** All feedback counts equally. No expert override, no feedback from human vs bot, no time decay.
- **Not schema versioning.** Feedback schema (alert_feedback table) is flat; future verdicts would require ALTER TABLE, not schema migration.

## Design

**FeedbackStore** — Query interface. Loads feedback from alert_feedback table. Calculates per-alert-type stats: true positives, false positives, unclear, average severity adjustment. Returns None if no feedback history.

**Feedback schema** — alert_feedback table (Phase 55): decision_id → verdict (true_positive, false_positive, unclear) + reason + severity_adjustment + feedback_by.

**CLI commands** — `secure feedback [alert_id] [verdict]` — Record verdict for a specific alert decision. Operator supplies decision_id from alert timeline, verdict from {true_positive, false_positive, unclear}.

**Feedback stats calculation** — Per alert_type (from alert_decisions.source_table): COUNT, tp/fp/unclear breakdown, AVG severity_adjustment. Used by Phase 64 confidence engine.

## Modules

- **secure/feedback/store.py** — FeedbackStore query interface, stats calculation (150 lines)
- **secure/feedback/schema.py** — alert_feedback table schema (35 lines)
- **secure/feedback/models.py** — AlertFeedback, FeedbackStats dataclasses (26 lines)
- **secure/cli/feedback.py** — CLI commands: `secure feedback` (125 lines)
- **tests/test_feedback_store.py** — 8 tests: store init, query, stats calc, empty/null cases

## Test Coverage

✅ Record feedback: INSERT into alert_feedback
✅ Query by feedback_id: exact row retrieval
✅ Get stats by alert_type: tp/fp/unclear breakdown, avg delta
✅ Cold start (no feedback): returns None
✅ Mixed verdicts: all three verdict types in same query
✅ Null handling: columns with no data (unclear, severity_adjustment)

## Known Gaps

1. **No mutation gate.** FeedbackStore.get_feedback_stats queries alert_feedback directly. A gate stubbing the query to return empty would verify Phase 64 surfaces PENDING when no feedback exists. Currently only tested via fixtures.

2. **Feedback verdict is unconstrained.** Any string accepted as verdict. Phase 64 expects {true_positive, false_positive, unclear} but does not validate. A typo (true_positive vs true_pos) silently breaks confidence calculation.

3. **Feedback severity_adjustment untested at scale.** Tests use single alerts. Real scenario: 100 anomaly_events with mixed adjustments (+1, -2, +3, null) → AVG calc includes nulls as 0. Behavior under sparse, skewed, or out-of-bounds adjustments not verified.

4. **No feedback retention or privacy policy.** Alert feedback linked to alert_decisions.id; if alert is deleted, orphaned feedback remains. No TTL, no purge, no GDPR-style deletion support.
