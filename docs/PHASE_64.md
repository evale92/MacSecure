# Phase 64: Automation Engine

## Scope

Confidence-based automation for security alerts. Analyze feedback history (true/false positives) to calculate per-alert-type confidence scores. High-confidence CRITICAL/HIGH severity alerts auto-approve for remediation; others remain PENDING for operator review.

## What Phase 64 Deliberately Does NOT Do

- **Not remediation execution.** Auto-approval routes to executor (Phase 2), but executor runs in SIMULATED mode only. No actual system changes without operator sign-off.
- **Not SIEM integration.** `secure/automation/` has zero SIEM references (see commit 5b71bca). Confidence engine and alert forwarding are independent phases. Phase 65 is not downstream.
- **Not threshold learning.** Confidence band thresholds (0.8 "high", etc) are constants, not trained or tuned per deployment.
- **Not operator override.** PENDING approvals cannot be auto-approved by confidence score alone. Operator decision is load-bearing.
- **Not schema additions.** Reuses existing alert_decisions, alert_feedback, automation_requests tables. No new tables.

## Design

**AutomationEngine** — Main coordinator. Loads feedback history, calculates per-alert-type confidence, applies risk policy (severity × confidence → approval/escalation).

**Confidence calculation** — True positive rate (tp / (tp + fp)), penalized by false positive ratio. Default fp_rate = 0.5 on cold start (no feedback) ensures fresh deployments auto-approve nothing.

```
no feedback  → fp_rate = 0.5  → fp_penalty = 0.25
best case:     CRITICAL 1.0 × 0.75 = 0.75  ← below 0.8 "high" band
```

A fresh install auto-approves zero alerts across all severity levels until an alert type accumulates real feedback history.

**AutomatedAlertDispatcher** — Routes alerts through confidence check, surfaces approval status (AUTO_APPROVED, PENDING, APPROVED, SUPPRESSED_EXPECTED).

**RiskLevel policy** — Maps (severity, confidence) → (risk_level, approval_required, rollback_allowed).

## Modules

- **secure/automation/engine.py** — AutomationEngine, confidence scoring (184 lines)
- **secure/automation/dispatcher.py** — AutomatedAlertDispatcher, approval routing (96 lines)
- **secure/remediation/executor.py** — ExecutionStatus.SIMULATED mode (supports Phase 64 "approve but don't execute")
- **tests/test_automation_engine.py** — 6 engine tests (confidence, policies, no-feedback cold start)
- **tests/test_automation_dispatcher.py** — 5 dispatcher tests (approval flow, escalation, suppressed alerts)

## Test Coverage

✅ Confidence calculation: high/low severity, high/low FP rate combinations
✅ Cold-start guard: new alert type with no feedback stays PENDING
✅ Approval routing: high confidence HIGH → AUTO_APPROVED, low confidence LOW → PENDING
✅ Operator override: PENDING stays PENDING even on high confidence if escalation_disable=false
✅ Suppressed alerts: bypass confidence check, approve directly
✅ Auto-escalation policy: CRITICAL + high confidence → low risk, CRITICAL + low confidence → high risk

## Known Gaps

1. **No mutation gate for feedback store.** AutomationEngine reads `alert_feedback` table directly. A gate that stubs the feedback store to empty (causing all confidence = 0.5) would verify the engine surfaces PENDING correctly. Currently only tested via fixtures.

2. **Severity weights and FP penalty are magic numbers.** The 0.5 default FP rate and 0.25 penalty scale are never explained or justified in code comments. A future maintainer changing 0.5 → 0.0 would unknowingly enable day-one auto-approval on CRITICAL alerts. (This is load-bearing: the 0.5 default is Phase 64's cold-start safety property.)

3. **Alert-type filtering untested against mixed types.** Tests feed one alert type per run (anomaly_events). Real scenarios: HIGH alerts on process_key type + LOW alerts on file_key type in same batch. Confidence calculation per type, but interaction edge cases (does one failing type block others?) not verified.

4. **AutomatedAlertDispatcher does not integrate with Phase 65.** SIEMForwarder is not called. An auto-approved alert can fail to reach an external SIEM without surfacing an error to the automation flow. Dispatcher → SIEM forwarding is Phase 65 work, not Phase 64. (This is the same boundary issue found during Phase 63 remediation — automation and SIEM are orthogonal.)
