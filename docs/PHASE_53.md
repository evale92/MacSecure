# Phase 53: Detection Intelligence — Alerting Layer

**Status:** ✅ COMPLETE  
**Completion Date:** 2026-09-23  
**LOC:** 1120  
**Tests:** 61 (all passing)  
**Commits:** 2 (`60db61e`, `4cee6f0`)

---

## Overview

Phase 53 implements the alerting layer for the Secure system. It provides **pure decision functions** that evaluate whether alerts should be suppressed (expected changes), escalated (contextual risk), or reported (anomalous).

**Key principle:** Alerts are made by pure functions of findings + frozen context. No I/O. No state mutations. No upward imports.

---

## Design Principles

### 1. Pure Functions Only

All decision logic is computed from inputs with no side effects:

```python
def classify(
    event_severity: str,
    entity_type: str,
    entity_path: Optional[str],
    event_timestamp: datetime,
    context: AlertContext,
) -> SuppressionVerdict:
    """Pure function — no I/O, no imports from peer layers."""
```

**Benefit:** Decisions are testable, deterministic, and independent of system state.

### 2. Frozen Dataclass Context

All context passed downward uses immutable frozen dataclasses:

```python
@dataclass(frozen=True)
class AlertContext:
    device: Optional[DeviceContext] = None
    response: Optional[ResponseContext] = None
    learning: Optional[LearningContext] = None
    expected_changes: tuple = ()
```

**Benefit:** Prevents accidental mutations. Signals immutability to caller.

### 3. Layering: compose.py is the Boundary

All imports from peer layers (remediation, multi_device, intelligence) happen in ONE file:

```python
# secure/alerting/compose.py
def compose() -> AlertContext:
    device = compose_device_context()      # Phase 49
    response = compose_response_context()  # Phase 48/51
    learning = compose_learning_context()  # Phase 50
    expected_changes = compose_expected_changes()
    return AlertContext(device, response, learning, expected_changes)
```

**Benefit:** Decision functions stay pure and testable. Peer-layer changes isolated to one file.

### 4. Suppression ≠ Escalation

Suppression (expected changes) and escalation (context risk) are independent:

```python
# Suppress first
suppression = classify_suppression(...)
if suppression.category == "SUPPRESSED_EXPECTED":
    # Don't escalate suppressed events
    return AlertDecision(..., verdict="SUPPRESSED_EXPECTED", ...)

# Escalate if not suppressed
final_severity, escalation_reasons = weigh(base_severity, context)
```

**Benefit:** Clean separation of concerns. Can tune each independently.

---

## Core Modules

### 1. context.py — Frozen Dataclasses

**Five frozen dataclasses for safe context passing:**

**AlertContext** — Main orchestration container
- Holds all context needed by decision functions
- Safe defaults: device/response/learning can be None
- expected_changes is always a tuple (may be empty)

```python
@dataclass(frozen=True)
class AlertContext:
    device: Optional[DeviceContext] = None
    response: Optional[ResponseContext] = None
    learning: Optional[LearningContext] = None
    expected_changes: tuple = ()
    
    @classmethod
    def empty(cls) -> AlertContext:
        """Return safe default when sources unavailable."""
        return cls(
            device=None,
            response=None,
            learning=LearningContext(),  # Always valid
            expected_changes=(),
        )
```

**DeviceContext** — Device state from Phase 49
- device_id: str — unique identifier
- role: str — PRIMARY|SECONDARY|SHARED|ADMIN (escalation factor)
- health: str — healthy|degraded|stale (annotation only)
- sync_state: str — synced|out-of-sync
- peer_device_count: int — how many peers have same finding (escalation factor)

**ResponseContext** — Remediation state from Phase 48/51
- max_risk_level: str — LOW|MEDIUM|HIGH (escalation factor)
- playbook_id: Optional[str] — which playbook is running
- playbook_severity: Optional[str] — critical|high|medium|low (escalation factor)

**LearningContext** — Threshold tuning from Phase 50
- threshold_overrides: Mapping[str, float] — from learning loop to baseline/scoring.py
- fp_rate_by_feature: Mapping[str, float] — false positive rates
- sample_counts: Mapping[str, int] — sample sizes for confidence

**ExpectedChange** — Suppression window definition
- kind: str — os_update|app_install|user_declared
- started_at: datetime — window start
- ends_at: datetime — window end
- entity_types: FrozenSet[str] — what entities this suppresses (e.g., "process_key")
- path_prefixes: tuple — which paths apply (e.g., "/Library/Updates")
- source: str — provenance for audit trail (e.g., "system:software_update")

### 2. suppression.py — Pure classify()

**Suppression Rules:**

**Rule 1:** CRITICAL events are never suppressed (design decision for safety)
```python
if event_severity == "CRITICAL":
    return SuppressionVerdict(category="ACTIVE", reason="...")
```

**Rule 2:** Matching requires entity-type + path-prefix + timestamp window
```python
for change in context.expected_changes:
    # Check timestamp window
    if not (change.started_at <= event_timestamp <= change.ends_at):
        continue
    
    # Check entity type
    if entity_type not in change.entity_types:
        continue
    
    # Check path prefix (or no-path-specified = match any path)
    if change.path_prefixes and entity_path:
        if not any(entity_path.startswith(p) for p in change.path_prefixes):
            continue
    
    # Match! Apply Rule 3...
```

**Rule 3:** Suppression level depends on severity
```python
if event_severity in ("HIGH", "MEDIUM"):
    # Cap only — downgrade one tier, never full suppression
    return SuppressionVerdict(category="DOWNGRADED_EXPECTED", ...)
else:
    # LOW / INFORMATIONAL — full suppression allowed
    return SuppressionVerdict(category="SUPPRESSED_EXPECTED", ...)
```

**Returns:** SuppressionVerdict with:
- category: ACTIVE|SUPPRESSED_EXPECTED|DOWNGRADED_EXPECTED
- matching_expected_change: Optional[ExpectedChange] (audit trail)
- reason: str (human-readable explanation)

**Tests:**
- Rule 1: CRITICAL never suppressed ✅
- Rule 2: Entity type matching ✅
- Rule 2: Path prefix matching ✅
- Rule 2: Timestamp window check ✅
- Rule 3: HIGH/MEDIUM capped ✅
- Rule 3: LOW/INFO suppressed ✅
- Edge case: No expected changes ✅
- Edge case: Matching change recorded ✅

### 3. escalation.py — Pure weigh()

**Escalation Signals (each +1 step):**

1. **device.role == ADMIN** → +1 (blast radius, can affect entire system)
2. **device.role == SHARED** → +1 (multi-user exposure)
3. **peer_device_count >= 2** → +1 (supply-chain indicator, same finding across devices)
4. **response.max_risk_level == HIGH** → +1 (matching HIGH-risk remediation exists)
5. **playbook_severity == critical** → +1 (Phase 51 judgment)

**NOT escalation (annotation only):**
- device.health == degraded|stale (reduced visibility ≠ reduced severity)

**Tier Ladder (Ordinal):**
```
INFORMATIONAL (0) < LOW (1) < MEDIUM (2) < HIGH (3) < CRITICAL (4)
```

**Step Clamping:** ±2 tiers maximum (enforced on step count)
```python
original_steps = steps  # Could be 0 to +5
steps = max(-2, min(2, steps))  # Clamp to ±2

# Then apply
final_idx = max(0, min(4, base_idx + steps))  # Also clamp to tier bounds
```

**Example:**
- LOW (1) + 4 signals = +4 steps, clamped to +2 = HIGH (3)
- MEDIUM (2) + 5 signals = +5 steps, clamped to +2 = HIGH (3)
- INFORMATIONAL (0) + 2 signals = +2 steps = MEDIUM (2)

**Returns:** (final_severity, list of reason strings)

**Tests:**
- ADMIN role escalates ✅
- SHARED role escalates ✅
- Peer device count escalates ✅
- HIGH-risk remediation escalates ✅
- Critical playbook escalates ✅
- Multiple signals stack correctly ✅
- Step clamping enforced ✅
- Final tier clamped to bounds ✅
- Device health annotated not escalated ✅
- Unknown base severity passthrough ✅
- CRITICAL cannot escalate further ✅
- Escalation clamped at tier bounds ✅
- No escalation without signals ✅

### 4. decide.py — Pure Orchestration

**Workflow:**

1. **Apply Suppression** — classify_suppression()
   - Returns SuppressionVerdict (category + reason)

2. **If Suppressed, Skip Escalation**
   - SUPPRESSED_EXPECTED events don't get escalated
   - Escalation is marked "skipped" in reasoning

3. **If Not Suppressed, Apply Escalation**
   - weigh() computes final severity
   - Records escalation reasons

4. **Build Reasoning Record**
   - Combines suppression + escalation reasons
   - Creates audit trail for decision

**Returns:** AlertDecision with:
- source_table: str (anomaly_events|correlation_alerts|...)
- source_id: int (row id in that table)
- base_severity: str (input)
- verdict: str (ACTIVE|SUPPRESSED_EXPECTED|DOWNGRADED_EXPECTED)
- final_severity: str (output)
- reasoning: List[str] (component reasons)

**Tests:**
- Suppressed events not escalated ✅
- Downgraded events still escalated ✅
- Active events escalated ✅
- Reasoning includes both components ✅
- Source info captured ✅
- CRITICAL never downgraded ✅
- Complete workflow with all signals ✅
- Edge case: No context ✅

### 5. compose.py — Single Impure Boundary

**Assembles AlertContext from Phase 48-51 sources:**

```python
def compose(use_defaults: bool = True) -> AlertContext:
    device = compose_device_context()        # Phase 49
    response = compose_response_context()    # Phase 48/51
    learning = compose_learning_context()    # Phase 50
    expected_changes = compose_expected_changes()
    
    return AlertContext(
        device=device,
        response=response,
        learning=learning,
        expected_changes=expected_changes,
    )
```

**Each compose_* function:**
- Wrapped in try/except
- Returns None (or empty) if source unavailable
- Preserves safe defaults

**Tests:**
- Returns AlertContext ✅
- Safe defaults when sources unavailable ✅
- Device context optional ✅
- Response context optional ✅
- Learning context always valid ✅
- Expected changes tuple ✅
- Deterministic across calls ✅
- All fields populated ✅

### 6. store.py — Persistence Layer

**AlertDecisionStore class:**

Methods:
- `store_decision(decision: AlertDecision, stored_at: datetime) -> int` — returns row id
- `get_recent_decisions(limit: int = 100) -> List[AlertDecision]` — fetch recent
- `get_decision_by_source(source_table: str, source_id: int) -> Optional[AlertDecision]` — lookup by source
- `count_by_verdict() -> dict` — counts by verdict category

**Tests:**
- Initialization ✅
- Accept optional connection ✅
- Store decision returns id ✅
- Get recent returns list ✅
- Respect limit ✅
- Count by verdict ✅
- Get by source not found ✅
- Empty table handling ✅
- Long reasoning list ✅
- Default limit sensible ✅

### 7. CLI Commands (alerts_decisions.py)

**AlertDecisionsCLI class with methods:**

- `cmd_recent(limit: int = 20)` — print recent decisions
- `get_recent(limit: int = 20) -> dict` — JSON output
- `cmd_counts()` — print verdict counts
- `get_counts() -> dict` — JSON output
- `cmd_detail(source_table, source_id)` — print one decision details
- `get_detail(source_table, source_id) -> dict` — JSON output
- `cmd_stats(days: int = 7)` — print statistics
- `get_stats(days: int = 7) -> dict` — JSON output

**Integration:**
- Add to argparse in `secure/cli/__init__.py`
- Subcommand: `secure alert-decisions recent|counts|detail|stats`
- Support `--json` flag for all reads

### 8. Explainer (alert_decision_explainer.py)

**AlertDecisionExplainer class with methods:**

- `explain_verdict(decision) -> str` — why suppressed/escalated/active
- `explain_suppression(decision) -> str` — which rule matched
- `explain_escalation(decision) -> str` — which signals fired
- `format_decision(decision, detailed=False) -> str` — full human-readable output
- `to_dict(decision) -> dict` — structured for JSON/API

**Usage:**
```python
decision = decide_alert(...)
print(AlertDecisionExplainer.format_decision(decision, detailed=True))
```

---

## Integration Points

### With Phase 48 (Remediation)

**Where:** compose.py → compose_response_context()

**Reads:**
- RemediationExecutor.list_executions() — get pending actions
- Action.risk_level — for max_risk_level
- Playbook.severity — for playbook_severity

**Effect:** High-risk remediations escalate related alerts

### With Phase 49 (Multi-Device)

**Where:** compose.py → compose_device_context()

**Reads:**
- device_registry.get_device_info() — device role, health, sync state
- cross_device.py — peer_device_count (how many devices have same finding)

**Effect:** Device role and supply-chain indicators escalate alerts

### With Phase 50 (Threat Intelligence)

**Where:** compose.py → compose_learning_context()

**Reads:**
- learning.get_threshold_proposals() — adjustments from learning loop

**Effect:** Threshold overrides tuned by Phase 50 learning

### With Phase 51 (Playbooks)

**Where:** compose.py → compose_response_context()

**Reads:**
- playbook.severity (critical|high|medium|low)

**Effect:** Critical playbooks escalate related alerts

### With Phase 52 (GUI & CLI)

**Where:** CLI in alerts_decisions.py, GUI displays decisions

**Provides:**
- Alert decision history and statistics
- Reasoning for each decision (audit trail)
- Integration with GUI panel (future work)

---

## Future Work

### Phase 54: Integration with Detection Pipeline

**Goal:** Wire alerting layer into baseline anomaly detection

**What to build:**
1. Feed baseline/scoring outputs to decide_alert()
2. Integrate Phase 49 correlation with alert decisions
3. Create end-to-end: baseline → anomaly → alert decision

### Phase 55: User Feedback Loop

**Goal:** Close the learning loop on alert quality

**What to build:**
1. Store user feedback (true/false positive) with alert decisions
2. Feed back to Phase 50 learning loop
3. Adjust suppression rules based on false positives
4. Adjust escalation weights based on incident severity

### Phase 56: Dashboard & Reporting

**Goal:** Visualize alert decisions and outcomes

**What to build:**
1. GUI panel showing alert decisions
2. Timeline view: findings → correlations → alerts → remediations
3. Export alert decision logs for compliance

---

## Testing Strategy

**Unit tests by module (61 total):**

| Module | Tests | Approach |
|--------|-------|----------|
| suppression | 8 | Rule-based: test each rule + edge cases |
| escalation | 13 | Signal-based: each signal, combinations, clamping |
| decide | 8 | Workflow-based: each path through orchestration |
| compose | 13 | Assembly-based: context composition with safe defaults |
| storage | 10 | Persistence: CRUD operations, structure |
| layering | 9 | Architecture: import constraints, pure functions |

**Run tests:**
```bash
python3 -m pytest tests/test_alerting_*.py -v
```

**All tests must pass before any commit.**

---

## Code Quality Checklist

- ✅ No imports from remediation/multi_device/intelligence (except in compose.py)
- ✅ All decision functions are pure (no I/O, no state)
- ✅ All context is frozen dataclass (immutable)
- ✅ Audit trail preserved (reasoning logged with decision)
- ✅ Type hints on all public APIs
- ✅ Comments only for non-obvious WHY (not WHAT)
- ✅ No external dependencies (stdlib only)
- ✅ All tests pass (61/61)

---

## Known Limitations

1. **Storage not connected to detection pipeline yet** (Phase 54 work)
   - store.py has stub implementations
   - Awaits database schema in Phase 54

2. **compose.py has TODOs**
   - Device peer_device_count currently returns 0
   - Expected changes from user declarations not yet wired

3. **Threshold overrides not yet tuned**
   - Phase 50 learning loop exists but thresholds not updated
   - Phase 54 will integrate feedback loop

---

## References

- **ARCHITECTURE_RULES.md** — Layering constraints
- **SECURITY_INVARIANTS.md** — Audit trail requirements
- **docs/PHASE_48.md** — Remediation layer
- **docs/PHASE_49.md** — Multi-device layer
- **HANDOFF.md** — Project state and session summary

---

**Phase 53 is complete and ready for Phase 54 integration work.**
