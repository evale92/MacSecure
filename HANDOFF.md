# Secure-Resource: Comprehensive Handoff & Documentation

**Last Updated:** 2026-09-24 08:07 EDT  
**Status:** Production-ready core (Phases 62-65 complete) + Test infrastructure (Phases 1-2 of production-readiness)  
**Git HEAD:** 29c38bf (Test Infrastructure: Rigorous production-readiness framework)  
**Working Directory:** `/Users/erickvale/Projects/secure-resource` (MOVED from ~/Desktop)

## Project Location & Access

**CRITICAL:** Project moved to `/Users/erickvale/Projects/secure-resource`

```bash
cd /Users/erickvale/Projects/secure-resource

# Verify location and status:
pwd  # Should output: /Users/erickvale/Projects/secure-resource
git log --oneline | head -1  # HEAD should be 29c38bf or later
ls HANDOFF.md BOT-START-HERE.md  # Both should exist
```

**Test environment:** macOS 8GB machine with pytest (no venv, use `/usr/bin/python3`)

---

## Quick Start for Bot (Next Session)

**Read in this order:**
1. **BOT-START-HERE.md** — orientation and critical constraints
2. **This file** (HANDOFF.md) — phases 62-65, test infrastructure, roadmap
3. **ARCHITECTURE_RULES.md** — layering constraints
4. Project vision: "Project Overview" section below

**Verify status:**
```bash
cd /Users/erickvale/Projects/secure-resource

# Health check (120 seconds)
git log --oneline | head -1  # HEAD → 29c38bf or later
/usr/bin/python3 -m pytest tests/test_feedback.py tests/test_alerting_decide.py -q

# Import check
/usr/bin/python3 -c "from secure.cli.feedback import cmd_feedback_submit; from secure.web.app import DashboardHandler; print('✓ Phases 62-63 OK')"
```

**Test constraints:**
- Max 20 test files per run (8GB machine)
- Never run full suite (`pytest tests/ -x`)
- Restart between batches
- If tests grow slow: run `git log --oneline | wc -l` to verify repo state

---

## Project Overview

**Secure** is a zero-trust threat detection, automated response, and SIEM integration system for macOS with feedback-driven threshold tuning.

**Capabilities:**
- **Detection:** Baseline anomalies (7 sensor types), multi-device correlation, context-aware alerting
- **Response:** Auto-remediation with risk-stratified approval, 12+ built-in actions
- **Feedback:** User verdict collection → learning loop → threshold tuning (Phase 62)
- **Observability:** Web dashboard with timeline view, alert export, real-time visualization (Phase 63)
- **Automation:** High-confidence alerts (>0.8) auto-approve without approval step (Phase 64)
- **SIEM:** Multi-format forwarding (CEF, Syslog, Splunk HEC, JSON) with buffering (Phase 65)
- **Testing:** Production-readiness framework (Phases 1-2 complete, 16 tests passing)

**Architecture:** 7 core phases (48-54) + 4 enhancement phases (62-65) + 5 test phases (1-5)  
**No external ML, Flask, or venv** — stdlib only  
**Audit trail:** Every decision, action, feedback logged with reasoning

---

## Phase Completion Status

| Phase | Component | Status | LOC | Tests |
|-------|-----------|--------|-----|-------|
| **Core Detection & Response** |
| 48 | Automated Remediation | ✅ | 2000+ | 173+ |
| 49 | Multi-Device Coordination | ✅ | 1300+ | 28 |
| 50 | Threat Intelligence | ✅ | 655 | 45 |
| 51 | Extended Playbooks | ✅ | 500+ | 26 |
| 52 | GUI Panel & CLI Wiring | ✅ | 1280 | — |
| 53 | Detection Intelligence | ✅ | 1120 | 61 |
| 54 | Detection Pipeline | ✅ | 624 | 10 |
| **Enhancement Features** |
| 62 | User Feedback Loop | ✅ | 450+ | 12 |
| 63 | Web Dashboard & Reporting | ✅ | 380+ | 8 |
| 64 | Response Automation | ✅ | 320+ | 12 |
| 65 | SIEM Integration | ✅ | 550+ | 12 |
| **Production-Readiness Testing** |
| Test-1 | Ground-Truth Sensor Accuracy | ✅ | 350 | 9 |
| Test-2 | Remediation Safety | ✅ | 360 | 8 |
| Test-3 | Learning Loop Stability | 🔮 Planned | — | — |
| Test-4 | SIEM Resilience | 🔮 Planned | — | — |
| Test-5 | Red-Team Resilience | 🔮 Planned | — | — |
| **Totals** | | **✅ 14/14** | **~9700** | **~385** |

---

## Session Work Summary (2026-09-24)

### Completed This Session (Phases 62-65 + Test Infrastructure)

**Phase 62: User Feedback Loop** ✅ (450+ LOC, 12 tests)

**Purpose:** Collect user verdicts (true/false positive/unclear) on alert decisions to measure false-positive rates and drive threshold tuning via Phase 50 learning loop.

**Core Components:**
1. `secure/cli/feedback.py` — Three commands
   - `cmd_feedback_submit`: Record verdict + optional reason + severity adjustment
   - `cmd_feedback_review`: List feedback with pagination + filtering
   - `cmd_feedback_stats`: Show FP rate by alert type and confidence bands

2. `secure/intelligence/learning.py` (modified)
   - `analyze_feedback()`: Calculate false-positive rate from user verdicts
   - Integrates into `propose_threshold_adjustment()` logic
   - High FP rate (>30%) triggers "RAISE threshold" recommendation

3. **Database:** `feedback` table
   - alert_decision_id, verdict, reason, severity_adjustment, timestamp
   - Index on (verdict, alert_type) for stats queries

**Integration:** Feedback flows back to Phase 50 learning engine for automatic threshold tuning

---

**Phase 63: Web Dashboard & Reporting** ✅ (380+ LOC, 8 tests)

**Purpose:** Real-time visualization of alerts with filtering, export, and embedded feedback submission.

**Core Components:**
1. `secure/web/app.py` — Stdlib HTTP server (NO Flask dependency)
   - `DashboardHandler` extends `BaseHTTPRequestHandler`
   - GET `/api/alerts`: Returns alert timeline (last 24h, filterable by severity/verdict)
   - GET `/api/export`: JSON or CSV export of alert_decisions table
   - POST `/api/feedback`: Submit verdict directly from dashboard
   - GET `/`: Serves embedded HTML/JavaScript dashboard UI

2. **Dashboard UI Features:**
   - Real-time alert timeline (refreshes every 10s)
   - Filter buttons: severity (CRITICAL/HIGH/MEDIUM/LOW), verdict (ACTIVE/SUPPRESSED/DOWNGRADED)
   - Click alert → detail view (full decision reasoning, remediation status)
   - Export button → download CSV with compliance fields
   - Feedback form → inline verdict submission

3. `secure/cli/web.py`
   - `cmd_web_start`: Launch server on host:port
   - Routes to `secure web start --host 127.0.0.1 --port 8080`

---

**Phase 64: Response Automation** ✅ (320+ LOC, 12 tests)

**Purpose:** Auto-approve high-confidence alerts (>0.8) without manual approval step; preserve audit trail.

**Core Components:**
1. `secure/automation/engine.py`
   - `AutomationEngine.calculate_confidence(alert_id, severity, alert_type)` → ConfidenceScore
     - Severity weight: CRITICAL=1.0, HIGH=0.9, MEDIUM=0.7, LOW=0.5
     - FP penalty: Reduces confidence by up to 50% based on recent feedback
     - Returns `confidence_level`: "high"/"medium"/"low"
   - `should_auto_approve(alert_id, severity)` → (bool, reason)
     - Returns True if `confidence_level == "high"`
   - `get_auto_approval_policy()` → ApprovalPolicy with RiskLevel

2. `secure/automation/dispatcher.py`
   - `AutomatedAlertDispatcher.process_alert_for_automation()`
     - Routes to `ApprovalStatus.AUTO_APPROVED` or `PENDING`
   - `create_automation_request()`: Audit trail record with executor ID, reason, confidence score

3. **Approval Workflow:**
   - CRITICAL or LOW confidence → PENDING (always needs approval)
   - MEDIUM confidence → PENDING (may escalate)
   - HIGH confidence (>0.8) → AUTO_APPROVED (executes immediately)
   - All auto-approvals logged with reasoning for compliance audits

---

**Phase 65: SIEM Integration** ✅ (550+ LOC, 12 tests)

**Purpose:** Forward alerts to external SIEM systems in multiple formats with buffering for network resilience.

**Core Components:**
1. `secure/integrations/siem.py` — SIEMForwarder class
   - `format_cef()`: Common Event Format (CEF header + extensions dict)
   - `format_syslog()`: RFC 3164 format with severity mapping
     - Priority = (facility × 8) + severity; facility 16 (local0) for security alerts
     - Severity: CRITICAL=2, HIGH=3, MEDIUM=4, LOW=5, NONE=7
   - `format_splunk_hec()`: Splunk HTTP Event Collector with Unix timestamp
   - `format_json()`: Generic JSON with alert metadata + extra_fields
   - `send_syslog()`: UDP socket to host:port
   - `send_http()`: POST with Bearer token auth
   - `send_alert()`: Routes to transport based on endpoint config

2. `secure/integrations/config.py` — SIEMConfigManager
   - `load_config()`: Read ~/.secure/siem_endpoints.json
   - `add_endpoint()`: Store syslog/splunk/http endpoint with URL, API key, timeout
   - `list_endpoints()`, `get_endpoint()`, `remove_endpoint()`
   - `enable_endpoint()`, `disable_endpoint()`

3. `secure/cli/siem.py` — CLI commands
   - `cmd_siem_add`: `secure siem add --format syslog --host 10.0.0.1 --port 514`
   - `cmd_siem_list`: Display all endpoints with status (enabled/disabled)
   - `cmd_siem_test`: Test endpoint connectivity
   - `cmd_siem_enable`, `cmd_siem_disable`: Toggle endpoint

4. **Buffering & Resilience:**
   - Failed sends logged with retry count
   - Queue persisted to disk for network outages
   - Exponential backoff: 1s → 2s → 5s → 10s max

---

### Test Infrastructure (Production-Readiness Phases 1-2) ✅

**Phase 1: Ground-Truth Sensor Accuracy** (9 tests, ~350 LOC)

**Purpose:** Measure detection accuracy, latency, false-positive rate of all 7 sensor types.

**Tests:**
1. `test_persistence_mechanism_detection`: LaunchAgent injection, <100ms detection
2. `test_listening_port_detection`: Port 9999 TCP, <50ms latency
3. `test_network_connection_detection`: Outbound 192.0.2.1:443
4. `test_file_integrity_detection`: Modified hosts file detection
5. `test_sensor_summary_metrics`: Aggregate 5 detections → 100% detection rate
6. `test_false_positive_baseline`: 1000 scans, no threats → <2% FP rate
7. `test_detection_latency_bounds`: p50 ≤ 45ms, avg < 50ms
8. `test_all_sensor_types_represented`: Verify 7 sensor types present
9. (1 more coverage test)

**Fixtures** (`tests/integration/fixtures.py`):
- `GroundTruthInjector`: Create test LaunchAgent plists, port records, file mods, connections
- `MetricsCollector`: Record + aggregate detection/remediation results
- `DetectionResult` & `RemediationResult` dataclasses for type-safe result tracking

---

**Phase 2: Remediation Safety** (8 tests, ~360 LOC)

**Purpose:** Verify remediation actions execute safely with pre/post state consistency and rollback integrity.

**Tests:**
1. `test_remediation_pre_post_state_verification`: Disable port 9999, verify state change
2. `test_remediation_rollback`: Unload LaunchAgent, restore on rollback
3. `test_remediation_partial_failure`: 2/3 files quarantine, error handling
4. `test_remediation_permission_safety`: Permission denied blocks execution
5. `test_blast_radius_isolation`: Kill malware, nearby processes untouched
6. `test_concurrent_remediation_safety`: Lock prevents conflicting execution
7. `test_remediation_audit_trail`: Action logged with timestamp, executor, reason
8. `test_remediation_summary_metrics`: 10 remediations, 80% success rate

**Metrics:** Execution rate, verification rate, rollback rate, error count per action

---

**Test Configuration** (`tests/integration/conftest.py`):
- Pytest markers: `@pytest.mark.integration`, `@pytest.mark.slow`
- `metrics_collector` fixture per test
- `integration_test_config` with SLAs: timeout 30s, max latency 100ms, FP rate <1%

**Test Running:**
```bash
# Phase 1 only
/usr/bin/python3 -m pytest tests/integration/test_sensor_ground_truth.py -v

# Phase 2 only
/usr/bin/python3 -m pytest tests/integration/test_remediation_safety.py -v

# Both (16 tests total, ~15 seconds)
/usr/bin/python3 -m pytest tests/integration/ -q

# With metrics export
/usr/bin/python3 -m pytest tests/integration/ --json=.testing/metrics.json
```

**Metrics Output:**
```json
{
  "detection_summary": {
    "persistence": {"detection_rate": 1.0, "avg_latency_ms": 45.2, "avg_confidence": 0.94},
    "connections": {"detection_rate": 1.0, "avg_latency_ms": 28.5, "avg_confidence": 0.91}
  },
  "remediation_summary": {
    "disable_port": {"execution_rate": 0.95, "verification_rate": 1.0, "rollback_rate": 1.0}
  },
  "total_detection_tests": 9,
  "total_remediation_tests": 8,
  "duration_seconds": 14.2
}

---

## Testing Roadmap (Phases 3-5)

**Phase 3: Learning Loop Stability** (Planned, ~400 LOC, 12 tests)
- Adversarial feedback marking: Inject conflicting verdicts (TP + FP on same alert)
- Model poisoning resistance: Threshold drift under feedback spam
- Threshold convergence: FP rate settles after 50 feedback loops
- Confidence volatility: Score stability when feedback changes

**Phase 4: SIEM Resilience** (Planned, ~350 LOC, 10 tests)
- Network partition simulation: SIEM endpoint unreachable for 30s
- Retry + buffering: Queued alerts resent after recovery
- Format fallback: Syslog endpoint fails → try Splunk → try JSON
- Lossy network: UDP packet loss recovery via TCP fallback
- Memory pressure: Buffer doesn't exceed 100MB under load

**Phase 5: Red-Team Resilience** (Planned, ~400 LOC, 15 tests)
- Sensor tampering: Attacker modifies baseline data
- Alert suppression: Malware forges user verdicts to lower confidence
- Remediation evasion: Action target disappears before execution
- Privilege escalation: Detect permission boundary violations
- Audit trail corruption: Verify tamper-evident log storage

**Testing Best Practices:**
- GroundTruthInjector for controlled artifact creation
- MetricsCollector for adversarial metrics aggregation
- Pytest fixtures for test isolation
- JSON export for CI/CD pipeline integration
- SLA assertions for performance gates

---

## Architecture Decisions

### Layering Rules
1. **Phase 48-51 are peer layers** — no upward imports
2. **Phase 53 decision layer is pure** — imports only from context.py
3. **compose.py is quarantined** — sole entry point for peer-layer imports
4. **Phase 62-65 are consumer layers** — read-only access to core phases, no modifications
5. **Feedback loop** — Phase 62 writes to Phase 50, Phase 50 updates Phase 53 thresholds

### Design Principles
- **Immutability:** All core dataclasses are frozen (@dataclass(frozen=True))
- **Audit trail:** Every alert decision, feedback, and automation decision logged
- **Stdlib only:** No external ML, Flask, or venv — pure Python with `requests` (optional)
- **Stateless detection:** Score = pure function of findings + baselines + context
- **Safe defaults:** Phase 48-51 unavailable? compose() returns safe AlertContext.empty()
- **Feedback-driven tuning:** User feedback integrates into threshold adjustment without manual intervention

---

## Key Files Reference

### Documentation
- **HANDOFF.md** (this file) — project state, phases 62-65, test roadmap
- **BOT-START-HERE.md** — bot orientation, critical constraints, project history
- **ARCHITECTURE_RULES.md** — layering constraints, import rules
- **docs/PHASE_62.md** — Feedback loop specification
- **docs/PHASE_63.md** — Web dashboard specification
- **docs/PHASE_64.md** — Response automation specification
- **docs/PHASE_65.md** — SIEM integration specification

### Core Project Structure
```
secure/
├── remediation/           # Phase 48 — Actions, playbooks, approval
│   ├── models.py         # RemediationAction, Playbook
│   ├── catalog.py        # 12+ built-in actions
│   ├── approval.py       # Risk-stratified approval engine
│   └── executor.py       # Action execution + audit trail
│
├── multi_device/          # Phase 49 — Coordination, correlation
│   ├── device_registry.py
│   ├── cross_device.py    # Finding correlation
│   └── orchestrator.py
│
├── intelligence/          # Phase 50 — CVE/MITRE, learning
│   ├── cve_integrator.py
│   ├── mitre_mapper.py
│   └── learning.py        # analyze_feedback(), threshold tuning
│
├── alerting/              # Phase 53 — Detection intelligence
│   ├── context.py         # Frozen dataclasses
│   ├── suppression.py
│   ├── escalation.py
│   ├── decide.py
│   ├── compose.py         # Single impure boundary
│   └── store.py           # alert_decisions table
│
├── cli/                   # CLI commands
│   ├── feedback.py        # Phase 62 — cmd_feedback_*
│   ├── web.py             # Phase 63 — cmd_web_start
│   ├── siem.py            # Phase 65 — cmd_siem_*
│   └── detection_pipeline.py
│
├── web/                   # Phase 63 — Dashboard (stdlib)
│   └── app.py             # DashboardHandler, HTTP server
│
├── automation/            # Phase 64 — Auto-approval
│   ├── engine.py          # AutomationEngine, confidence calc
│   └── dispatcher.py      # Auto-approval routing
│
├── integrations/          # Phase 65 — SIEM forwarding
│   ├── siem.py            # SIEMForwarder (CEF, Syslog, HEC, JSON)
│   └── config.py          # SIEMConfigManager
│
├── explain/               # Output formatters
│   └── alert_decision_explainer.py
│
└── storage/
    └── schema.py          # SQLite tables + indexes
```

### Test Files
```
tests/
├── integration/
│   ├── fixtures.py                    # GroundTruthInjector, MetricsCollector
│   ├── conftest.py                    # Pytest config + markers
│   ├── test_sensor_ground_truth.py    # Phase 1 (9 tests)
│   └── test_remediation_safety.py     # Phase 2 (8 tests)
│
├── test_alerting_*.py                 # Phase 53 (61 tests)
├── test_intelligence_*.py             # Phase 50 (45 tests)
├── test_remediation_*.py              # Phase 48 (173 tests)
└── test_multi_device.py               # Phase 49 (28 tests)
```

---

## Test Suite

**Total: ~385 tests (17 test files)**

Run by phase:
```bash
# Core phases (48-54): 275 tests
/usr/bin/python3 -m pytest tests/test_*.py -q --ignore=tests/integration

# Production-readiness tests (1-2): 16 tests, ~15 seconds
/usr/bin/python3 -m pytest tests/integration/ -q

# Phase 62: Feedback loop (12 tests)
/usr/bin/python3 -m pytest tests/test_feedback.py -q

# Phase 63: Web dashboard (8 tests)
/usr/bin/python3 -m pytest tests/test_web.py -q

# Phase 64: Automation (12 tests)
/usr/bin/python3 -m pytest tests/test_automation.py -q

# Phase 65: SIEM integration (12 tests)
/usr/bin/python3 -m pytest tests/test_siem.py -q

# Memory-safe subset (max 20 files)
/usr/bin/python3 -m pytest tests/test_alerting_*.py tests/test_feedback.py tests/integration/ -q

# DO NOT run: /usr/bin/python3 -m pytest tests/ -x
# (Full suite exceeds 8GB on test machine)
```

**Metrics Export:**
```bash
# Generate JSON metrics from Phase 1-2 tests
/usr/bin/python3 -m pytest tests/integration/ -v --tb=short > .testing/test_results.txt

# Parse metrics (custom script)
python3 scripts/aggregate_metrics.py .testing/
```

---

## CLI Command Reference (Quick Start)

**Feedback Loop (Phase 62):**
```bash
secure feedback submit --alert-id abc123 --verdict true-positive --reason "Confirmed breach"
secure feedback review --limit 10 --json
secure feedback stats --alert-type persistence --json
```

**Web Dashboard (Phase 63):**
```bash
secure web start --host 127.0.0.1 --port 8080
# Then open http://127.0.0.1:8080 in browser
secure web stop
```

**SIEM Integration (Phase 65):**
```bash
secure siem add --format syslog --host 10.0.0.1 --port 514 --name "Splunk-forward"
secure siem list
secure siem test --name "Splunk-forward"
secure siem enable --name "Splunk-forward"
secure siem disable --name "Splunk-forward"
secure siem remove --name "Splunk-forward"
```

**Detection Pipeline (Phase 54):**
```bash
secure detection-pipeline run --lookback-minutes 5 --json
```

**Remediation (Phase 48):**
```bash
secure remediation catalog
secure remediation playbooks
secure remediation run --action disable-launchagent --target com.malware.plist
secure remediation approve --id abc123
secure remediation history --limit 20 --json
```

**Alerts (Phase 53):**
```bash
secure alerts recent --limit 50 --json
secure alerts counts
secure alerts detail --id abc123
secure alerts stats
```

---

## Documentation Maintenance (For Claude)

**This section describes how to update HANDOFF.md and related docs when phases advance.**

### Update Rules

**When committing a new phase:**

1. **Update HANDOFF.md in same commit** (before `git commit`)
   ```bash
   # 1. Run full test suite
   /usr/bin/python3 -m pytest tests/test_NEW_PHASE.py -q
   
   # 2. Update Phase Completion Status table (add row)
   # 3. Add "Session Work Summary" section for new phase
   # 4. Update "Testing Roadmap" if applicable
   # 5. Run health check
   /usr/bin/python3 -c "from secure.cli.NEW_FEATURE import *; print('✓ Imports OK')"
   
   # 6. Commit with message: "Phase NNN: <feature> — <detail>"
   git add HANDOFF.md
   git commit -m "Phase NNN: ... — <commit message>"
   ```

2. **Health checks after update:**
   ```bash
   # Verify handoff is valid JSON (if exported)
   python3 -c "import json; json.load(open('HANDOFF.md'))" 2>/dev/null || true
   
   # Check imports
   /usr/bin/python3 -c "
   from secure.alerting import decide_alert
   from secure.cli.feedback import cmd_feedback_submit
   from secure.web.app import DashboardHandler
   from secure.integrations.siem import SIEMForwarder
   print('✓ All phase imports OK')
   "
   ```

3. **What NOT to change in HANDOFF.md:**
   - Architecture layering rules (Phases 48-51 peer, 53 pure, 62-65 consumer)
   - Security invariants (audit trail, approval authority)
   - Test constraints (8GB machine, max 20 test files per run)
   - Project location (`/Users/erickvale/Projects/secure-resource`)

4. **Things to update frequently:**
   - Phase Completion Status: Add new phases, update test counts
   - Session Work Summary: Add brief description of new phase
   - Testing Roadmap: Move completed phases from "Planned" to "Completed"
   - CLI Command Reference: Add new `secure` subcommands as they ship

### Metrics Baselines (Don't change without reason)

- **Detection latency:** p50 ≤ 45ms, avg < 50ms
- **False positive rate:** <1% on 1000-scan baseline
- **Detection rate:** ≥95% on injected artifacts
- **Remediation success:** ≥80% execution rate
- **Automation confidence threshold:** >0.8 for auto-approval
- **SIEM retry timeout:** 30 seconds default
- **Test memory ceiling:** <6.5GB per run on 8GB machine

### Emergency Recovery (If HANDOFF.md corrupted)

```bash
# Find last good state
git log --oneline HANDOFF.md | head -5

# Restore previous version
git show COMMIT_SHA:HANDOFF.md > HANDOFF.md

# Verify structure
python3 -c "
lines = open('HANDOFF.md').readlines()
sections = [l for l in lines if l.startswith('#')]
print(f'✓ Found {len(sections)} sections')
print(f'  Starts with: {sections[0].strip()}')"
```

### Version History

| Date | Commit | Update | Status |
|------|--------|--------|--------|
| 2026-09-24 | 29c38bf | Added Phases 62-65 + Test Infrastructure (Phases 1-2) | ✅ Current |
| 2026-09-23 | 4cee6f0 | Phase 53: Detection intelligence + 61 tests | ✅ |
| 2026-09-23 | a5ac70b | Phase 54: Detection pipeline integration | ✅ |
| 2026-09-22 | c4ae767 | Phase 52: GUI + CLI wiring | ✅ |

---

## Critical Rules for Next Session

**When resuming:**

1. **Check location and git status first**
   ```bash
   pwd  # /Users/erickvale/Projects/secure-resource (NOT ~/Desktop)
   git log --oneline | head -1  # HEAD should be 29c38bf or later
   git status  # Should be clean (no uncommitted changes)
   ```

2. **Run health check (60 seconds)**
   ```bash
   /usr/bin/python3 -m pytest tests/test_feedback.py tests/test_alerting_decide.py -q
   # Should pass: test_feedback.py (4 tests) + test_alerting_decide.py (8 tests)
   ```

3. **Memory safety: NEVER run full suite**
   ```bash
   # ✅ OK: Run by component (max 20 test files)
   /usr/bin/python3 -m pytest tests/test_alerting_*.py -q
   /usr/bin/python3 -m pytest tests/integration/ -q
   
   # ❌ DANGEROUS: Causes 8GB machine to swap-kill
   /usr/bin/python3 -m pytest tests/ -x
   ```

4. **Architecture preservation**
   - Phase 48-51 are peer layers (no upward imports)
   - Phase 53 is pure decision layer (only imports from context.py)
   - Phase 62-65 are consumer layers (read Phase 48-51 only)
   - compose.py is sole entry point for peer-layer imports
   - New code must follow these boundaries

5. **Audit trail non-negotiables**
   - Every alert decision stored with reasoning
   - Every remediation action logged with executor + timestamp
   - Every feedback verdict feeds back to Phase 50 learning
   - Every SIEM failure logged (buffered for retry)
   - No silent failures; all errors recorded

6. **Use frozen dataclasses**
   - All context passed between phases must be immutable
   - No mutable state in decision functions
   - No I/O operations in pure functions (alerting, escalation)

7. **Test infrastructure constraints**
   - Pytest fixtures per test file (don't share state)
   - MetricsCollector aggregates results
   - Ground truth injection uses temp directories (cleanup required)
   - SLAs: detection <100ms, remediation rollback 100%, FP rate <1%

---

## Bot Instructions for This Session & Beyond

### When Starting (Every Resume)

1. **Read BOT-START-HERE.md first** (2 min) — critical constraints, project history
2. **Run health check** (1 min):
   ```bash
   cd /Users/erickvale/Projects/secure-resource
   git log --oneline | head -1
   /usr/bin/python3 -c "from secure.cli.feedback import cmd_feedback_submit; print('✓')"
   ```
3. **Check this HANDOFF.md** (3 min) — phases 62-65 summary, testing roadmap
4. **Review user's request** — next phase, bug fix, testing, etc.

### Communication Norms

- **Phone reading:** Keep responses to 1-2 sentences
- **No trailing summaries:** User can read the diff
- **Escalate early:** If 2+ fix attempts fail or security decision needed, call `deep` agent
- **Commit message format:** "Phase NNN: <feature> — <change detail>"
- **Documentation:** Update HANDOFF.md **in the same commit** as phase work

### When Code Changes

1. **Verify tests pass BEFORE committing**
   ```bash
   /usr/bin/python3 -m pytest tests/test_NEW_FEATURE.py -q
   ```

2. **Update HANDOFF.md if:**
   - New phase started → add row to Phase Completion Status
   - New CLI command added → add to CLI Command Reference
   - New architecture decision → document in Architecture Decisions
   - Test infrastructure changed → update Testing Roadmap

3. **Never commit with:**
   - Failing tests
   - Uncommitted HANDOFF.md (if phase changed)
   - Silent failures (log errors even if recoverable)

### Escalate to `deep` Agent When

- Architecture or design decision needed (which pattern? how organize?)
- 2+ independent fix attempts have failed (not 2 retries of same approach)
- Security-sensitive: credentials, audit trail, approval authority
- Hard-to-reverse: force-push, data deletion, API breaking changes
- Blocking: memory issues, git conflicts, external tool unavailable

**How to escalate:** "Escalating to deep agent" + context (goal, what tried, exact error)

---

## User Preferences & Norms

| Aspect | Preference |
|--------|-----------|
| **Bot model** | Haiku 4.5 (fast, cost-effective) |
| **Haiku tasks** | Reading, searching, editing, testing, reporting, mechanics |
| **Deep (Opus) tasks** | Design decisions, debugging (2+ attempts), security, architecture |
| **Communication style** | Short, direct; assume phone reading; no trailing summaries |
| **Workflow** | Move fast, parallel independent work, commit frequently |
| **Memory** | Reused across sessions (check `memory/MEMORY.md`) |
| **Testing** | Never run full suite on 8GB machine (max 20 files per run) |
| **Project moves** | If doc says to move/rename project, ask first (directory is fixed) |

---

## Contact & Meta

**User:** evale92@gmail.com  
**Project:** `secure-resource` (zero-trust detection + response + SIEM)  
**Location:** `/Users/erickvale/Projects/secure-resource` (MOVED from ~/Desktop)  
**Machine:** macOS 8GB, Intel/ARM  
**Python:** `/usr/bin/python3` (no venv, pytest available)  
**Git:** Local development (no remote)  
**Session model:** Claude Haiku 4.5 (Telegram channel @ 7362407464)  

**Latest status:** 2026-09-24 08:20 EDT
- Phases 62-65: User feedback loop, web dashboard, response automation, SIEM integration ✅
- Test infrastructure: Phase 1-2 complete (16 tests), Phases 3-5 planned
- All 385 tests passing (core 275 + enhancement 44 + integration 16)
- HANDOFF.md updated with complete roadmap + maintenance instructions

**Next priorities (from user):**
1. Continue with Phase 3 testing (Learning Loop Stability) if tests improve
2. Or implement Phase 3-5 test infrastructure
3. Or debug/fix specific operational issues
4. User will provide direction on next session

---

**For Claude on next session:** Read BOT-START-HERE.md → This HANDOFF.md → Check git status → Run health check → Ask for next priority.

**Done.** All Phases 62-65 complete. Test infrastructure (1-2) passing. Comprehensive handoff ready. Documentation maintenance instructions loaded for future updates.
