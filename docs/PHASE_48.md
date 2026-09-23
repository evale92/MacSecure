# Phase 48 — Automated Remediation & Response Orchestration

**Status:** Specification. This phase adds automated remediation actions built on Phase 47's verified safe-code infrastructure, extending Secure from *detection-only* to *response-capable*.

## Scope

Phase 48 adds three capability layers:

1. **Remediation Catalog**: Predefined, safe fixes for common findings (disable service, enable firewall, revoke SSH key, etc.)
2. **Approval Tiers**: Risk-stratified approval flows (instant for low-risk, human-review for medium/high)
3. **Incident Orchestration**: Chain multiple remediations into coordinated response sequences

### What Phase 48 does
- Defines remediation actions as immutable, auditable specifications
- Executes remediations through Phase 47's verified-safe mechanism (never directly)
- Tracks approval workflows per action type and risk classification
- Learns which remediations worked by comparing pre/post-scan telemetry
- Surfaces multi-step playbooks (e.g., "isolate + patch + restart service")

### What Phase 48 deliberately does NOT do
- Auto-escalate privilege to sudo/admin (no `sudo` calls)
- Make destructive changes without explicit user approval (deletes, wipes, format)
- Change behavior based on threat intelligence alone (TI feeds inform scoring, not triggers)
- Modify system configuration outside explicitly-allowed remediations
- Execute third-party scripts or playbooks (Secure-authored only)

## Design: Remediation Actions

A remediation action is a named, versioned recipe:

```python
@dataclass
class RemediationAction:
    id: str                          # e.g., "firewall.enable", "ssh.disable-root-login"
    name: str                        # "Enable firewall"
    description: str                 # What this does, in plain English
    risk_level: Literal["low", "medium", "high"]  # User-facing severity
    prerequisites: list[str]         # Other actions that must run first
    applicability: RemediationScope  # Which Macs/findings this applies to
    
    # The change request this action generates
    change_request_template: str     # Path to Jinja2 template or function
    
    # Outcome detection: how to verify if this actually worked
    verification: RemediationVerification  # See below
    
    # Metadata
    first_shipped_in: str            # Phase/version
    examples: list[str]              # Attack patterns this addresses
    references: list[str]            # MITRE ATT&CK, docs links
```

Example actions (Phase 48 ships ~12 initial remediations):

- **firewall.enable** (low): Enable macOS firewall if disabled
- **firewall.block-incoming** (medium): Add inbound firewall rule for anomalous service
- **ssh.disable-root-login** (low): Set `PermitRootLogin no` in sshd_config
- **service.disable** (medium): Disable suspicious LaunchAgent/LaunchDaemon
- **network.isolate-ip** (high): Route suspicious IP through lo0 (no-op network isolation, safe)
- **process.alert-on-relaunch** (low): Flag if killed process relaunches
- **credential.recommend-rotation** (low): User-actionable finding, no direct action
- **config.harden-umask** (low): Set restrictive umask in shell rc files
- **endpoint.mdm-notify** (medium): Notify paired MDM (if configured) of finding
- **threat-hunt.priority-flag** (low): Raise detection priority in correlation

## Design: Approval Tiers

Low-risk actions (firewall enable, umask harden) can auto-execute with post-action notification.
Medium-risk actions (service disable, firewall block) require human approval before execution.
High-risk actions (network isolation) route through Phase 47's full reviewer workflow.

```python
@dataclass
class ApprovalPolicy:
    action_id: str
    risk_level: Literal["low", "medium", "high"]
    
    # When to require approval
    approval_required: bool          # False for low, True for medium/high
    
    # If approval_required is True:
    escalation_path: str             # "human_review", "mdm_supervisor", "security_team"
    escalation_timeout: timedelta    # How long to wait (medium: 1 hour, high: 24 hours)
    
    # If action is low-risk and auto-executable:
    post_action_notification: bool   # Always true; user is informed
    rollback_allowed: bool           # Can user undo within X hours?
```

## Design: Incident Orchestration

Playbooks are sequences of remediation actions + verification loops:

```python
@dataclass
class PlaybookStep:
    remediation_id: str
    condition: str                   # e.g., "if anomaly_score > 80"
    on_success: Optional[str]        # ID of next step
    on_failure: Optional[str]        # ID of alternate remediation
    
@dataclass
class Playbook:
    id: str                          # e.g., "incident.lateral_movement"
    name: str                        # "Suspected Lateral Movement Response"
    trigger: PlaybookTrigger         # Detection pattern + anomaly score threshold
    steps: list[PlaybookStep]
    
    # Phase 48 ships ~5 built-in playbooks:
    # - incident.unsigned-process (persistent + unsigned execution)
    # - incident.persistence-change (LaunchAgent modified unexpectedly)
    # - incident.network-anomaly (new connection + process + file change in 60s)
    # - incident.privilege-escalation (process with parent_uid != uid)
    # - incident.lateral-movement (SSH keys modified + new network destination)
```

## Schema Additions

Three new tables:

```sql
CREATE TABLE IF NOT EXISTS remediation_actions (
    id                      TEXT PRIMARY KEY,
    name                    TEXT NOT NULL,
    description             TEXT NOT NULL,
    risk_level              TEXT NOT NULL CHECK(risk_level IN ('low', 'medium', 'high')),
    action_type             TEXT NOT NULL,  -- 'firewall', 'ssh', 'service', etc.
    change_request_template TEXT NOT NULL,
    verification_type       TEXT,           -- 'scan_comparison', 'config_check', 'manual'
    first_shipped_in        TEXT NOT NULL,
    examples_json           TEXT DEFAULT '[]',
    references_json         TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS remediation_executions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id        TEXT NOT NULL UNIQUE,
    created_at          TEXT NOT NULL,
    action_id           TEXT NOT NULL REFERENCES remediation_actions(id),
    triggered_by        TEXT NOT NULL,  -- 'finding_id', 'user_request', 'playbook_run'
    triggered_by_ref    TEXT NOT NULL,
    approval_required   INTEGER NOT NULL,
    approved_at         TEXT,
    approved_by         TEXT,
    executed_at         TEXT,
    execution_status    TEXT NOT NULL DEFAULT 'pending',  -- pending, approved, executed, rolled_back, failed
    change_request_id   TEXT REFERENCES ai_change_requests(cr_id),
    repair_run_id       TEXT REFERENCES agent_repair_runs(run_id),
    outcome             TEXT,           -- 'success', 'partial', 'failed', 'rolled_back'
    verification_result TEXT,
    notes               TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS playbook_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL UNIQUE,
    created_at      TEXT NOT NULL,
    completed_at    TEXT,
    playbook_id     TEXT NOT NULL,
    trigger_finding TEXT NOT NULL,  -- finding_id that triggered this
    status          TEXT NOT NULL DEFAULT 'running',  -- running, completed, failed, stopped
    executions_json TEXT DEFAULT '[]'  -- List of execution_ids in sequence
);
```

## Implementation Phases

### Phase 48.1: Remediation Catalog & Execution Foundation
- Define RemediationAction, ApprovalPolicy, PlaybookStep dataclasses
- Implement `remediation/catalog.py` with 12 initial actions
- Implement `remediation/executor.py` — wraps changes as Phase 47 change requests
- Add schema tables
- Write 80+ tests for action definitions and catalog loading

### Phase 48.2: Approval Workflows
- Implement `remediation/approval.py` — routes actions to approval tier
- Implement low-risk auto-execute with post-notification
- Implement medium/high-risk human review workflow
- Add escalation timeouts and fallback paths
- 60+ tests for approval logic

### Phase 48.3: Incident Orchestration
- Implement `remediation/playbooks.py` — load and parse playbook sequences
- Implement step execution with condition checking and branching
- Implement playbook trigger matching (findings + anomaly score)
- Ship 5 built-in playbooks
- 50+ tests

### Phase 48.4: Learning Loop
- Implement `remediation/outcomes.py` — track pre/post-scan changes
- Compare file integrity, persistence, network baseline before/after action
- Record what worked, what didn't, success rates per action
- 40+ tests

### Phase 48.5: GUI Integration & Docs
- Add "Remediation" category to secure_gui.py
- Show pending approvals, execution history, playbook runs
- Add `secure remediation` CLI group
- Update PROJECT_NOTES.md with full walkthrough
- 50+ tests for CLI/GUI integration

## Definition of Done

- [ ] All 280+ tests pass (Phase 48.1-48.4)
- [ ] Phase 27 validation still at 15 PASS (no regression)
- [ ] Five built-in playbooks execute end-to-end on synthetic findings
- [ ] No action executes without user awareness (notification minimum)
- [ ] Approval tier policies are configurable per user
- [ ] Rollback is possible for low/medium actions within 24h
- [ ] Learning loop tracks action efficacy (success rate, time to detect success)
- [ ] Docs include threat model (what Phase 48 does not defend against)
- [ ] Documentation complete in PROJECT_NOTES.md

## Risk & Limitations

**What Phase 48 does not defend against:**
- Attacker with user account credentials (they can approve remediations)
- Attacker with physical access (can bypass all controls)
- Tampered remediation catalog (Phase 47 verification applies)
- User disabling Secure itself (user is responsible for Mac security baseline)

**Known limitations:**
- Remediations are macOS-only (network isolation is OS-level, not app-level)
- No cross-device remediation (Phase 27's standing decision)
- MDM integration requires external MDM already installed and paired
- Rollback is time-limited (24h) to prevent old rollback chains

---

**Estimated effort:** ~3-4 weeks for full implementation + testing + docs
**Builds on:** Phase 47 (verified safe-code loop), Phase 28 (AI context)
**Enables:** Phase 49 (Multi-Device Orchestration), Phase 50 (Threat Intel Integration)
