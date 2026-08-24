# Roadmap — Part 2, Phases 38–47 (verbatim governing text)

Saved to disk 2026-08-22 so this never has to be re-pasted and any
future session can pick the work up cold. **This file is the verbatim
governing instruction as issued by the user.** Do not paraphrase,
"improve," or reinterpret it here — a phase's acceptance criteria are
whatever this file says they are. Phase-by-phase results, decisions,
and VERIFIED marks live in `PROJECT_NOTES.md` and
`docs/AGENT_FOUNDATION.md`, not here.

Two operational notes accompanied the text and are binding alongside
it:

1. Phase 41 names a real address (`evale92@gmail.com`). Build and test
   the notification path, but **do not send real email to it** without
   saying so first.
2. Phase 42's launchd installation and Phase 46's package updates are
   explicitly approval-gated: implement and test with mocks/fixtures,
   raise the change request, and **stop** rather than touching the live
   Mac.

---

Continue Secure Project MB Part 2 from Phase 38 through Phase 47.

Phase 37 is already VERIFIED. Do not redo it.

Continue automatically between phases when the current phase is VERIFIED,
all required tests/validation pass, no material model disagreement exists,
and no approval-gated action is required.

STOP only for:
- SYSTEM_CHANGE
- PRIVILEGED_CHANGE
- DEPENDENCY_CHANGE requiring live-system modification
- SECURITY_SEMANTIC_CHANGE
- destructive/data-loss risk
- unresolved architectural ambiguity
- deterministic verification failure
- material coder/reviewer disagreement

Never weaken tests to obtain green results.
Never invent acceptance criteria.
Prefer existing open-source frameworks over bespoke implementations.
All agent actions remain subject to the Phase 31/31.5 isolation, audit,
verification, diff-hashing, and approval boundaries.


======================================================================
PHASE 38 — INDEPENDENT REVIEWER
======================================================================

Make the second local model an independent reviewer of non-trivial repairs.

Provide it:
- original failure
- diagnosis
- actual Git diff
- files changed
- tests run
- results
- relevant architecture/security policies

Ask it to evaluate:
- does the patch address the root problem?
- are tests being weakened?
- could data be lost?
- could security be weakened?
- is provenance affected?
- are architecture boundaries violated?
- is the change unnecessarily broad?
- were unexplained dependencies introduced?
- does anything require human approval?

The reviewer does not determine test success.
Deterministic verification remains authoritative.

If coder and reviewer materially disagree:
STOP AND ESCALATE.

Record both assessments.

ACCEPTANCE:
A non-trivial candidate repair can be independently reviewed, its assessment
is persisted/auditable, deterministic test results remain authoritative, and
material disagreement prevents automatic progression.


======================================================================
PHASE 39 — CHANGE CLASSIFICATION
======================================================================

Classify proposed changes before promotion.

At minimum:
SAFE_PROJECT_CODE
DEPENDENCY_CHANGE
SECURITY_SEMANTIC_CHANGE
SYSTEM_CHANGE
PRIVILEGED_CHANGE

Examples requiring approval include:
- launchd
- firewall
- macOS settings
- network configuration
- Bluetooth/Wi-Fi configuration
- Keychain
- package installation/removal/update
- permissions outside Secure
- sudo/root
- external background services
- destructive schema/data operations

Classification must be deterministic where possible.

When uncertain, choose the more restrictive class.

Do not let model confidence downgrade the required approval level.

ACCEPTANCE:
Tests prove consequential changes cannot be classified into automatic
execution merely because an LLM describes them as safe. Unknown/ambiguous
cases fail toward the more restrictive classification.


======================================================================
PHASE 40 — CHANGE REQUEST CENTER
======================================================================

Extend Secure's existing change-request workflow rather than replacing it.

Expose pending consequential changes in the Secure GUI.

For each request show:
- request ID
- requesting run
- requesting model/framework
- reason
- exact proposed action
- actual diff where applicable
- diff/revision hash
- affected files/settings
- risk classification
- commands involved
- tests performed
- test results
- reviewer assessment
- rollback strategy
- status

Provide:
VIEW DETAILS
VIEW DIFF
VIEW TESTS
APPROVE
REJECT

Approval must remain bound to the exact reviewed revision/diff.

If proposed content changes after approval:
INVALIDATE/SUPERSEDE THE REQUEST.

Never silently transfer approval to changed content.

ACCEPTANCE:
A consequential candidate can be reviewed end-to-end in Secure; approval is
cryptographically/revision-bound to the reviewed content; changed content
cannot inherit stale approval.


======================================================================
PHASE 41 — EMAIL CHANGE NOTIFICATIONS
======================================================================

Whenever a consequential change reaches AWAITING_APPROVAL, notify:

evale92@gmail.com

Reuse existing Secure notification/email infrastructure where possible.

Notify for at least:
DEPENDENCY_CHANGE
SECURITY_SEMANTIC_CHANGE
SYSTEM_CHANGE
PRIVILEGED_CHANGE

Email should contain:
- request ID
- reason
- requested action
- classification
- requesting agent/model
- reviewer result
- status
- instruction to review inside Secure

Email is notification only.

Email replies must NEVER authorize execution.

Never include secrets or sensitive model context.

ACCEPTANCE:
Tests prove the correct approval states generate sanitized notifications,
ordinary SAFE_PROJECT_CODE does not unnecessarily notify, secrets cannot enter
the generated email, and email has no authorization path.


======================================================================
PHASE 42 — BACKGROUND SUPERVISOR
======================================================================

Add lightweight background scheduling using a standard macOS mechanism such
as launchd.

Do not build a custom daemon framework if launchd provides the lifecycle
management needed.

The supervisor may trigger bounded jobs such as:
- health check
- integration-health check
- FAST verification
- failure review
- pending interrupted-run review

State vocabulary may include:
IDLE
CHECKING
TESTING
DIAGNOSING
REPAIRING_IN_SANDBOX
VERIFYING
AWAITING_APPROVAL
HEALTHY
FAILED

Resource use must remain conservative.

Do not continuously run the full regression suite.

Do not let ordinary GUI launch trigger autonomous repairs.

IMPORTANT:
Installing/modifying an actual launchd job on the live Mac is a SYSTEM_CHANGE.
Implement and test the scheduling machinery without installing it. Generate a
change request and STOP before live launchd installation unless I explicitly
approve it.

ACCEPTANCE:
Scheduling/supervisor behavior can be tested without modifying live launchd;
jobs are bounded/audited; ordinary GUI startup cannot trigger repairs; actual
launchd installation is approval-gated.


======================================================================
PHASE 43 — AUTOMATED FAILURE DIAGNOSIS
======================================================================

Connect health/testing failures to the repair workflow.

Required sequence:

DETECT FAILURE
→ REPRODUCE
→ COLLECT MINIMAL RELEVANT CONTEXT
→ PRIMARY AGENT DIAGNOSIS
→ SANDBOX REPAIR
→ TARGETED TESTS
→ BROADER TESTS AS REQUIRED
→ INDEPENDENT REVIEW

Do not dump the entire repository into model context by default.

Prefer targeted retrieval based on:
- traceback
- failing tests
- imports
- affected module
- recent changes
- relevant architecture documentation

If the failure cannot be reproduced, record that explicitly.

Do not fabricate a repair for a non-reproducible failure.

ACCEPTANCE:
Known synthetic failures can travel automatically from detection through
reproduction, bounded-context diagnosis, isolated repair, verification, and
review. Non-reproducible failures stop honestly.


======================================================================
PHASE 44 — VERIFIED SELF-HEALING
======================================================================

Define authoritative criteria for VERIFIED repairs.

A repair may be VERIFIED only when:

1. original failure was reproduced before repair
2. candidate patch was applied only in isolation
3. original failure disappears
4. FAST verification passes
5. TARGETED tests pass
6. FULL regression passes when required
7. Phase 27 validation passes when security behavior is affected
8. performance diagnostics show no unacceptable regression where relevant
9. independent review reports no blocking issue
10. architecture/security policy remains satisfied
11. actual final diff still matches its recorded hash

Only VERIFIED SAFE_PROJECT_CODE changes may become candidates for automatic
promotion.

All other classifications follow their approval policy.

Never define success from model confidence or textual self-assessment.

ACCEPTANCE:
Adversarial tests prove no candidate can reach VERIFIED by skipping required
gates, changing its diff after verification, relying on model confidence, or
failing required deterministic checks.


======================================================================
PHASE 45 — MAINTENANCE MEMORY
======================================================================

Add structured engineering/repair history.

Do not use unrestricted chat history as the primary memory system.

Store structured facts such as:
- failure signature
- timestamp
- affected component
- root cause
- repair strategy
- framework/model used
- files changed
- diff/revision identity
- verification performed
- reviewer assessment
- approval decision
- final outcome
- rollback
- later regression linked to this repair

Allow future failures to search prior validated repairs.

Previous repairs are evidence, not authority.

Never blindly replay an old patch against changed code.

ACCEPTANCE:
A later matching failure can retrieve relevant historical repair evidence while
preserving revision/context differences and without automatically applying the
old solution.


======================================================================
PHASE 46 — DEPENDENCY & SECURITY TOOL MAINTENANCE
======================================================================

Extend the supervised workflow to external tooling and dependencies.

Relevant components may include:
- Ollama
- local models
- mini-SWE-agent
- Aider
- osquery
- YARA-X
- Sigma content/tooling
- Suricata
- Zeek
- Velociraptor
- Python dependencies

Preferred workflow:

UPDATE/COMPATIBILITY ISSUE DETECTED
→ ANALYZE
→ TEST CHANGE IN ISOLATION
→ TARGETED TESTS
→ FULL REGRESSION AS NEEDED
→ SECURITY VALIDATION AS NEEDED
→ INDEPENDENT REVIEW
→ CHANGE CLASSIFICATION
→ APPROVAL IF REQUIRED
→ PROMOTION
→ POST-CHANGE VERIFICATION

Never silently update the live security stack.

Package installation/update remains approval-gated.

Do not install tools merely because they appear in this phase. Reuse installed
tools and simulate/mimic update scenarios in tests where appropriate.

ACCEPTANCE:
Secure can identify and analyze representative dependency/tool maintenance
situations and produce a verified proposal/change request without silently
altering the live environment.


======================================================================
PHASE 47 — SUPERVISED AUTONOMOUS MAINTENANCE
======================================================================

Integrate the completed Part 2 components into one bounded maintenance loop.

Target flow:

HEALTH / TESTS
→ FAILURE DETECTED
→ REPRODUCE
→ PRIMARY CODER
→ ISOLATED REPAIR
→ ACTUAL GIT DIFF
→ DETERMINISTIC TESTS
→ SECURITY VALIDATION WHEN RELEVANT
→ INDEPENDENT REVIEW
→ CHANGE CLASSIFICATION

Then:

VERIFIED SAFE_PROJECT_CODE
→ policy-permitted promotion

OR:

CONSEQUENTIAL CHANGE
→ CHANGE REQUEST
→ SECURE UI
→ EMAIL NOTIFICATION
→ HUMAN APPROVAL
→ APPLY
→ POST-VERIFY

Finally:
→ AUDIT / MAINTENANCE MEMORY


FINAL AUTHORITY MODEL

LLMs may:
- investigate
- diagnose
- propose
- edit isolated code
- execute permitted sandbox operations
- run tests
- review patches
- prepare change requests

LLMs do NOT independently establish:
- authorization
- security truth
- successful deterministic verification
- permission for consequential host changes

Deterministic sensors/tests establish observable results.
Secure policy establishes permitted actions.
Human approval authorizes consequential system changes.

Every meaningful autonomous action must remain attributable and auditable.

ACCEPTANCE:
Demonstrate the complete loop using controlled synthetic failures.

At minimum demonstrate:
1. one repair that safely reaches VERIFIED through the automated pipeline
2. one intentionally failing repair that is rejected
3. one consequential/system-change scenario that stops at AWAITING_APPROVAL
   without modifying the host
4. one coder/reviewer disagreement that escalates instead of proceeding
5. one non-reproducible failure that stops honestly
6. complete action/provenance history for each scenario

Run the complete regression suite and relevant Phase 27 validation before
declaring Part 2 complete.

Do not perform a real host/system change merely to demonstrate Phase 47.

Proceed with Phase 38 now and continue automatically under these rules.
