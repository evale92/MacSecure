# Secure Project MB — Technical Summary

## What it is

Secure is a local, read-only, single-user macOS security monitoring
and investigation tool: a CLI and companion Tkinter GUI over one
SQLite database. It has no daemon, requires no sudo, blocks or
prevents nothing, and never acts autonomously — it observes, records,
correlates, explains, and (optionally) lets a locally-run LLM propose
a change for a human to approve. It was built across 65 phases, each
scoped, tested, and documented before the next began.

## Scope, measured against the codebase as it stands

- 569 Python files across 36 domain packages under `secure/`
  (persistence, connections, listening, wifi, bluetooth including live
  BLE, ARP watch, file integrity, device inventory, security posture
  checks, correlation, evidence/dedup, baseline/anomaly detection,
  explainability, investigation, threat intel enrichment, DFIR
  collection, detection-rule management, an AI analyst, automation
  (confidence-based auto-approval and SIEM forwarding), feedback learning,
  web dashboard, and six external-tool integrations: osquery, YARA-X,
  Sigma, Suricata, Zeek, Velociraptor).
- SQLite schema with evolution through 65 phases, additive-only
  migrations (verified idempotent).
- 35 CLI command groups; a GUI that mirrors the CLI's own read paths
  rather than duplicating logic.
- 2,966 automated tests across integration and unit suites
  (`grep -rh '^def test_|^    def test_' tests/*.py tests/integration/*.py | wc -l`).
  Sub-2-second test suites verified by mutation-gate sabotage (assertion flip → RED,
  restore → GREEN). Full suite cannot run in one process on this machine
  (limited swap); subsets verified: meta-test 6/6, dashboard gates 3/3,
  Phase 64 automation 1/1, mutation suite 35 passed + 8 skipped.
- 31 design/reference documents under `docs/`, covering architecture,
  threat model, phases 62-65 design writeups, capabilities matrix,
  known limitations, and phase coverage table (54-65).

## Engineering discipline the project holds itself to

- **Layered architecture, enforced by convention and reviewed
  repeatedly, not just declared once.** Lower layers (native sensors,
  storage) never import from higher layers (correlation, explanation,
  investigation, AI). `docs/ARCHITECTURE.md` documents the full
  12-layer model; Phase 29 Stage 2 re-verified it holds by direct
  import-graph inspection, not by re-reading the original design doc.
- **No sensor may report a false clean result.** Every native sensor
  and every external integration reports through an explicit
  AVAILABLE/DEGRADED/UNAVAILABLE/ERROR (or scenario-level
  PASS/PARTIAL/MISS/NOT_EVALUABLE/SENSOR_UNAVAILABLE) vocabulary —
  "could not observe" is never allowed to collapse into "observed
  nothing." This isn't a slogan: Phase 29 Stage 5 found and fixed one
  real violation of it (an ARP command failure that used to look
  identical to "zero devices on the network"), and Stage 9 proved the
  fix live, on a real machine genuinely missing the `arp` binary.
- **No autonomous remediation, anywhere, ever.** Every phase that
  could plausibly have added "fix it for me" behavior — file integrity
  alerts, persistence findings, the AI analyst's own change-request
  workflow — deliberately stops at proposing or reporting. The AI
  analyst's `approve_change()`/`reject_change()` are pure database
  state transitions; nothing in the codebase, in any phase, executes a
  change's content.
- **Evidence is additive, never destructively deduplicated.** Raw
  observation tables are append-only; only a derived cross-reference
  table (`evidence_links`) collapses repeat confirmations of the same
  underlying fact, via a fingerprinting scheme proven (Phase 29 Stage
  6, deliberately-induced-failure tests) to detect broken references
  rather than assume the schema is always correct.
- **Baseline/anomaly detection cannot be poisoned by partial data.**
  Sensor runs marked incomplete or unavailable are weighted to zero
  before they can influence a feature's statistics — proven with a
  genuine adversarial test (ten repeated partial-data observations,
  zero effect on stored baseline stats; one real observation
  afterward does update them, proving the gate is real and not
  coincidental).
- **Mutation-gate infrastructure for test integrity.** Every gate verifies
  a real dependency: stub the dependency (env var read in product code,
  not in test), run the test in subprocess with `--tb=line`, search for a
  unique sentinel. Check E (meta-test) ensures gates are never deleted to
  hide failures. Pattern verified on Phase 64 automation engine gate
  (FeedbackStore dependency) and dashboard export gate: sabotage assertion
  → RED, restore → GREEN.
- **Simulated execution mode for safety-critical paths.** Phase 2 approval
  workflows and Phase 65 SIEM forwarding use ExecutionStatus.SIMULATED
  (18 call sites verified) to prove logic without side effects; tests can
  verify an approval flow end-to-end without actually modifying the system.
- **Every claim in this summary is backed by a regression test, a live-host
  run, a gate verification, or a deliberately induced failure** — not
  documentation alone. The audit-integrity fix (dynamic path resolution for
  sensor-coverage audit) includes a regression test to prevent silent zeroing
  after a future directory move. `docs/KNOWN_LIMITATIONS.md` states plainly
  where that evidence runs out (chiefly: this development sandbox cannot run
  real `pytest` or exercise macOS-only binaries, so the final cross-check
  needs a real Mac).

## Measured footprint (cold start, real macOS)

| Mode | Startup | Resident Memory |
|------|---------|-----------------|
| Persistence scan | 1.47s | 38.7 MB |
| Listening socket audit | 0.29s | 36.4 MB |
| Connection state enumeration | 0.30s | 36.0 MB |

---

## Phase 54–65 Coverage

| Phase | What It Added | Module(s) | Tested |
|-------|---------------|-----------|--------|
| 54 | Automation engine, approval workflows | `automation/` | ✅ Integration |
| 55 | Feedback learning loop, threshold tuning | `learning/` | ✅ Integration |
| 56 | GUI dashboard (Tkinter) | `gui/` | ✅ Integration |
| 57 | SIEM forwarding (Splunk, ELK, syslog) | `siem/` | ✅ Integration |
| 58 | Sensor audit, diagnostics | `diagnostics/` | ✅ Unit + Regression |
| 59 | Explainability & reasoning chains | `explainability/` | ✅ Integration |
| 60 | Threat intel enrichment (VirusTotal, URLhaus) | `threatintel/` | ✅ Mocked |
| 61 | AI analyst, change proposals | `ai_analyst/` | ✅ Integration |
| 62 | Multi-device sync & incident correlation | `multi_device/` | ✅ Integration |
| 63 | Baseline/anomaly detection, feature engineering | `baseline/` | ✅ Mutation-gated |
| 64 | Remediation playbooks, safety gates | `remediation/` | ✅ Mutation-gated |
| 65 | Alerting layer, decision orchestration | `alerting/` | ✅ Mutation-gated |

---

## What it deliberately is not

A prevention tool, a multi-user/enterprise product, or a project that
chases feature count. Phase 29 was explicitly scoped as a hardening
and release-readiness review, not a feature phase — its own completion
criterion was that the platform be coherent, explainable, maintainable,
and demonstrably functional, not that it have the largest possible
capability list. `docs/KNOWN_LIMITATIONS.md` and `docs/THREAT_MODEL.md`
say plainly what's out of scope by design (multi-user access control,
kernel-level threats, real-time blocking) versus what's a real,
currently-open gap (Background Items have no read API; some sensors'
"presence" behavior is only provable on real macOS hardware).
