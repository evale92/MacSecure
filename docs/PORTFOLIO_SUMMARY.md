# Secure Project MB — Technical Summary

## What it is

Secure is a local, read-only, single-user macOS security monitoring
and investigation tool: a CLI and companion Tkinter GUI over one
SQLite database. It has no daemon, requires no sudo, blocks or
prevents nothing, and never acts autonomously — it observes, records,
correlates, explains, and (optionally) lets a locally-run LLM propose
a change for a human to approve. It was built across 29 phases, each
scoped, tested, and documented before the next began.

## Scope, measured against the codebase as it stands

- 254 Python files across 21 domain packages under `secure/`
  (persistence, connections, listening, wifi, bluetooth including live
  BLE, ARP watch, file integrity, device inventory, security posture
  checks, correlation, evidence/dedup, baseline/anomaly detection,
  explainability, investigation, threat intel enrichment, DFIR
  collection, detection-rule management, an AI analyst, and six
  external-tool integrations: osquery, YARA-X, Sigma, Suricata, Zeek,
  Velociraptor).
- 59 tables in one SQLite schema, all defined in one place, with
  additive-only migrations (verified idempotent against populated data
  in Phase 29 Stage 6).
- 21 CLI command groups; a GUI that mirrors the CLI's own read paths
  rather than duplicating logic.
- 1,573 automated tests across 85 files — 0 failing as of the most
  recent full run (Phase 29 Stage 9; see `docs/VALIDATION_REPORT.md`
  for exactly how that run was performed and its own honestly-stated
  limits).
- 18 design/reference documents under `docs/`, covering architecture,
  threat model, every subsystem's own design writeup, a
  capabilities matrix, an SBOM, a known-limitations document, and this
  summary.

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
- **Every claim in this phase's own audit is backed by a regression
  test, a live-host run, or a deliberately induced failure** — not
  documentation alone. That was the explicit governing rule for
  Phase 29's second half (Stages 6–12), and it's the same standard
  this summary itself is trying to hold to: nothing above is asserted
  without a stage, a test file, or a live command backing it, and
  `docs/KNOWN_LIMITATIONS.md` states plainly where that evidence runs
  out (chiefly: this development sandbox cannot run real `pytest` or
  exercise macOS-only binaries, so the final cross-check needs a real
  Mac).

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
