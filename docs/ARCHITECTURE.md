# Architecture (Phase 29)

This document is the single, current map of Secure Project MB's whole
codebase — 267 source files across 30 phases, consolidated here rather
than re-derived phase-by-phase. It supersedes no other doc; `docs/*.md`
files remain the authoritative deep-dive for each subsystem they cover
(cross-referenced below).

## The layer model

Secure is built in strict layers. A layer only ever depends on layers
below it — nothing in a lower layer imports from a higher one. This is
the single architectural rule that has held across all 28 phases.

```
 1. Foundation        secure/config.py, secure/logging_setup.py,
                       secure/storage/ (database.py + models/)

 2. Native sensors     secure/persistence, fileintegrity, connections,
                        listening, wifi, bluetooth, arpwatch, inventory,
                        checks — read-only macOS observation, no
                        external dependency beyond the stdlib + Apple's
                        own read-only CLI tools

 3. External           secure/integrations/{osquery,yarax,sigma,
    integrations         suricata,zeek}, secure/dfir/velociraptor —
                          normalize a specialist security tool's own
                          output into Secure's shape; a missing/broken
                          tool reports OK/DEGRADED/UNAVAILABLE/ERROR,
                          never a silent clean pass

 4. Evidence &         secure/evidence — the fingerprint/lineage model
    deduplication        every sensor and integration's findings are
                          linked through (evidence_links), preventing
                          the same real-world event from being counted
                          twice across independent sensors

 5. Baseline &         secure/baseline — learns per-Mac normal behavior
    anomaly               over time and flags statistically unusual
                           activity, poisoning-resistant by design
                           (maturity/eligibility gating)

 6. Correlation        secure/correlate, secure/detect — clusters
                         multi-sensor signals into higher-confidence
                         findings; secure/detect is the rule-lifecycle
                         layer (Sigma/YARA-X/Suricata rule sync,
                         fixture validation, firing history)

 7. Explanation &      secure/explain — turns any finding into a
    threat intel          human-readable Explanation (severity,
                           confidence, evidence, uncertainty);
                           secure/threatintel enriches with external
                           reputation data, opt-in, never authoritative

 8. Investigation      secure/investigate — entity-centric pivoting:
                         given a process/file/destination/persistence
                         item, walk everything Secure knows about it
                         (timeline, related evidence, pivots)

 9. DFIR               secure/dfir — the ONE layer that can reach
                         beyond read-only observation: explicit,
                         human-triggered Velociraptor artifact
                         collection, allowlist-gated

10. Validation         secure/validate — a synthetic-fixture framework
                         that proves layers 2-9 actually work, entirely
                         against throwaway sandboxes, never the real DB

11. AI analyst         secure/ai — optional local-LLM layer that reads
    (optional)           everything from layers 4-10 read-only, never
                          authoritative, with a change-request workflow
                          requiring explicit human approval for any
                          proposal it or its own verifier model makes

12. Interfaces         secure/cli (secure/__main__.py's entry point)
                         and secure_gui.py — both are thin: they parse
                         input, call into layers 1-11, and format
                         output. Neither contains detection or scoring
                         logic of its own.
```

## Package-by-package map

### Foundation

| Package/module | Purpose |
|---|---|
| `secure/config.py` | `AppConfig` dataclass, `load_config()`/`save_config()` — one JSON file at `~/.secure/config.json`, forgiving load (missing file/field never crashes), every optional integration gated by an empty-string-default field. |
| `secure/logging_setup.py` | Structured (JSON) logging to `~/.secure/logs/` + console. |
| `secure/storage/database.py` | Schema (59 tables), connection handling, additive-only migrations (`init_schema()`, safe to call every run). |
| `secure/storage/models/` | One file per domain (persistence, connections, ai, ...) — the only code that writes SQL; every other layer goes through these functions, never raw SQL of its own. |

### Native sensors (layer 2)

`persistence`, `fileintegrity`, `connections`, `listening`, `wifi`,
`bluetooth` (+ `bluetooth/ble/`), `arpwatch`, `inventory`, `checks` — each
reads one class of macOS state via a read-only, no-sudo command or API,
persists observations, and raises alerts on new/changed/unusual
findings. Each has its own `docs/*.md` where one exists, and every one
follows the same `_shell.py` seam pattern (isolate the one subprocess
call behind a module tests can mock).

### External integrations (layer 3)

| Package | Tool | Docs |
|---|---|---|
| `secure/integrations/osquery/` | osquery | `docs/INTEGRATIONS.md` |
| `secure/integrations/yarax/` | YARA-X | `docs/INTEGRATIONS.md` |
| `secure/integrations/sigma/` | Sigma rules | `docs/INTEGRATIONS.md` |
| `secure/integrations/suricata/` | Suricata EVE JSON | `docs/INTEGRATIONS.md` |
| `secure/integrations/zeek/` | Zeek logs | `docs/INTEGRATIONS.md` |
| `secure/dfir/velociraptor/` | Velociraptor | `docs/DFIR.md` |

All six share `secure/integrations/base.py`'s `STATUS_OK` /
`STATUS_DEGRADED` / `STATUS_UNAVAILABLE` / `STATUS_ERROR` vocabulary —
see `docs/CAPABILITIES_MATRIX.md` (Stage 3) for the full confirmation
that every one of them reports honestly.

### Cross-cutting analysis (layers 4-9)

| Package | Purpose | Docs |
|---|---|---|
| `secure/evidence/` | Fingerprinting + `evidence_links` — the shared identity model every dedup decision in the app goes through. | `docs/EVIDENCE.md` |
| `secure/baseline/` | Per-Mac behavioral baseline + anomaly scoring. | `docs/BASELINING.md` |
| `secure/correlate/` | Cross-module clustering into `correlation_alerts`; `secure/detect/` for rule lifecycle + chain scoring. | `docs/CORRELATION_CHAINS.md`, `docs/DETECTION_ENGINEERING.md` |
| `secure/explain/` | Deterministic `Explanation` object (severity/confidence/evidence/uncertainty) for any alert row. | `docs/EXPLAINABILITY.md` |
| `secure/threatintel/` | Opt-in external reputation enrichment, cache-first, never authoritative. | `docs/THREATINTEL.md` |
| `secure/investigate/` | Entity resolution + timeline + pivot discovery. | `docs/INVESTIGATION.md` |
| `secure/dfir/` | Human-triggered forensic collection, allowlist-gated. | `docs/DFIR.md` |

### Validation and AI (layers 10-11)

| Package | Purpose | Docs |
|---|---|---|
| `secure/validate/` | Synthetic fixture scenarios proving detection/correlation/explanation work, against throwaway sandboxes only. | `docs/SECURITY_VALIDATION.md` |
| `secure/ai/` | Optional local-LLM analyst (Ollama/OpenAI-compatible), two-role verification, constrained read-only-plus-test verification mode, human-gated change requests. | `docs/AI_ANALYST.md` |

### Interfaces (layer 12)

- `secure/cli/` — one file per domain (mirrors `secure/storage/models/`'s
  own split), all wired into `secure/cli/__init__.py`'s single
  `build_parser()`. `secure/__main__.py` is the entry point
  (`python3 -m secure ...`).
- `secure_gui.py` + `secure_gui/` — a Tkinter control panel calling the
  same underlying functions the CLI does; contains no detection logic
  of its own (see `docs/DESIGN_SYSTEM.md`).

### Performance & Diagnostics (cross-cutting, non-security — Phase 30)

`secure/diagnostics/` sits alongside `secure/validate/` and
`secure/ai/` in the dependency graph — callable only from the
interfaces layer, never imported by any sensor, integration, evidence,
baseline, correlation, or explanation module, in either direction.
Answers "what hardware is this, how loaded is it, how much is Secure
itself using, which modules are expensive" — deliberately NOT a
security-detection layer: nothing here writes to `severity`,
`anomaly_score`, `correlation_alerts`, or anything `secure/explain/`
reads. See `docs/PERFORMANCE.md`.

### Agent Foundation (supervised, human-approved autonomous repair — Phase 31)

`secure/agent/` sits alongside `secure/ai/` and `secure/validate/` in
the dependency graph — callable only from the interfaces layer, never
imported by any sensor/integration/evidence/baseline/correlation/
explanation module. It owns policy, isolation, evidence, verification,
and the CLI/GUI surface for a repair; it deliberately owns no coding-
agent loop of its own — mini-SWE-agent (an external tool, invoked as a
fixed-argv subprocess) owns reading files, deciding what to change, and
producing a patch. Reuses Phase 28's change-request workflow
(`secure/ai/changes/workflow.py`, unmodified) for approval, Phase 27's
verification primitives (pytest + `secure validate`) as the sole
authority on whether a repair technically passed, and Phase 30's
`AppConfig`/Ollama fields for local-model configuration — no new
provider, approval, or verification code was written for this phase.
The loop: `failure -> deterministic policy -> isolated git worktree ->
mini-SWE-agent -> Secure computes the actual diff independently ->
Secure verifies in an isolated HOME -> diff SHA-256 embedded in a
pending change request -> human approval bound to that exact hash,
revalidated against the worktree immediately before approval -> manual
promotion (still not automated in this phase)`. See
`docs/AGENT_FOUNDATION.md`.

### Engineering policy files (repository root — Phase 37)

`AGENTS.md`, `ARCHITECTURE_RULES.md`, `SECURITY_INVARIANTS.md`, and
`TESTING_POLICY.md` sit at the repository root. They are normative for
human and automated authors alike, and `secure/agent/context.py` reads
them into every repair prompt. `ARCHITECTURE_RULES.md` is the normative
subset of this document; where the two ever disagree, that file is a
bug report against this one.

## Data flow (a typical `secure run-all`)

```
run-all
  -> each native sensor scans, persists raw observations + its own
     *_alerts rows
  -> each configured integration's own scan/sync path runs, persists
     integration_alerts + evidence_links to any matching native finding
  -> secure/evidence/ dedup logic runs during the above, preventing the
     same real event (e.g. a process both osquery and a native sensor
     saw) from being double-counted
  -> secure/baseline/ updates feature statistics and raises
     anomaly_events for statistically unusual activity
  -> secure/correlate/ clusters same-timeframe multi-sensor signals into
     correlation_alerts (and, via secure/detect/, chain-scored
     correlation_chain_alerts)
  -> nothing renders yet — all of the above is pure persistence
```

```
secure investigate show <entity>          (on demand, read-only)
  -> secure/investigate/ walks every table above for one entity,
     producing a timeline + related evidence + pivots
  -> secure/explain/ turns any alert row into a human-readable
     Explanation on demand
  -> secure/threatintel/ enriches indicators from cache (or a fresh
     opt-in network lookup) on demand
  -> secure/ai/ (if configured) can answer a free-form or entity-scoped
     question about any of the above, citing exact evidence ids
```

Every step in both diagrams is either "observe and persist" or "read
and explain" — nothing in this flow ever mutates system state.

## Why this layering, not something flatter

The strict lower-never-imports-higher rule is what makes `secure
validate` (layer 10) trustworthy as a release gate: it can exercise
layers 2-9 in complete isolation, with synthetic fixtures, and know the
result reflects only those layers' own logic — not some hidden
dependency on the CLI, the GUI, or the AI layer above them. The same
property is why the AI layer (11) could be added in one phase without
touching detection logic anywhere below it: it only ever *reads* layers
4-10 through their own existing read-only entry points.
