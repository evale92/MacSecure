# Secure Project MB — Software Engineering Plan

**Status:** planning document only. Nothing in this file changes any
existing behavior, schema, CLI command, or GUI element. It exists to
set direction before Phases 11–27 continue, per explicit instruction:
review now, consolidate later (see §8), not now.

**Companion document:** `PROJECT_NOTES.md` remains the detailed,
phase-by-phase development journal — this file is the zoomed-out view
of *how the codebase is put together* and *how that should evolve*, not
a replacement for it.

---

## 1. Current architecture, as it actually exists today

Secure is a **local, read-only, no-sudo, no-daemon security tool** for
one Mac, with two front ends (`secure` CLI, `secure_gui.py` Tkinter
GUI) sitting on top of one SQLite database. Concretely, as measured
against the codebase right now:

| Metric | Value |
|---|---|
| Domain packages under `secure/` | 12 (`checks`, `inventory`, `connections`, `listening`, `arpwatch`, `wifi`, `bluetooth` + `bluetooth/ble`, `persistence`, `correlate`, `fileintegrity`) |
| Database tables | 30, all defined in one `database.py` schema string |
| Lines in `secure/storage/models.py` (the *only* file allowed to contain SQL) | 2,457 |
| Lines in `secure/cli.py` (every command handler + all argparse wiring) | 2,517 |
| Lines in `secure_gui.py` (every GUI command + all category wiring) | 1,220 |
| Total `secure/` package LOC | ~14,100 |
| Top-level CLI command groups | 16 |
| GUI categories | 16 (currently a 1:1 mirror of the CLI groups) |
| Automated tests | 472, across 15 test files |
| Duplicated `_shell.py` subprocess-boundary files | 9 (one per domain package — deliberate, documented duplication, not an oversight) |
| Independent `uuid.uuid4().hex[:12]` run-id generation sites | 11 |
| Files that independently define severity string literals | 4+ (`cli.py`, `correlate/strength.py`, `correlate/analysis.py`, `fileintegrity/analysis.py`, plus bare `"medium"`/`"high"` strings in several earlier packages) |

**The layering that exists today:**

```
secure_gui.py  ─┐
                 ├──► secure/cli.py  ──► secure/<domain>/scanner.py
secure CLI     ─┘                           │
                                             ├─► secure/<domain>/_shell.py (subprocess boundary)
                                             ├─► secure/<domain>/analysis.py (pure logic, no I/O)
                                             └─► secure/storage/models.py ──► secure/storage/database.py (SQLite)
```

Every domain package follows the same internal shape: a pure-function
layer (parsing, classification, scoring — testable with no Mac and no
database) plus a thin orchestration layer (`scanner.py`) that calls the
pure layer, talks to the one subprocess boundary (`_shell.py`), and
writes through `models.py`. This has been consistent since Phase 2 and
is the single biggest reason the codebase has stayed navigable through
ten phases.

**`secure/correlate/`** is architecturally different from the eleven
domain packages above it: it has no `_shell.py` for scanning (it reads
only the database), and it is the first package whose entire job is to
read *other* packages' tables and produce a new, unified event shape
(`Signal` → clustered → `CorrelationAlertRecord`). It is the closest
thing this codebase currently has to the shared event model described
in §4 of the standing direction — see §3 below.

**`secure/self_update.py`** is the first utility that is neither a
domain sensor nor a piece of correlation — a small, genuinely
cross-cutting concern (marking a time window as "trusted context").

---

## 2. What is already well-structured

Worth stating plainly, since a plan like this can read as all-debt:

- **The pure-function/thin-wrapper split is real and consistently
  applied.** Every `analysis.py` across every package can be unit
  tested with hand-built inputs, no Mac, no database, no subprocess.
  This is *why* 472 tests exist without the suite being slow or flaky.
- **`models.py` as the sole SQL surface has held.** Ten-plus phases in,
  nobody has reached for raw `conn.execute()` outside that one file.
  That discipline is worth explicitly preserving as the codebase grows,
  even as the file itself gets large (see §3).
- **The `known`/`trusted` reviewable-state pattern is already a
  de facto shared vocabulary.** Sixteen places across the schema use
  the same shape (`known INTEGER NOT NULL DEFAULT 0`, or `trusted` in
  Bluetooth's own vocabulary) with the same semantics: something new
  defaults to unreviewed, the user marks it, nothing is ever silently
  auto-trusted. This is an unformalized instance of exactly the kind of
  convention §4's shared event model asks to converge toward.
- **The `run_id`-groups-a-scan convention is already a proto "scan
  run" concept**, independently reinvented eleven times. `secure
  correlate` and `secure fileintegrity` have already taken this one
  step further into a real observability record
  (`file_integrity_scans`, `CorrelationResult`) — see §4.
- **The correlation engine is already what §4 of the standing
  direction calls "the beginning of the shared event architecture."**
  `Signal` (timestamp, module, kind, strength, identifier, label,
  source_table, source_id) is a real, working, partial draft of
  `SecurityEvent`. `strength.py`'s WEAK/MEDIUM/STRONG is a real, working
  partial draft of a shared confidence/severity vocabulary. Neither was
  designed as infrastructure for future phases — they were built to
  solve correlation specifically — but they are the natural place to
  generalize from, not a parallel system to reconcile later.
- **Failure paths are already distinguished from "nothing found," not
  uniformly, but genuinely, in the newer phases.** `persistence.py`
  reports `processes_available: bool` separately from "zero new
  processes." `fileintegrity` distinguishes `unreadable` from "doesn't
  exist" at the `FileMetadata` level, and `SCAN_INCOMPLETE` from "no
  files here" at the watch-path level. `codesign.py` distinguishes
  `UNKNOWN` (codesign didn't run) from `UNSIGNED` (confirmed negative)
  and treats the two very differently on purpose. This is exactly the
  §6 standard ("distinguish nothing found from could not determine")
  already being followed — just not yet through a shared type.
- **Read-only/no-sudo/no-destructive-action is an actual invariant, not
  a slogan.** Every phase's tests and documentation reaffirm it; no
  phase has ever needed walking back.
- **Documentation discipline already exists and has held for ten
  phases.** `PROJECT_NOTES.md` gets a phase-intro bullet, a full
  section, a file-tree update, a CLI reference update, a test-section
  writeup, and a change-log entry *every single phase*, without fail.
  That habit is the reason this plan can be written with real numbers
  instead of guesses.

---

## 3. Emerging technical debt

Classified per the standing direction's CRITICAL/HIGH/MEDIUM/LOW scale.
**Nothing below is CRITICAL** — there is no known security or
correctness defect in the current codebase. That is itself worth
noting: the debt here is entirely about *shape*, not *correctness*.

| Severity | Item | Why it matters |
|---|---|---|
| HIGH | `secure/cli.py` (2,517 lines) and `secure_gui.py` (1,220 lines) are both single-file monoliths that grow by one command-handler block per phase, with no internal module boundary. | Every future phase edit touches the same two giant files; merge/diff noise and navigation cost both compound. This is the most concrete near-term risk to "modular." |
| MEDIUM | Severity/kind vocabulary is duplicated rather than shared. `LOW`/`MEDIUM`/`HIGH` (or bare `"medium"`/`"high"` strings) are independently declared in at least four places, with no single source of truth a new phase is required to import from. | Nothing has drifted *yet*, but nothing currently prevents a future phase from inventing a fifth spelling, or a severity band with different thresholds than everyone else's. |
| MEDIUM | `run_id`/scan-observability is not a shared shape. `fileintegrity` and `correlate` now record real per-run metadata (duration, counts, completeness); the other nine domain packages do not, and each generates its own `run_id` independently. | The exact "are all my sensors actually working?" question §8 of the standing direction asks the app to eventually answer cannot be answered uniformly today — `fileintegrity` could report a clean scan, and `arpwatch` could have silently found nothing because `arp` isn't on PATH, and the GUI would show both the same way. |
| MEDIUM | The correlation engine has implicit, unenforced coupling to every other package. `secure/correlate/signals.py` names ~13 tables directly; nothing fails loudly if a future phase forgets to add itself there. | A new phase can be fully implemented, tested, and shipped while silently never participating in correlation — no test currently catches that omission at the integration level. |
| MEDIUM | `known`/`trusted` state is per-table, not per-identity. An executable trusted via `process_entries.known` has no relationship to the *same* executable appearing in `persistence_entries.known`. | Not a bug today (each table's meaning is locally correct), but it means "trust" doesn't compose across modules — exactly the kind of duplication §4 asks to watch for as the shared event model matures. |
| LOW | `secure/storage/models.py` (2,457 lines) is a single file for all SQL across 30 tables. | The one-file-for-SQL discipline is a deliberate, working choice (§1) — flagged here only because the file's *size* is a legitimate future navigation cost, not because the discipline itself should change. |
| LOW | No schema version is stored anywhere. Schema evolution today is "additive `CREATE TABLE IF NOT EXISTS` plus an explicit `_COLUMN_MIGRATIONS` healing list," which has worked cleanly so far but has no version number a future consolidation can hang compatibility guarantees on. | Not urgent at 30 tables; will matter more once external consumers (docs, exports, a future re-implementation) start assuming a specific shape. |
| LOW | No `docs/` tree, no `README.md`, no semantic version. | Explicitly acceptable per the standing direction (§9, §12) — listed here only for completeness against the debt taxonomy. |
| LOW | The test harness (`/tmp/testharness/run_tests.py`) is a bespoke ~70-line runner, not real `pytest` — no fixtures beyond `tmp_path`/`monkeypatch`, no parametrization, no markers, no coverage tooling, and it always runs the entire `tests/` directory regardless of the path argument passed to it. | Fine at 472 tests; worth a look at the consolidation milestone if test run time or test *selection* becomes a real workflow friction. |

---

## 4. Architectural risks as Phases 11–27 are added

These are not present-tense debt — they are what the items in §3
*become* if seventeen more phases are added the same way the first
eleven were, without the rule changes in §5.

1. **The CLI/GUI monoliths compound linearly.** Each phase so far has
   added roughly 150–250 lines to `cli.py` and 80–150 lines to
   `secure_gui.py`. Unchanged, that trajectory puts `cli.py` near
   6,000–7,000 lines and `secure_gui.py` near 3,000–3,500 lines by
   Phase 27 — well past the point where either file is comfortable to
   review as a whole, and well past the point where the GUI's current
   "one category per phase" shape can still make sense to a real user
   (this is precisely the concern the standing direction raises in §2).
2. **Severity/confidence vocabulary drift compounds silently.** Without
   one shared type, each new phase is a fresh chance to spell severity
   slightly differently, use a different band boundary, or omit a
   `confidence` concept the correlation engine already has for signal
   *strength* but no domain package yet exposes per-finding. The
   symptom would not be a crash — it would be a GUI that looks
   inconsistent phase to phase, which is exactly what §1's "user-
   friendly" and §15's "understandable in the UI" are meant to prevent.
3. **Correlation's implicit coupling becomes a maintenance trap.**
   Every new phase that produces alert-worthy findings needs someone to
   remember to (a) add a `_collect_*` function to `signals.py`, (b)
   classify its strength in `strength.py`, and (c) decide whether any
   of its module pairings belong in `MEANINGFUL_MODULE_PAIRS` — three
   manual steps, in three files, with no test today that fails if a new
   phase's alerts simply never show up in `secure correlate`. At 27
   phases, an omission here is easy to miss and hard to notice, because
   the symptom is *silence*, not an error.
4. **No sensor-health concept means "clean" and "broken" can look
   identical.** `fileintegrity` and `persistence` each invented their
   own answer to "did this scan actually work"; the other domain
   packages mostly don't have one yet. As more phases are added, more
   distinct, incompatible answers to the same question accumulate,
   making the eventual DIAGNOSTICS domain (§6) harder to build
   uniformly rather than easier.
5. **Database growth outpaces any single mental model of it.** 30
   tables today; a plausible additional 4–6 per remaining phase puts
   the schema in the 90–130 table range by Phase 27, with no ERD/
   diagram anywhere. This doesn't block any single phase, but it raises
   the cost of the exact kind of cross-cutting question (§4's shared
   event model, §5's sensor/detection/correlation separation) that
   later phases will increasingly need to ask.
6. **GUI navigation degrades faster than CLI usability does.** A CLI
   with 27 top-level command groups is still fully usable (tab
   completion, `--help`, muscle memory). A GUI with 27 same-shaped
   category boxes, each named after a development phase rather than a
   security domain, stops being something a non-developer would
   recognize as a coherent product well before Phase 27 — this is the
   specific failure mode §2 of the standing direction is naming.

---

## 5. Engineering rules for future phases (starting now, not deferred)

These apply immediately, without touching any existing code:

1. **Keep the pure-function/thin-wrapper split.** It is the single
   highest-leverage pattern in this codebase and should not be
   relaxed for convenience.
2. **Reuse existing severity/strength vocabulary before inventing
   new spellings.** If a new phase needs LOW/MEDIUM/HIGH, import from
   an existing module that already defines it (e.g. mirror
   `fileintegrity/analysis.py`'s constants, or `correlate/strength.py`'s
   WEAK/MEDIUM/STRONG for anything correlation-facing) rather than
   re-declaring string literals. The first time two phases *need* the
   exact same constants, that's the signal to extract a shared module —
   not before, and not by working around the duplication instead.
3. **Every new scanner returns an explicit availability signal.**
   Model new result dataclasses on `PersistenceScanResult.
  processes_available` / `FileIntegrityScanResult.watch_paths_incomplete`
   — a tri-state (ok / degraded / unavailable), never a bare empty list
   standing in for "couldn't check." This is what will let a future
   DIAGNOSTICS view exist without a retrofit.
4. **Every new scanner records its own run identity from day one** —
   run_id, started_at, completed_at/duration, and basic
   examined/skipped/errored counts, following `file_integrity_scans`'
   shape rather than each phase inventing its own subset. Doesn't
   require a shared table yet — just shared *shape*, so a future
   consolidation can unify the storage without re-deriving the concept
   per package.
5. **Wire new alert-producing phases into correlation deliberately, as
   part of that phase's own Definition of Done** — extend
   `signals.py`/`strength.py`, and add a test asserting the new
   module's signals are actually collected (the same way
   `test_correlate.py` already tests every existing dimension). Don't
   let "did this get correlated" become an implicit, easy-to-forget
   step.
6. **Name new CLI/GUI additions for what they do, not for their phase
   number**, and write help text/labels that would still make sense
   filed under their eventual domain in §6 below. No code reorganization
   is required now — just naming discipline, which costs nothing today
   and saves real relabeling work later.
7. **Prefer dataclasses over ad hoc dicts for new structured data**,
   and keep using `from __future__ import annotations` + full type
   hints on new public functions — both already the norm; keep them
   the norm.
8. **No bare `except Exception: pass`.** Every new failure path gets
   classified (not found / permission denied / timed out / malformed
   output / genuinely absent) the way `codesign.py`, `persistence.py`,
   and `fileintegrity/hashing.py` already do.
9. **Destructive capability stays out of scope by default.** Any new
   phase that could plausibly delete, quarantine, restore, chmod, kill,
   or otherwise act on a finding requires an explicit, separate,
   user-approved remediation design — never bundled quietly into a
   detection phase.
10. **New tables read as "family."** `created_at`/`run_id` on
    append-only history tables, `known` (or a documented equivalent)
    on reviewable dedup tables, and a schema comment explaining any
    non-obvious identity/UNIQUE choice — matching the commenting style
    already used for all 30 existing tables.

---

## 6. Proposed eventual GUI/domain organization

The domain structure from the standing direction, mapped against
**today's actual categories** so the gap is concrete rather than
abstract. This mapping is a target for gradual convergence (§9) — no
GUI code changes now.

| Eventual domain | Current category/categories that would move there |
|---|---|
| **OVERVIEW** | *(doesn't exist yet)* — would host "Run Everything," a rollup of the newest correlation alerts, last-scan timestamps, and (once built, see §5.3) sensor health |
| **NETWORK** | Device Inventory, Active Connections, Listening Services, ARP Watch |
| **WIRELESS** | Wi-Fi Security, Bluetooth (incl. Live BLE) |
| **ENDPOINT** | Process & Persistence, Security Posture |
| **FILES** | File Integrity |
| **ALERTS** | Correlation, plus the individual alert lists currently scattered inside each domain category (persistence alerts, arp alerts, wifi alerts, bluetooth alerts, file-integrity alerts) |
| **FORENSICS** | *(doesn't exist yet)* — would host Continuity/Snapshot, and eventually a cross-module timeline/search over every `*_observations`/`*_events` table |
| **PRIVACY** | *(doesn't exist yet — no phase has built this)* |
| **SETTINGS** | *(doesn't exist yet)* — would host watch-path/exclusion management (currently `secure fileintegrity watch-add`/`watch-remove`, CLI-only), trusted-entity management (currently scattered across every domain's own `mark known/unknown`), and future thresholds/config |
| **DIAGNOSTICS** | Event Log, plus (once built, see §5.3–4) sensor availability, scan failures, and database status |

Two things worth being explicit about:

- **Alerts and Settings are the two domains with the least precedent
  today.** Every phase currently manages its own alerts inline and its
  own configuration (mostly hardcoded, e.g. `fileintegrity`'s default
  watch list) rather than through anything centralized. These two
  domains are where the eventual redesign will require actual new
  functionality, not just moving buttons around.
- **Progressive disclosure (Level 1 summary / Level 2 evidence / Level
  3 raw telemetry)** is a per-finding presentation pattern to apply
  once the domain reorganization happens — e.g. a File Integrity
  finding's Level 1 might be "`cli.py` changed unexpectedly," Level 2
  the plain-English reasons list `fileintegrity/analysis.py` already
  generates, and Level 3 the raw hash/uid/mode/dev/ino values already
  stored in `file_change_events.details`. The *data* for all three
  levels already exists in most phases today (see §3's note on
  explanation text already being generated); what's missing is a GUI
  affordance to layer them, not new backend work.

---

## 7. Proposed documentation structure

Per the standing direction, target:

```
docs/
    ARCHITECTURE.md       High-level system diagram + this plan's §1, kept current
    SECURITY_MODEL.md      What Secure protects against, its invariants, its limits
    THREAT_MODEL.md         What's explicitly out of scope and why (ties to every
                             phase's "What's deliberately NOT here yet" in PROJECT_NOTES.md)
    ROADMAP.md               Phases 12-27 at a glance, kept short
    TESTING.md                 The testing philosophy in §7 of the standing direction,
                                 made concrete against this project's actual test suite
    DESIGN_DECISIONS.md         Index into docs/decisions/ (ADRs, see §10 below)
    DEMO_SCENARIOS.md            The controlled demo list from §11 of the standing direction
    screenshots/
    diagrams/
    decisions/                    One file per ADR (see §10)
```

**What changes now, at zero cost and zero risk:** a short `README.md`
at the project root — the "concise public/product explanation" the
standing direction asks for eventually — is worth writing early,
since it costs nothing to keep current and gives the project a front
door that isn't a 2,900-line development journal. `PROJECT_NOTES.md`
keeps doing exactly what it does today: the detailed, phase-by-phase
journal, including the full parts of this plan that are about to
happen. The rest of `docs/` (ADRs, architecture diagrams, demo
scenarios, screenshots) is scoped for the consolidation milestone in
§8, not built piecemeal now — building it before the architecture it
describes has stabilized would mean rewriting it at that milestone
anyway.

---

## 8. Proposed architecture-consolidation milestone

Recommended at **Phase 14–15**, per the standing direction, with a
concrete checklist scoped to this project's actual state rather than
a generic list:

- [ ] Extract one shared severity/confidence module; backport every
      existing domain package's string literals to import from it
      (mechanical, low-risk, high-value — the single biggest win from
      §3/§4's findings)
- [ ] Extract a shared "scan run" dataclass/table shape; backport the
      nine domain packages that don't yet have `fileintegrity`/
      `correlate`-level observability
- [ ] Split `secure/cli.py` into `secure/cli/` with one module per
      domain plus a thin top-level dispatcher (mechanical, preserves
      every existing command exactly)
- [ ] Split `secure_gui.py`'s category-building logic similarly, *and*
      execute the domain reorganization from §6 at the same time
      (these two are coupled — no point splitting files by phase only
      to immediately regroup them by domain)
- [ ] Review the 30-table schema as a whole; produce the first real
      ERD; decide whether a schema version column is worth adding at
      that point
- [ ] Review `MEANINGFUL_MODULE_PAIRS` and the correlation-signal
      dimension list for completeness against every phase shipped by
      then
- [ ] Stand up `docs/` fully (§7), write the ADRs listed in §10,
      write `README.md` if not already done
- [ ] Address every MEDIUM item in this plan's §3 that hasn't already
      been resolved incrementally by then; re-run this plan's
      measurement table (§1) and compare growth against the
      projections in §4
- [ ] Only after all of the above: consider whether a version number
      (§12 of the standing direction) makes sense to start stamping

---

## 9. What should happen gradually vs. what should wait

**Gradual — start now, alongside Phase 11/12, no coordination cost:**

- Writing `README.md`
- Writing ADRs for the six decisions already called out (SQLite;
  human-approved remediation as a standing rule; CoreBluetooth/Bleak
  for Live BLE; weighted correlation instead of flat escalation;
  periodic file integrity before FSEvents; Syncthing-based update/
  distribution) — each is a real decision this project already made
  and can document today without touching code
- Starting a `TECHNICAL_DEBT.md` seeded from §3 of this plan, updated
  as new debt is identified
- Applying the ten rules in §5 to every phase from here forward
- Naming new CLI/GUI additions for their eventual domain, not their
  phase number
- Tracking the metrics table in §1 at each phase boundary (test count,
  table count, LOC) as informal portfolio evidence per §11 of the
  standing direction — cheap to capture now, harder to reconstruct later

**Wait for the Phase 14–15 consolidation milestone:**

- Splitting `cli.py`/`secure_gui.py` into multiple files
- Executing the GUI domain reorganization (§6)
- Extracting/backporting a shared severity module across *existing*
  packages (new phases should still follow rule §5.2 in the meantime —
  it's the *backport* of old code that waits, not the *rule* for new
  code)
- Any schema-wide versioning scheme
- Building out the rest of `docs/` beyond `README.md`
- Any decision about semantic versioning / calling anything "1.0"

---

## 10. Confirmation

This document changes no existing table, no existing CLI command, no
existing GUI element, and no existing security check's behavior. It is
a planning artifact only. Phase 11 (File Integrity Monitoring) remains
implemented exactly as delivered; §5's rules apply starting with
whatever phase comes next.
