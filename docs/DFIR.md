# Secure — Targeted DFIR Integration (Phase 24)

This documents `secure/dfir/` — Phase 24's integration of Velociraptor
as Secure's specialist forensic collection engine. Companion reading:
`docs/INVESTIGATION.md` (Phase 23 — the entity/timeline model a
collection is wired into), `docs/EVIDENCE.md` (Phase 21 —
`evidence_links`, the graph a collection is linked into), and
`PROJECT_NOTES.md`'s Phase 24 change log entry.

**Status: all 8 stages DONE (backend + CLI). No GUI wiring — see "What
this phase does NOT do yet" below.**

## The problem this solves

Every prior phase either observes what's already on this Mac
(processes, connections, persistence, files) or asks an already-running
tool for its opinion (osquery, YARA-X, Sigma, Suricata, Zeek, threat
intel). None of them can go GET something new and specific — pull a
process's full command-line history, dump a browser's extension list,
collect a targeted forensic artifact about one exact thing an
investigation is already looking at. Phase 24's own governing
instruction, verbatim: *"Integrate Velociraptor, where practical, as
Secure's specialist forensic collection engine. Do not recreate a DFIR
framework. Secure should request or ingest narrowly scoped forensic
evidence based on an investigation."*

The instruction's own pipeline is the literal architecture:

```
finding/investigation -> user-approved collection -> Velociraptor
artifact/result -> normalized forensic evidence -> Secure investigation
```

Each arrow is a real module boundary: `secure/dfir/suggest.py` reads
Phase 23's investigation (`finding/investigation`); `secure dfir
collect` is the `user-approved collection` step; `secure/dfir/
velociraptor/collect.py` runs the `Velociraptor artifact/result`;
`secure/storage/models/dfir.py` persists `normalized forensic
evidence`; and `secure/dfir/collector.py`'s evidence-linking closes the
loop back into `Secure investigation` (Phase 23's `investigate()`).

## Four hard rules

Stated in `secure/dfir/__init__.py`'s own docstring, and enforced in
code, not just documented:

1. **Never auto-triggered.** Nothing in this package runs a collection
   on its own — not from `secure run-all`, not from any scan, not from
   a low-confidence finding. `secure/dfir/suggest.py` may *propose* a
   candidate; only an explicit `secure dfir collect` invocation ever
   executes one.
2. **Reuse `secure/integrations/base.py`'s STATUS_OK/DEGRADED/
   UNAVAILABLE/ERROR vocabulary directly** — never a second health
   vocabulary invented for Velociraptor specifically.
3. **Failure means unavailable, never exculpatory.** A collection that
   couldn't run, or that failed partway, is recorded as UNAVAILABLE/
   ERROR/DEGRADED and must never be read — by this package, by
   `secure/investigate/`, or by an operator glancing at `secure dfir
   evidence` — as "ran cleanly and found nothing."
4. **Every artifact name is checked against `AppConfig.
   dfir_artifact_allowlist` before any subprocess is ever started.** An
   artifact outside the allowlist is refused; no `forensic_collections`
   row is ever written for a refused request — it simply never
   happened.

## Design decisions the user explicitly approved

Two clarifying questions were asked before any code was written; both
were answered by selecting the recommended option:

- **"User-approved collection" is a single-step explicit command, not a
  two-step request/approve ceremony.** One deliberate `secure dfir
  collect --artifact <name> --entity-type ... --entity-key ... --reason
  "..."` invocation, with its exact artifact name, parameters, and
  stated reason, IS the entire approval — the same "one deliberate CLI
  command is the whole trigger" discipline `secure threatintel lookup`
  (Phase 20) and `secure correlate chains run` (Phase 22) already
  established. There is no separate `pending`/`approved` row anywhere
  in the schema.
- **Artifact scope is a configured allowlist**, not free-form. `AppConfig.
  dfir_artifact_allowlist` is a plain `list[str]`, empty by default —
  nothing is collectible until the operator explicitly adds artifact
  names to `config.json`. This is the concrete mechanism behind
  "narrowly scoped... based on an investigation": Secure never lets an
  operator (or, more importantly, never lets some future automated
  caller) collect an artifact nobody deliberately vetted for this
  install.

## Schema (Stage 1)

Two new, purely additive tables — see `database.py`'s own schema
comments for the full reasoning:

- **`forensic_collections`** — one row per `secure dfir collect`
  invocation. Records `requested_at`/`started_at`/`completed_at`
  (all three, not collapsed into one timestamp), `artifact_name`,
  `parameters_json`, `reason`, the `entity_type`/`entity_key` this
  collection is about, the optional `source_table`/`source_id` finding
  that motivated it, `status` (a `secure/integrations/base.py`
  STATUS_* value), `detail`, `tool_version`, and `evidence_item_count`.
  Always an INSERT — a refused (allowlist-rejected) request never
  reaches this table at all; every other outcome (success, timeout,
  nonzero exit, zero rows, partially malformed output) is recorded
  through this exact same row shape.
- **`forensic_evidence_items`** — one row per normalized result row a
  successful-or-degraded collection produced, linked to its
  `forensic_collections` row by `collection_id`. `fields_json` holds
  the collection's own arbitrary Velociraptor result fields, verbatim
  — this table doesn't know or care what any artifact's columns mean.
  A failed/unavailable collection has zero rows here, always — there is
  no code path that fabricates evidence for a collection that didn't
  actually produce any.

`secure/storage/models/dfir.py` is the only place either table is ever
read or written, per this codebase's long-standing "no raw SQL outside
`storage/models/`" rule.

## The Velociraptor boundary (`secure/dfir/velociraptor/`, Stage 2)

- **`_shell.py`** — the only file that runs a subprocess (`run()`,
  `try_get_version()`), same shape as
  `secure/integrations/suricata/_shell.py`. Dependency-injectable —
  every test in `tests/test_dfir_velociraptor.py` monkeypatches this
  module's `run` directly rather than needing a real `velociraptor`
  binary.
- **`availability.py`** — `check_availability(cfg)` runs `velociraptor
  version` and classifies OK (ran successfully, version extracted) /
  UNAVAILABLE (binary not found — routine, most installs won't have
  Velociraptor) / ERROR (binary present but broken). Backs `secure dfir
  status`.
- **`collect.py`** — `run_collection(cfg, artifact_name, parameters)`
  runs exactly one collection and returns a `CollectionOutcome`. Never
  raises — every subprocess failure mode (missing binary, timeout,
  nonzero exit, malformed output) is captured as UNAVAILABLE/ERROR/
  DEGRADED, never an exception that could abort a caller mid-way
  through recording a collection. Zero result rows is explicitly
  DEGRADED, not OK — "collected nothing" must never look identical to
  "ran fine, found something clean."
- **`parser.py`** — `parse_jsonl()` turns Velociraptor's own line-
  oriented JSONL result output into plain row dicts. Tolerant of blank
  lines; *counts*, never silently drops, malformed lines (including
  valid-JSON-but-non-object lines) via `malformed_count`.

**Honesty note on the exact CLI invocation.** `collect.py`'s
`_build_args()` builds `["artifacts", "collect", artifact_name,
"--format", "jsonl", "--args", "key=value", ...]` — Velociraptor's
documented offline/local-collector usage, run against its own bundled
default artifact definitions (no server or separate artifact-pack
config needed for a built-in artifact name). This exact invocation has
**not** been validated against a real Velociraptor install — none was
available in this sandbox — the same limitation Phase 18/19 (Suricata/
Zeek) documented honestly rather than overstating certainty about log
formats they also couldn't test against a live install. It is isolated
behind the one small `_build_args()` function specifically so it can be
corrected later without touching `CollectionOutcome`, the allowlist
check, storage, or any caller.

## Config (Stage 3)

Two new `AppConfig` fields:

- `velociraptor_binary_path: str = ""` — resolved via
  `velociraptor_binary_resolved()`, which falls back to the bare
  `"velociraptor"` (found via `PATH`) when unset.
- `dfir_artifact_allowlist: list[str] = []` — empty by default. See
  "design decisions the user explicitly approved" above.

## The suggestion layer (`secure/dfir/suggest.py`, Stage 4)

`suggest_collections(conn, entity) -> List[CollectionCandidate]` is
read-only and executes nothing. It reuses Phase 23's own
`investigate()`/`explain_observation()` directly — every finding it
considers is exactly the same finding, with exactly the same severity/
confidence, `secure investigate show` would already display for this
entity. No detection logic lives here; this module only decides which
already-computed findings clear a bar.

**The gate — both axes required independently:**
`_MIN_SEVERITIES = ("high", "critical")` AND `_MIN_CONFIDENCES =
(LIKELY, CONFIRMED)`. A CRITICAL-severity finding Secure is only
UNCERTAIN about never qualifies — that's exactly the "low-confidence
finding" the governing instruction says must never auto-trigger
anything. A CONFIRMED but LOW-severity finding doesn't qualify either.
This is the concrete mechanism behind "do not trigger broad forensic
collection automatically from low-confidence findings": nothing here
executes automatically at all (rule 1 above), but even the *proposal*
an operator sees is filtered so a human is never nudged toward
collecting evidence for something Secure itself isn't confident about.

**What this deliberately does NOT do: pick a specific Velociraptor
artifact name.** Secure has no built-in catalog of "the right artifact
for a persistence finding" to draw from — inventing one would mean
either hardcoding artifact names this codebase can't verify are current
(no live install to check against), or silently recommending something
outside the operator's own allowlist. Consistent with "Secure decides
WHEN and WHY to look, the external tool owns WHAT it does" (the same
split `secure/integrations/yarax/targets.py` already established for
scan targets vs. rule content), `suggest_collections()` answers "is
this finding worth considering a collection for" — the operator
supplies *which* allowlisted artifact to actually run, at `secure dfir
collect` time.

## Orchestration (`secure/dfir/collector.py`, Stage 5)

`collect_evidence(conn, cfg, request) -> ForensicCollectionRecord` is
the one function in this entire codebase that can start a Velociraptor
collection. It:

1. Checks `request.artifact_name` against `cfg.dfir_artifact_allowlist`
   — raises `ArtifactNotAllowedError` and writes nothing at all if it
   isn't listed (rule 4).
2. Calls `run_collection()` and persists the outcome as one
   `forensic_collections` row, whatever status resulted (rule 3) —
   success, timeout, nonzero exit, and zero-result-rows are all
   recorded through the identical path.
3. Persists every normalized result row as a `forensic_evidence_items`
   row (zero rows for a failed/unavailable collection).
4. Links the collection into Phase 21's `evidence_links` graph —
   **twice**, both best-effort (wrapped in `try/except Exception: pass`
   — enrichment must never fail the primary action, matching Phase 22
   Stage 1's own discipline for YARA-X/persistence linking):
   - to **every anchor** `resolve_entity(conn, request.entity)` returns
     — guarantees the collection surfaces in `investigate()` for the
     exact entity it was collected about, regardless of whether the
     motivating finding happens to itself be linked to that entity yet;
   - to the **motivating finding** (`source_table`/`source_id`), when
     one was supplied — separate "why" provenance, independently
     traceable.

Only `secure/cli/dfir.py`'s `collect` command ever imports
`collect_evidence` — enforced by a standing regression test
(`tests/test_dfir_adversarial.py`) that statically checks no other file
in `secure/` imports it, and that `secure/cli/root.py` (home of
`cmd_run_all`) has zero awareness of `secure.dfir` at all.

## Wired into Phase 23's investigation engine (Stage 6)

Two `secure/investigate/resolve.py` additions close the loop back to
`Secure investigation`:

- `resolve_observation()` gained handlers for `forensic_collections`
  (reads `entity_type`/`entity_key` straight off the row) and
  `forensic_evidence_items` (one-hop `JOIN` to its owning collection) —
  so an analyst can pivot from a specific collection or evidence item
  back to the entity it's about.
- `secure/evidence/chain.py`'s `_TIMESTAMP_COLUMN_BY_TABLE` gained
  entries for both tables (`created_at`), so a collection sorts
  correctly when `walk_chain()`/`build_timeline()` order it among other
  evidence.

Combined with `collector.py`'s dual evidence-linking above, a
collection run about an entity always appears in that entity's own
`secure investigate show` timeline — confirmed end to end by
`tests/test_dfir_investigate_wiring.py` and, before that, a live manual
smoke test during development (seed a process + a persistence alert,
run a fake collection, confirm `investigate().timeline` includes
`forensic_collections`, `process_entries`, *and* `persistence_alerts`
together).

## CLI (Stage 5)

```
secure dfir status
                    Velociraptor availability/version + the currently
                    configured allowlist.
secure dfir suggest <entity_type> <entity_key>
                    Read-only candidates for this entity (Stage 4's
                    severity/confidence-gated findings) plus the exact
                    `secure dfir collect` invocation shape to consider.
secure dfir collect --artifact <name> --entity-type T --entity-key K
                    --reason "..." [--param KEY=VALUE ...]
                    [--source-table T --source-id N]
                    Run ONE collection. The artifact must already be in
                    AppConfig.dfir_artifact_allowlist — this explicit
                    invocation IS the approval.
secure dfir list [--entity-type T --entity-key K] [--limit N]
                    Every forensic collection ever recorded, optionally
                    filtered to one entity.
secure dfir show <collection_id>
                    One collection's full detail: status, parameters,
                    reason, every timestamp, tool version, motivating
                    finding.
secure dfir evidence <collection_id>
                    Normalized result rows for one collection. On a
                    failed/unavailable collection, explicitly states
                    that absence of evidence here means the collection
                    didn't complete, never "nothing found."
```

## What this phase does NOT do yet

- **No GUI wiring.** `secure_gui.py` was not touched — matching Phase
  23's own "backend + CLI only" scope boundary, applied here as the
  same reasonable default.
- **No artifact catalog or recommendation.** `secure dfir suggest`
  never proposes a specific artifact name — see "the suggestion layer"
  above for why.
- **No verified real-world CLI syntax.** The exact `velociraptor`
  invocation is best-effort, not validated against a live install — see
  the honesty note under "the Velociraptor boundary" above.
- **No automatic re-collection or scheduling.** Every collection is a
  one-time, point-in-time snapshot triggered by one `secure dfir
  collect` call; there is no concept of a recurring or watched
  collection.
- **No collection cancellation or streaming progress.** `run_collection()`
  blocks for up to `DEFAULT_COLLECTION_TIMEOUT_SECONDS` (120s) and
  returns one final outcome — there is no partial-progress reporting
  while a collection is in flight.
