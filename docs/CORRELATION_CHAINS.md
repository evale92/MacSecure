# Secure — Provenance-Aware Behavioral Correlation (Phase 22)

This documents `secure/correlate/chains.py`, `secure/evidence/chain.py`,
and `secure/correlate/chain_scanner.py` — Phase 22's upgrade from
correlation that's primarily temporal clustering to correlation that
walks and scores genuine evidence chains. Companion reading:
`docs/EVIDENCE.md` (Phase 21 — the `evidence_links` graph this phase
walks), `docs/EXPLAINABILITY.md`, and `PROJECT_NOTES.md`'s Phase 22
change log entry.

**Status: all 6 stages DONE.**

## The problem this solves

Phase 5's existing `secure/correlate/` model (`analysis.py`,
`signals.py`, `scanner.py`) clusters signals that happened close
together in TIME and scores the cluster. That's genuinely useful, but
temporal proximity is a proxy for relatedness, not relatedness itself
— and Phase 21 gave this codebase something stronger to use: an actual
graph of asserted relationships between specific stored rows
(`evidence_links`, `duplicate_observation`/`same_event_confirmation`/
`derived_evidence`). Phase 22's own instruction, verbatim: *"Temporal
proximity should remain evidence but should no longer be the primary
definition of relatedness."*

The concrete goal: support meaningful multi-step chains like *file
created -> YARA finding -> process execution -> persistence -> unusual
destination -> network IDS finding* — a genuine causal story, not just
"these six things happened within five minutes of each other."

## Add alongside, don't replace

Per explicit approval (asked and answered before any implementation),
this phase is **entirely additive**:

| | Existing (Phase 5) | New (Phase 22) |
|---|---|---|
| Module | `secure/correlate/analysis.py`, `signals.py`, `scanner.py` | `secure/correlate/chains.py`, `chain_scanner.py` |
| Relatedness | temporal window clustering | `evidence_links` graph traversal |
| Storage | `correlation_alerts` | `correlation_chain_alerts` (separate table) |
| CLI | `secure correlate run/list/mark-alert` | `secure correlate chains run/list/mark-alert` |

Nothing in the existing path was touched. Every regression run through
this phase's six stages confirms zero output changes to
`correlation_alerts`.

## The chain-walking read layer (`secure/evidence/chain.py`, Stage 2)

`walk_chain(conn, start_ref, max_hops=6)` breadth-first-walks
`evidence_links` outward from one row, returning every node reached and
every edge traversed (`Chain`, `ChainNode`, `ChainEdge`). Cycle-guarded
via a `visited` dict (a node reached through two different edges is
never duplicated, but both edges are still reported — `hop_count` can
exceed `len(nodes) - 1`). Each node's real-world timestamp is resolved
from a per-table column map, so a chain orders causally rather than
trusting each `evidence_links` row's own from/to direction.

Deliberately placed in `secure/evidence/` — the shared,
integration-neutral package — not `secure/correlate/`. It answers
exactly one question ("what's connected to this row, and in what
order did it happen?"), with no opinion about what that means
security-wise. Phase 23's investigation/pivot model is expected to
reuse this exact traversal.

## Confirmation groups: the anti-inflation mechanism (Stage 3)

This is the concrete technical answer to Phase 22's own instruction:
*"Use Phase 21 lineage/deduplication so duplicated observations cannot
inflate corroboration."*

Before any scoring happens, `build_confirmation_groups()` runs a
union-find over every node in the walked chain, merging two nodes
whenever they're connected by a `duplicate_observation` or
`same_event_confirmation` edge. The result is a list of
`ConfirmationGroup`s — each one is ONE independent fact, no matter how
many raw rows (`raw_node_count`) or how many different modules/sources
confirmed it. `derived_evidence` edges deliberately do **not** merge
groups: they represent a genuine causal step ("this exists because of
that"), not a restatement of the same fact.

Every scoring computation from this point on operates on GROUPS, never
on raw node count:

- **`raw_observation_count`** — every node walked, duplicates included.
  Shown for transparency, never used in scoring.
- **`independent_fact_count`** — `len(groups)`. The number that
  actually matters.
- **`count_meaningful_relationships()`** — a `derived_evidence` edge
  counts only when it connects two DIFFERENT groups whose module sets
  are disjoint. A `derived_evidence` edge between two facts from the
  SAME module (or that got merged into the same group) earns nothing
  — it isn't evidence of independent sources agreeing, so it can't be
  treated as a "meaningful relationship" in the phrase's actual sense.
- **`evidence_concentration()`** — the largest single module's share
  of independent facts (>= 0.6 counts as concentrated, the same
  threshold `secure/explain/correlation_explainer.py` already uses for
  temporal clusters). A fact confirmed by three tools no longer counts
  as three separate observations pushing concentration around — it was
  already collapsed into one group first.

## Scoring: additive, capped, reused — never reinvented

`chain_raw_score()` mirrors `secure/correlate/analysis.py`'s own
`correlation_score()` shape exactly: a weighted sum over groups, plus a
corroboration bonus for module diversity, plus a capped bonus for
meaningful relationships (`4 * min(meaningful_relationship_count, 3)`
— a 10-hop chain isn't treated as 10x as meaningful). Never a
multiplier, matching this codebase's established scoring discipline.

`severity_for_score()`, `CRITICAL`/`HIGH`/`MEDIUM_SEVERITY`/`LOW`/
`INFORMATIONAL`, `is_recent_boot()`/`get_boot_time()`, and
`stable_fingerprint()`/`observation_part()` are all imported directly
from their existing modules — never reimplemented, so a chain alert's
severity vocabulary and boot-time benign-context handling mean exactly
the same thing they already mean for the temporal-clustering model.
`apply_weak_evidence_cap()` mirrors `analysis.py`'s own weak-signal
cap: a chain where every group's strongest member is weight-1 (no real
alert/severity anywhere in it) can never reach HIGH or CRITICAL, no
matter how many hops or modules it spans.

Confidence (`_compute_confidence()`) uses the existing
`explain/vocab.py` vocabulary — `CONFIRMED`/`LIKELY`/`UNCERTAIN`/
`INSUFFICIENT_EVIDENCE` — checked strongest-condition-first so a
weaker branch can never shadow a stronger one:

1. `module_count <= 1` -> `INSUFFICIENT_EVIDENCE` (only one vantage
   point exists at all — there's nothing to have an opinion about yet).
2. `concentration >= 0.6` -> `UNCERTAIN` (most of the apparent
   corroboration comes from one module).
3. `module_count >= 3 and meaningful_relationship_count >= 2` ->
   `CONFIRMED`.
4. `module_count >= 2 and meaningful_relationship_count >= 1` ->
   `LIKELY`.
5. otherwise -> `UNCERTAIN`.

(Checks 3 and 4 must run in that order — every chain qualifying for
`CONFIRMED` also qualifies for `LIKELY`'s weaker condition, so checking
4 first would make `CONFIRMED` unreachable. The same ordering mistake
was caught and fixed for check 1 vs. 2 during Stage 3/5 test-writing —
see PROJECT_NOTES.md's Phase 22 change log entry.)

## Storage and identity

`correlation_chain_alerts` (`secure/storage/database.py`) is a
completely separate table from `correlation_alerts` — same idempotent-
by-fingerprint discipline (`add_correlation_chain_alert()` mirrors
`add_correlation_alert()`'s `INSERT OR IGNORE` + fingerprint-uniqueness
pattern exactly), but its own schema: raw/independent fact counts,
module/source counts, meaningful-relationship count, concentration,
raw/adjusted score, severity, confidence, uncertainty notes,
benign-context notes, a full explanation, and JSON `members`/`edges`
payloads (each member carries its module/source/group_id; each edge
carries its relationship, endpoints, match_basis, and the underlying
`evidence_links.id` — enough to redisplay or re-derive grouping without
a second walk).

`fingerprint_for_chain()` hashes every member node's exact
`(source_table, source_id)` — order-independent, so reviewing the same
chain starting from ANY of its own member nodes produces the identical
fingerprint. `persist_chain_score()` is therefore safe to call
repeatedly over overlapping history: a chain already on record is
never re-inserted.

## Orchestration and CLI (Stage 4)

`secure/correlate/chain_scanner.py`'s `run_chain_correlation()` is the
run_id-per-pass, lookback-windowed batch entry point — the chain
counterpart to `secure/correlate/scanner.py`'s `correlate()`. It finds
every node touched by `evidence_links` activity within the lookback
window (an isolated node with no links at all can never produce more
than a trivial, `INSUFFICIENT_EVIDENCE` one-node chain, so it isn't
worth walking), walks+scores+persists each one, and tracks fingerprints
already scored THIS pass to avoid re-walking the same connected
component from each of its own member nodes — a pure efficiency guard,
since `persist_chain_score()`'s own idempotent write would have caught
the duplicate anyway.

CLI: `secure correlate chains run [--lookback-hours N]`, `secure
correlate chains list`, `secure correlate chains mark-alert <id>
known|unknown`. `secure explain chains <id>` reuses the exact same
`secure/explain/dispatch.py` path every other alert source already
goes through — `secure/explain/chain_explainer.py` reshapes a
`CorrelationChainAlertRecord`'s already-computed fields into the shared
`Explanation` model; it recomputes nothing.

## The worked example (Stage 5)

`tests/test_correlate_chains_worked_examples.py` builds the exact
six-step shape named in Phase 22's own instruction, against real
tables with real columns:

```
file_integrity_alerts (file created)
        |  derived_evidence
        v
integration_alerts[yara-x] (YARA finding)
        |  derived_evidence
        v
process_entries (process execution)
        |  derived_evidence
        v
persistence_alerts (persistence)
        |  derived_evidence
        v
connection_events (unusual destination)
        |  derived_evidence
        v
integration_alerts[suricata] (network IDS finding)
```

Six raw observations, six independent facts (nothing collapses — every
step is a genuinely distinct event), five modules, five meaningful
cross-source relationships (every edge crosses a module boundary) ->
`CONFIRMED` confidence, `HIGH`/`CRITICAL` severity. Reviewing the chain
starting from any of its six member nodes (the first alert an analyst
happens to notice) surfaces the identical full chain.

## Adversarial false-positive tests (Stage 5)

Each of the following tries one specific way to trick the model into
over-crediting evidence, and asserts it fails:

- **Ten redundant confirmations of one fact** (the same connection
  "confirmed" by ten different `integration_observations` rows from
  the same tool) — raw count grows to 11, but `independent_fact_count`
  stays 1, and confidence never reaches `CONFIRMED` off a single
  module's repetition.
- **A same-module `derived_evidence` edge** (two Zeek-sourced facts,
  one nominally "derived from" the other) — the two facts stay
  distinct (correctly not merged), but the edge earns zero credit
  toward `meaningful_relationship_count`, because both sides are the
  same source.
- **A long chain built entirely from weight-1 facts** (six hops, no
  real severity anywhere) — `apply_weak_evidence_cap()` holds it below
  HIGH regardless of hop count or apparent module diversity.
- **A tight rescan burst** (the identical relationship recorded five
  times in a row) — produces a bit-for-bit stable score every single
  time, never a creeping one.
- **A burst of ordinary facts right after boot** — annotated via
  `benign_context_notes` and discounted, the same treatment
  `secure/correlate/context.py` already gives the temporal-clustering
  model.

## What this phase does NOT do yet

- **No GUI wiring.** Chain alerts are CLI/`secure explain`-only for
  now — `secure_gui.py` was not touched. Not scoped into this phase's
  approved 6 stages; a natural candidate for a future GUI-focused
  phase, or for Phase 23's investigation UI to absorb directly.
- **No `run-all` wiring.** `secure run-all` does not automatically run
  `secure correlate chains run` — it must be invoked explicitly. Kept
  separate deliberately, matching this phase's "explicit new command
  family, not folded silently into an existing one" approach; can be
  revisited once chain correlation has run in practice for a while.
- **No historical backfill specific to chains** beyond whatever
  `evidence_links` rows Phase 21's own Stage 5 backfill (still
  deferred) would eventually produce — a chain can only be walked from
  `evidence_links` rows that already exist.
- **No premature replacement of the temporal-clustering model.**
  `correlation_alerts` stays exactly what it was; `secure correlate
  chains` is a second, parallel signal, not a migration off the first.
