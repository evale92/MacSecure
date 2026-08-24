# Secure — Behavioral Baselining and Anomaly Detection (Product Phase 14)

This documents `secure/baseline/`, the deterministic behavioral
baselining and anomaly-scoring layer introduced in Product Phase 14.
This file is being built incrementally alongside the phase's staged
implementation (see `PROJECT_NOTES.md` for the stage-by-stage build
log); the full reference — CLI, GUI, and correlation integration — is
completed in Stage 8. This section is written early, during Stage 3,
because it documents a limitation that must stay visible from the
moment the relevant code ships, not be backfilled into the docs later
alongside everything else.

## The one rule that matters most

**Nothing in `secure/baseline/` is opaque machine learning.** Every
maturity decision, eligibility rule, and anomaly score component is a
plain, named, deterministic comparison against statistics already
sitting in SQLite — the same "explain what happened and why" standard
the rest of Secure holds itself to (see `docs/EXPLAINABILITY.md`).
Nothing here is trained, fitted, or learned in a way that can't be
reproduced by hand from the stored rows.

## Historical coverage starts at different times

Secure did not gain a unified behavioral history model all at once.
Several modules already had years of raw per-scan history in SQLite
before Phase 14 existed — `arp_observations`, `wifi_observations`,
`listening_events`, `process_entries`, and so on — and Phase 14's
entity-level baselining (Stage 2) reconstructs history for those
entity types directly from that pre-existing data (plus a small
gap-filling table, `baseline_activity`, for the two entity types —
`inventory` and `process` — that had entity rows but no per-scan log
of their own).

Three specific **feature dimensions**, however, had no historical log
to reconstruct from, even though their parent entity type did:

- **`signing_status`** on `persistence` entities — `persistence_entries.signing_status`
  is re-checked on every scan, but only the current value was ever
  stored; nothing recorded what it used to be.
- **`bind_scope`** on `listening` entities — `listening_services` had
  no column at all for "was this bound to localhost or the network"
  history, only the current scan's classification.
- **`security`** on `wifi` entities — `wifi_observations` stores the
  current scan's security type, but nothing summarized how often a
  given network's security type had appeared or changed over time.

For exactly these three feature dimensions, Phase 14 Stage 3 added a
dedicated append-only table, `baseline_feature_activity`, plus a
feature-level maturity table, `baseline_feature_maturity`, that tracks
each one independently of its parent entity's own maturity.

**This history is zero-backfill.** The first row in
`baseline_feature_activity` for any `(entity_type, entity_key,
feature_name)` is the first observation logged *after* this code
shipped. Nothing before that point is fabricated, approximated, or
inferred from the entity's other, older history — even when that
entity already has months of unrelated history and an `ESTABLISHED`
overall maturity state. Concretely, this means:

- A process/persistence entity can show `ESTABLISHED` entity-level
  maturity (`baseline_entities`, e.g. "42 eligible observations across
  21 days") while its `signing_status` **feature** maturity is still
  `LEARNING` or even `NO_BASELINE` ("0 eligible observations") —
  these are two independent maturity records, computed by the same
  pure `compute_maturity()` function but never sharing counters.
- Anomaly scoring respects this: a `signing_status` behavior-change
  transition is never scored above the `LOW` tier while its feature
  baseline is immature, no matter how confident the entity's overall
  history looks (see `secure/baseline/scoring.py`'s
  `apply_maturity_cap()`).
- This gap in coverage is intentional and permanent for data recorded
  before Stage 3 shipped — it will never retroactively fill in, and
  the UI/CLI/explain layers built in later stages are required to
  surface "feature history begins at Phase 14" rather than implying a
  longer track record than actually exists.

## Maturity, eligibility, and scoring — summary

See `secure/baseline/maturity.py`, `secure/baseline/eligibility.py`,
and `secure/baseline/scoring.py` for the authoritative, fully-commented
logic. Briefly:

- **Maturity** (`NO_BASELINE` / `LEARNING` / `ESTABLISHED` / `STALE`)
  requires at least 20 eligible-weighted observations spanning at
  least 14 distinct days over at least a 14-day span before an entity
  or feature is considered `ESTABLISHED`; 30+ days of silence demotes
  it to `STALE`.
- **Eligibility** protects against baseline poisoning: observations
  tied to an excluded entity, a partial/failed sensor read, or an
  unresolved HIGH/CRITICAL alert contribute zero weight toward
  maturity or statistics; an unresolved MEDIUM alert contributes half
  weight. Review is forward-only — marking an alert known/reviewed
  never rewrites the eligibility of observations already recorded
  before that review happened.
- **Anomaly scoring** combines five independent, capped components —
  rarity, recency, behavior-change, security-context, and
  time-of-day-deviation — into a 0–100 score, mapped to a named tier,
  then capped based on maturity state (`LEARNING`/`NO_BASELINE` can
  never exceed `LOW`; `STALE` can never exceed `MEDIUM`).

## Anomaly persistence (`anomaly_events`)

Every scored observation that reaches `evaluate_and_record_feature_observation()`
or `evaluate_and_record_process_destination_observation()` is scored
(the five components above), but only observations that actually reach
a real tier — `low`/`medium`/`high`/`critical`, never `none` — are
written to `anomaly_events`. This is deliberate: a bare `none`-tier
result is not "the absence of a finding," it's the overwhelming common
case (normal behavior), and persisting one row per normal observation
would drown out every real finding in noise. `maybe_record_anomaly_event()`
in `secure/baseline/engine.py` is the single choke point for this rule.

**What's stored per anomaly:** the observed value, an `expected_summary`
(a short, deterministic sentence describing what was normal instead —
not a template placeholder, an actual reconstruction from the stored
statistics), the full five-component `score_breakdown` (as JSON — only
`rarity`/`recency`/`behavior_change`/`security_context`/`time_deviation`,
never the call-site bookkeeping fields like `raw_score` or `tier`,
which have their own columns), the entity's maturity state and eligible
history depth *at the time of this specific observation* (frozen at
write time — later baseline drift, resets, or maturity changes never
rewrite an already-persisted anomaly event), and — when the underlying
scanner can identify one reliably — a `source_table`/`source_id`
reference back to the raw row that produced this observation.

**Idempotence.** `anomaly_events` has a unique index on `(run_id,
entity_type, entity_key, feature_name)`. `add_anomaly_event()` checks
for an existing row with that exact key before inserting, returning the
existing row rather than a duplicate on a repeat call. This guarantee
is scoped precisely to a literal re-invocation with the *same*
`run_id` — a genuinely new scan always mints a new `run_id`, so two
real, calendar-separated anomalies for the same entity/feature are
never silently deduplicated into one. What this actually protects
against is a caller accidentally processing the same observation twice
within one run (a retry, a bug, a batched re-evaluation) — not
legitimate day-over-day recurrence.

**Review state.** Each anomaly event has a `known` flag, same
known/unknown vocabulary as every alert source since Product Phase 1.
`secure anomalies mark <id> known|unknown` flips it and appends a
review-state transition to the existing `events` table under the
`anomaly_review_change` category — the same append-only pattern
Product Phase 13 established for every other alert source
(`alert_review_change`), kept as its own category so anomaly review
history stays distinguishable rather than conflated with pre-Phase-14
alert review history. A no-op re-mark (marking `known` something that's
already `known`) writes nothing new.

## Baseline run lifecycle (`baseline_runs`)

Every scanner that feeds baselining (`inventory`, `connections`,
`listening`, `wifi`, `persistence`) now creates one `BaselineRunCounters`
accumulator per scan invocation, threads it by reference through every
baseline write call it makes, and calls `finalize_baseline_run()`
exactly once, on every exit path, before returning — including
early-return failure paths, so a scanner that couldn't do anything
still produces a row rather than leaving `secure baseline status`
blind to the failure.

A run's `status` is derived, not chosen by the caller:

- **`failed`** — there were errors *and* nothing was actually updated
  (`entities_updated + features_updated == 0`). The scan produced
  nothing usable.
- **`partial`** — there were errors, or at least one input was
  incomplete (a sensor read that came back partial/unavailable), but
  something was still updated. The scan made progress but not clean
  progress.
- **`success`** — neither of the above.

One subtlety worth stating explicitly: an observation becoming
*ineligible* because of an unresolved alert, an excluded entity, or a
per-entity_type cap being reached is **not** an error and does not by
itself demote a run to `partial`. That's the poisoning-protection
mechanism (see `secure/baseline/eligibility.py`) working exactly as
designed, not the baseline subsystem degrading — `secure baseline
status` reports cap and eligibility numbers separately from run
health for this reason.

`secure baseline status` surfaces: total entities and their maturity
breakdown, excluded/frozen counts, per-`entity_type` cap usage (a
silently-truncated entity_type from a reached cap is never actually
silent), anomaly counts by tier plus how many await review, the most
recent run's full detail (including any incomplete-input or
entities-skipped-cap counts and the first few error strings), and how
many of all recorded runs were `partial` or `failed`.

## Exclude / include / freeze / unfreeze / reset

Five operator controls on one entity at a time, all reachable via
`secure baseline <verb> <entity_type> <entity_key>` (see the CLI
reference below). None of them ever touch another entity, and none of
them retroactively rewrite anything already recorded — every one of
these is a forward-only change in behavior from the moment it's
issued.

- **exclude** — the entity stays fully visible in raw logs (activity
  and feature-activity are always still written, at weight 0, with
  `eligibility_reason = "excluded_entity"`), but it stops contributing
  to statistics and stops producing new anomaly scores. Use this for
  an entity you've deliberately decided is noise (e.g. a dev tool that
  legitimately behaves erratically) without deleting its history.
- **include** — undoes `exclude`. Observations logged *while* excluded
  are not retroactively made eligible; only observations from this
  point forward count again.
- **freeze** — raw activity logging and anomaly scoring both continue
  exactly as before (comparisons keep running against the
  already-learned baseline), but the statistics that define "current
  normal" stop advancing. Use this when you want to lock in a
  known-good baseline and be alerted on any future deviation from it,
  without that deviation itself quietly becoming the new normal.
- **unfreeze** — undoes `freeze`. Observations logged *while* frozen
  are not retroactively folded into the statistics; only observations
  from this point forward resume advancing them.
- **reset** — clears one entity's *derived* baseline knowledge
  (`maturity_state` back to `no_baseline`, all counters and
  timestamps back to pristine, `baseline_feature_stats` /
  `baseline_feature_maturity` / `baseline_time_stats` rows deleted)
  while explicitly preserving the *raw* record: `baseline_activity`,
  `baseline_feature_activity`, and every past `anomaly_events` row are
  never touched. A reset does not reprocess that preserved raw history
  back into the newly-cleared derived tables either — baseline
  knowledge only ever builds forward from the moment of each
  observation, including the moment right after a reset, matching the
  zero-backfill principle from the historical-coverage section above.
  `excluded`/`frozen` flags survive a reset unchanged, since they're
  operator input, not derived output.

`secure baseline reset` never resets more than one entity unless you
pass `--all`, and `--all` itself does nothing without also passing
`--yes` — without `--yes` it only prints a preview of what it would
do. `--all` can be scoped to one `entity_type` via `--entity-type`.

## CLI reference (Stage 4)

```
secure baseline status
secure baseline list [--entity-type T] [--maturity M] [--excluded] [--frozen]
secure baseline show <entity_type> <entity_key>
secure baseline exclude <entity_type> <entity_key>
secure baseline include <entity_type> <entity_key>
secure baseline freeze  <entity_type> <entity_key>
secure baseline unfreeze <entity_type> <entity_key>
secure baseline reset <entity_type> <entity_key>
secure baseline reset --all [--entity-type T] --yes

secure anomalies list [--tier T] [--entity-type T] [--known|--unknown] [--since-hours N] [--limit N]
secure anomalies show <id>
secure anomalies mark <id> known|unknown
```

`secure anomalies show <id>` deliberately does not duplicate Product
Phase 13's narrative explanation prose (confidence/evidence/
recommended action) — that integration point is Phase 14 Stage 5
(`secure/explain/`). What it does show: the full score breakdown, the
expected-summary, the source reference when one exists, the maturity/
eligible-history snapshot from the moment of scoring, and a set of
*caveats* comparing that snapshot against the entity's current state
— e.g. "this entity is currently EXCLUDED," "maturity has since
changed to established" — since an old anomaly's context can drift out
of date without the anomaly record itself changing.

Further sections — the full entity-type reference, GUI baseline
management, and the correlation integration — are added in later
stages of Phase 14 and will expand this document rather than replace
it.
