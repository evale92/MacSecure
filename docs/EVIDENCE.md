# Secure — Unified Evidence, Lineage and Deduplication (Phase 21)

This documents `secure/evidence/`, the model that lets Secure tell
"one real-world event, observed four times" apart from "four genuinely
independent findings." Companion reading: `docs/INTEGRATIONS.md` (the
osquery/YARA-X/Sigma/Suricata/Zeek sources this model links together),
`docs/EXPLAINABILITY.md`, and `PROJECT_NOTES.md` (phase-by-phase build
log, including this phase's own change log entry and the "Phase 21 —
Cross-Tool Deduplication & Evidence Lineage" roadmap bullet).

**Status: Stages 1–3 of 5 delivered by this phase; Stage 4 delivered by
Phase 22 (`docs/CORRELATION_CHAINS.md`); Stage 5 still deferred.**
"Stage 4" here was originally scoped as "update `secure/correlate/`'s
scoring to actually consume `evidence_links`" — that turned out to be
substantial enough (a new provenance-aware chain-walking and scoring
model, not a small addition to the existing temporal-clustering
scorer) to warrant its own phase and its own approval gate rather than
being folded silently into this one. It shipped as Phase 22, entirely
additive alongside the existing `correlation_alerts` model exactly as
this document's own "what this phase does NOT do yet" section below
originally anticipated. Stage 5 (a historical backfill CLI,
retroactively computing `evidence_links` for pre-Phase-21 rows) remains
deferred, not yet approved.

## The problem this solves

Once several sources watch the same Mac (Secure's own native scanners,
plus osquery, Zeek, and Suricata via `secure/integrations/`), one real
network connection can legitimately appear as a `connection_events`
row, an `integration_observations` row from osquery, a Zeek `conn.log`
entry, and a Suricata alert — four rows, one underlying fact. Without
something to say so explicitly, a naive reader (a human, or a future
correlation/scoring pass) can't tell that apart from four genuinely
independent sources corroborating each other, which is a very
different and much stronger signal.

## Deliberate minimalism: what did NOT get new storage

Most of the vocabulary this phase's own instruction asked to
represent — entity, observation, finding, source, provenance — already
has a home in this codebase. `secure/evidence/model.py`'s own module
docstring is the authoritative mapping; summarized:

| Concept | Where it already lives |
|---|---|
| Entity | `secure/baseline/entities.py`'s `(entity_type, entity_key)` |
| Observation | the existing `*_observations`/`*_events` tables |
| Finding | the existing `*_alerts`, `anomaly_events`, `correlation_alerts` |
| Source | `SourceRef` — names an existing `integration`/`provider` column value |
| Provenance | the existing `source_table`/`source_id` pair pattern |
| Event family | computed on read, the transitive closure over `evidence_links` |

Only **one** genuinely new storage concept was added: the
relationship/lineage link itself, `evidence_links`. This mirrors
`secure/integrations/base.py`'s own founding discipline — "design the
smallest generic boundary needed... do not prematurely build the
entire future unified-evidence architecture" — arriving at that future
point without a bigger rewrite than the problem needs.

## Three relationship values, deliberately not four

`secure/evidence/model.py` defines exactly three `RELATIONSHIP_*`
constants:

- **`duplicate_observation`** — the same collection mechanism (or two
  mechanisms with no independent vantage point) recorded the same fact
  more than once.
- **`same_event_confirmation`** — genuinely different vantage points
  independently observed the same real-world event (osquery vs.
  Secure's own native scan; Zeek's `conn.log` vs. Secure's own
  connection scan).
- **`derived_evidence`** — one record exists only *because of* another
  (Suricata's alert message embeds process context that was derived
  from a matched `connection_events` row — not a duplicate, not an
  independent confirmation).

"Genuinely independent corroboration" — the fourth concept the
instruction explicitly asked to distinguish — deliberately has **no**
stored constant. It's represented structurally, by the *absence* of
any `evidence_links` row connecting two pieces of evidence — the same
"make the invariant structural, not a value to remember" discipline
Phase 20's `ProviderLookupResult` used for "not found is not safe."

`EvidenceLink` carries no severity, confidence, anomaly, or trust
field of its own, per the instruction's explicit "do not collapse
severity, confidence, anomaly or trust into the evidence model" — a
dedicated test inspects `EvidenceLink.__dataclass_fields__.keys()`
directly rather than trusting a comment.

## The `evidence_links` table, and the correction it went through

The table (`secure/storage/database.py`) records one row per
lineage/dedup fact connecting two rows that already exist elsewhere in
this database:

- `from_source_table`/`from_source_id` — the **latest** confirming
  observation's exact row id (its own real primary key, never a
  deduplicated identity-table row).
- `first_source_id` — the **first** confirming observation's row id,
  preserved and never overwritten.
- `to_source_table`/`to_source_id` — the "matched"/"explaining" side.
- `relationship`, `match_basis` (free text — "identity+timing",
  "structural_agreement"), `time_delta_seconds` (timing matches only),
  `detail`, `created_by` (the exact mechanism that wrote this row —
  e.g. `"zeek_dedup"`, `"suricata_correlate"`, `"osquery_crosscheck"`).
- `first_seen`/`last_seen`/`times_seen` — how long this relationship
  has been on file and how many times it's been reconfirmed.
- `from_fingerprint`/`to_fingerprint` — the LOGICAL identity each side
  is deduplicated against (see below).

### The idempotence bug, found before this stage was reported done

The original design keyed idempotence off the exact
`(from_source_table, from_source_id, to_source_table, to_source_id,
relationship)` tuple. That's correct for Zeek and Suricata: their own
log-cursor/timestamp-cursor mechanisms mean a rescan of an
already-classified match produces **zero new observations**, so the
evidence-link write path simply never re-fires — genuinely idempotent,
for free.

osquery has no such cursor. `scan_osquery()` re-runs its queries fresh
every pass and inserts a **brand-new** `integration_observations` row
every time, even when the underlying real-world fact (a port still
listening, a persistence entry still present) hasn't changed at all.
Keying idempotence off that ever-changing row id meant a fresh
`evidence_links` row was recorded on **every single osquery scan** for
one ongoing, unchanged relationship — confirmed empirically by a test
written to assert idempotence, which failed the first time it ran.

Per this phase's own approval condition — "if any stage turns out to
require changing existing behavior rather than adding alongside it,
stop and show me the issue before proceeding" — this was surfaced
rather than silently shipped or silently redesigned.

**The fix:** `evidence_links` now represents one *logical*
relationship, not one scan's confirmation of it.

- `ObservationRef` (`secure/evidence/model.py`) gained an optional
  `logical_key` field. When a caller supplies one, the ref's identity
  for dedup purposes is `(source_table, logical_key)` — independent of
  the specific row id. When omitted, the row's own id remains the
  identity (unchanged for Zeek/Suricata).
- `secure/evidence/fingerprint.py`'s `logical_ref_identity()` computes
  this: `f"{source_table}:{logical_key or source_id}"`. Deliberately a
  plain, readable string rather than a hash — a stored `from_fingerprint`
  is directly inspectable without a lookup table.
- osquery's crosscheck wiring (`secure/integrations/osquery/scanner.py`)
  passes `logical_key=f"osquery:{kind}:{identity_key}"` — built from
  osquery's own stable per-fact identity, not the observation row.
  Zeek and Suricata pass no `logical_key` at all; their behavior is
  completely unchanged by this correction.
- `evidence_links`' unique index is now on `(from_fingerprint,
  to_fingerprint, relationship)`.
- `secure/evidence/record.py`'s `record_link()`: a brand-new logical
  relationship is inserted as before. A **repeat** confirmation of an
  already-known relationship instead **touches** the existing row —
  `last_seen` advances, `times_seen` increments, `from_source_id`
  moves to this confirmation's own row id — while `first_source_id`,
  `first_seen`/`created_at`, and `detail` are preserved exactly as
  first written, the same append-only-history discipline every other
  table in this app follows for its own "first observed" fields.
- A new append-only table, `evidence_link_observations`
  (`evidence_link_id`, `from_source_table`, `from_source_id`,
  `observed_at`), keeps exact per-confirmation provenance regardless
  of how many times the same relationship is reconfirmed — so no
  history is lost even though `evidence_links` itself now represents
  the relationship rather than the scan. `integration_observations`
  itself is never touched by any of this — it keeps logging every
  single scan, exactly as it always has; repeated observations remain
  useful historical evidence.

A database that had already created `evidence_links` under the
pre-correction shape (from this same phase's own earlier dev/test
runs) heals automatically: `_ensure_column()` adds the new columns
nullable, a small backfill step reconstructs `from_fingerprint`/
`to_fingerprint`/`first_source_id`/`first_seen`/`last_seen` for any
pre-existing row from what it already recorded, and the old unique
index is dropped and replaced — all run *after* the column migration,
not inside the same schema script, since the index can't reference a
column that doesn't exist yet on an un-migrated table. This exact
sequencing bug was caught live: a real `secure wifi scan` run against
an already-existing database surfaced `no such column:
from_fingerprint` immediately after the first (unfixed) version of
this change was written, and the fix was verified against both an
old-shape and a fresh database before being considered done.

## Stage 3 wiring: what actually changed per integration

All three are additive — no existing scan output changed, no existing
alert/observation logic was touched, every `record_link()` call is
wrapped in `try/except Exception: pass` (enrichment must never turn a
successful scan into a failed one).

- **Zeek** (`secure/integrations/zeek/scanner.py`): the already-tested
  `classify_conn_dedup()` is read, not refactored. When it finds a
  match against a native `connection_events` row, a
  `same_event_confirmation` link is now also recorded.
- **Suricata** (`secure/integrations/suricata/scanner.py`): the
  already-tested `find_process_correlation()` is read, not refactored.
  When it finds a match, a `derived_evidence` link is now also
  recorded (the alert's process context is *derived from* the matched
  connection, not a duplicate of it).
- **osquery** (`secure/integrations/osquery/crosscheck.py` +
  `scanner.py`): two new pure functions,
  `find_listening_port_matches()`/`find_persistence_matches()`, sit
  alongside the existing, untouched discrepancy-finding functions. A
  native/osquery **match** — which previously produced literally
  nothing (see `crosscheck.py`'s own founding docstring: the structural
  fix for "don't let the same observation count as independent
  corroboration twice" is to never write a discrepancy row for a
  match at all) — now also gets a `same_event_confirmation` link, with
  the logical-key correction described above.

## What this phase does NOT do yet

- **Stage 4 — correlation scoring. DELIVERED, by Phase 22.** At the
  time this phase shipped, `secure/correlate/` did not yet read
  `evidence_links` at all — the links existed and were queryable
  (`list_evidence_links_for()`), but nothing let a genuine independent
  corroboration (no link between two signals) score differently from a
  same-event confirmation (a link exists). Phase 22
  (`docs/CORRELATION_CHAINS.md`) is that consumption: `secure/evidence/
  chain.py` walks the `evidence_links` graph and `secure/correlate/
  chains.py` scores what it finds, with duplicate/confirming
  observations collapsed into one independent fact BEFORE any scoring
  — exactly the anti-inflation guarantee this bullet originally named
  as the risk. Delivered additively, in a separate table
  (`correlation_chain_alerts`) alongside the existing `correlation_alerts`
  model, not a rewrite of it.
- **Stage 5 — historical backfill.** No CLI exists to retroactively
  compute `evidence_links` rows for observations/alerts recorded
  before this phase shipped. Historical rows simply have no lineage
  links; nothing about them is incorrect, just less complete than
  anything recorded going forward.
- **No premature replacement of native sensors.** Nothing about this
  model changes what any scanner collects or how; it only adds
  relationships between rows that already exist.
