# Secure — Entity-Centric Investigation Engine (Phase 23)

This documents `secure/investigate/` — Phase 23's turn from Secure
being primarily an alert viewer into an entity-centric investigation
tool. Companion reading: `docs/EVIDENCE.md` (Phase 21 — the
`evidence_links` graph this phase walks), `docs/CORRELATION_CHAINS.md`
(Phase 22 — `walk_chain()`, reused unchanged here), `docs/EXPLAINABILITY.md`,
and `PROJECT_NOTES.md`'s Phase 23 change log entry.

**Status: all 6 stages DONE (backend + CLI). No GUI wiring — see "What
this phase does NOT do yet" below.**

## The problem this solves

Every prior phase answers "what alerts exist." None of them answer "I'm
looking at ONE thing — this process, this destination, this file — show
me everything connected to it, in order, so I can decide whether it's a
problem." Phase 23's own instruction, verbatim: *"Turn Secure from
primarily an alert viewer into an entity-centric investigation tool...
Add an investigation timeline and related-evidence view... Do not
duplicate detection logic in the investigation UI."*

## Two addressing schemes, not one

`secure/investigate/entity.py` and `secure/evidence/model.py` (Phase 21,
reused unchanged) give this phase two distinct, deliberately-not-merged
ways to point at something:

- **`EntityRef(entity_type, entity_key)`** — a durable, recurring
  real-world thing worth pivoting on: a process, a destination, a
  persistence mechanism. Reuses `secure/baseline/entities.py`'s
  vocabulary and `*_key()` functions VERBATIM wherever a type overlaps
  (a process investigated here and a process baselined there must
  always agree on what "this process" means — see "historical behavior"
  as a named pivot target). Three types are investigate-only —
  `destination`, `file`, `indicator` — approved explicitly by the user
  as investigation-owned rather than forced into baseline's vocabulary:

  | entity_type | entity_key shape | why not a baseline type |
  |---|---|---|
  | `destination` | `remote_addr:remote_port/proto` | baseline only tracks `(process, destination)` pairs (`process_destination`), never the destination alone — investigation sometimes wants "what has EVER talked to this IP," independent of which process |
  | `file` | the file's own path | baseline aggregates at the watch-path level to avoid entity-count explosion; investigation wants to pivot on ONE exact file |
  | `indicator` | `type:normalized_value` (reuses `secure/threatintel/indicators.py`'s own `normalize_indicator()` directly) | not a behavioral baseline concept at all — a typed threat-intel value |

- **`ObservationRef(source_table, source_id)`** (Phase 21, unchanged) —
  one exact row: a specific alert, a specific YARA/Sigma finding, a
  specific connection event. Findings and evidence are never modeled as
  new entity types with their own identity — they're EVIDENCE ABOUT an
  entity, reached by walking `evidence_links`.

Deliberately NOT modeled as entity types: YARA/Sigma/Suricata/Zeek
findings, anomalies, threat-intel lookup results, correlated findings.
They stay `ObservationRef`s, reached via resolution/pivoting, not a
sixth-plus entity type each.

## Entity resolution (`resolve.py`, Stage 2)

`resolve_entity(conn, EntityRef) -> EntityResolution` answers "is this
on record, and what anchors it" — a presentation-ready `summary` dict
(never a raw row dump) plus every `ObservationRef` that IS this entity
(a process's own `process_entries` row; a wifi SSID's one-or-more
`wifi_networks` rows for distinct BSSIDs). `resolve_observation(conn,
ObservationRef) -> list[EntityRef]` is the reverse: "given this one
exact row someone clicked, which entity/entities does it belong to" —
how an analyst gets FROM a specific finding INTO an investigation.
Scoped to 14 tables with an exact, unambiguous mapping; a table without
one (most `*_alerts` tables — their own identifier fields don't
reliably match another table's key format) returns `[]` rather than
guessing.

**Never parse an `entity_key` string.** Every resolver iterates
candidate rows from an existing `list_*()` function and recomputes+
compares using the SAME canonical key-builder the entity type's key was
built from — never a second, hand-rolled parse of the key string back
into components. This matters concretely: a destination's `remote_addr`
can itself contain colons (IPv6), so splitting `destination_key()`'s
output on `:` would be ambiguous. Recomputing and comparing is always
unambiguous regardless of what the key happens to look like.

A small number of new read-only, filtered storage functions were added
alongside this stage where one didn't already exist —
`list_process_destinations_for_process/_for_remote()`,
`find_remote_endpoint_by_identity()` (`connections.py`), and
`find_file_entries_by_hash()` (`fileintegrity.py`) — never raw SQL
outside `storage/models/`, matching this codebase's one long-standing
rule about where SQL is allowed to live.

## Timeline + related evidence (`timeline.py`, Stage 3)

`build_timeline(conn, entity) -> Timeline` and `related_evidence(conn,
entity) -> RelatedEvidence` both walk outward from EVERY anchor
`resolve_entity()` returns, using `secure/evidence/chain.py`'s
`walk_chain()` **completely unchanged** from Phase 22 — the exact reuse
that module's own docstring named as the reason it lives in
`secure/evidence/` rather than `secure/correlate/`. Results from
multiple anchors are merged and deduplicated by `(source_table,
source_id)`, so evidence reachable from more than one anchor is never
shown twice, and each node's `hops_from_entity` is the SHORTEST
distance from any anchor (an entity's own anchors always sit at hop 0).

- `build_timeline()` — chronological order (oldest first), including
  the entity's own anchors (`is_anchor=True`). Rows with no resolvable
  timestamp (not every table is in `chain.py`'s own
  `_TIMESTAMP_COLUMN_BY_TABLE`) sort last rather than breaking the sort
  or vanishing.
- `related_evidence()` — grouped by hop distance instead, for
  progressive disclosure (closest evidence first). The entity's own
  anchors are deliberately excluded here — `resolve_entity()`'s own
  `anchors` field already answers "what IS this entity"; this answers
  "what else is connected to it."

Neither function computes severity, confidence, or "what does this
mean" — that stays entirely with `secure/explain/dispatch.py`'s
`explain()`, applied on top of these refs by the view layer (see
below). This is the literal mechanism behind "do not duplicate
detection logic": the investigation layer never reimplements scoring,
it only asks existing scoring code about rows it already found.

## Pivot discovery (`pivots.py`, Stage 4)

`discover_pivots(conn, entity) -> list[PivotTarget]` answers "from
here, where can an analyst go next," combining two sources:

1. **Evidence-linked pivots** — every `ObservationRef` reachable from
   the entity (its own anchors, plus everything `related_evidence()`
   reaches) is run back through `resolve_observation()` to recover the
   entity/entities each row belongs to. General-purpose: any
   relationship Phase 21/22 already recorded as an `evidence_links` row
   surfaces here automatically, with zero per-entity-type code.
2. **Native/structural pivots** — a small, explicit table of
   relationships that are always true by construction but are NOT
   `evidence_links` rows, because `evidence_links` exists to record
   CROSS-SOURCE corroboration/derivation, not to restate a fact already
   sitting in one row's own column: `process` <-> `process_destination`
   (via `list_process_destinations_for_process/_for_remote()`),
   `destination` -> `process` (matched by iterating `process_entries`
   and comparing `process_name` — never assuming `process_name` IS the
   executable path), `persistence`/`file` -> `process` (via the row's
   own `program_path` field, but ONLY if a `process_entries` row for
   that path actually exists — never fabricating a pivot to a process
   that isn't on record).

Every `PivotTarget` carries a short human-readable `reason` and, when
grounded in a specific row, the exact `ObservationRef` (`via`) — never
a bare, unexplained list of entity refs. Deduplicated by target entity
(evidence-linked reasons take priority over native ones when both would
suggest the same target).

## The top-level view (`view.py`, Stage 5)

`investigate(conn, entity) -> InvestigationView` is the one call a
frontend needs: `resolve_entity()` + `build_timeline()` +
`related_evidence()` + `discover_pivots()`, composed into one read-only
result. `exists=False` short-circuits every other field to its empty
default.

`explain_observation(conn, ObservationRef) -> Explanation | None` is
the progressive-disclosure hook: given any `ObservationRef` the
timeline or related-evidence view surfaced, get the FULL Phase 13
`Explanation` (severity/confidence/evidence/uncertainty/recommended
action) — but only when the row is actually alert-shaped (one of the
same 9 tables `secure/explain/dispatch.py`'s `_EXPLAINERS` already
registers an explainer for). A plain identity/observation row
(`process_entries`, `connection_events`, ...) has no severity to
explain — asking for one returns `None`, not a fabricated or misleading
`Explanation`, the same "never fabricate what isn't there" discipline
Phase 20's "not found is not safe" and Phase 16's `degraded=True`
already established. Hands the exact same record straight to the exact
same `explain()` the Alerts table uses — an investigation view and the
Alerts table can never disagree about what one alert means.

## Independent of tkinter, by construction

Nothing in `secure/investigate/` imports `tkinter` or `secure_gui`.
Every function takes a plain `sqlite3.Connection` and returns plain
dataclasses — the same "backend model a future frontend can reuse"
shape `secure/evidence/`, `secure/explain/`, and `secure/correlate/`
already use. `secure/cli/investigate.py` is the CLI's own thin
formatting layer on top; a future GUI or API would call `investigate()`
and `explain_observation()` directly, not the CLI module.

## Read-only, by construction

`secure/investigate/` contains zero write functions. Marking something
known/unknown stays exactly where it already lives per-domain (`secure
persistence mark-*`, `secure correlate mark-alert`, ...) — never
duplicated here.

## CLI (Stage 5)

```
secure investigate types            List every entity type and how to
                                     build its entity_key.
secure investigate show <entity_type> <entity_key> [--max-hops N]
                                     Show one entity's summary, timeline,
                                     related evidence (with an inline
                                     Explanation for any alert-shaped
                                     row), and pivot targets.
```

`entity_key` must be built by hand today (no free-text search yet — see
scope note below); `secure investigate types` prints the exact shape
for every entity_type as a reference.

## What this phase does NOT do yet

- **No GUI wiring.** `secure_gui.py` was not touched — investigation is
  CLI-only for now. The user's own approval response addressed entity
  modeling explicitly but not GUI scope; backend + CLI only was applied
  as the reasonable default (matching Phase 22's own "no GUI wiring"
  scope boundary) and should be confirmed or revised on request.
- **No free-text entity search.** An operator must already know (or
  build by hand, per `secure investigate types`) an exact `entity_key`
  — there's no "find the process that looks like X" fuzzy lookup yet.
- **No write/marking actions from within `secure investigate`.**
  Reviewing (marking known/unknown) an alert surfaced during an
  investigation still requires the alert's own existing command (e.g.
  `secure persistence mark-alert <id> known`) — investigation is
  strictly a read/pivot surface.
- **No historical-behavior baseline comparison inline.** Pivoting to
  "historical behavior" today means pivoting to the SAME entity's
  baseline state via `secure baseline show <entity_type> <entity_key>`
  as a separate command — `InvestigationView` doesn't embed baseline
  maturity/anomaly history directly (a natural follow-up, not scoped
  into this phase's 6 stages).
