# Secure — Explainable Security UX (Product Phase 13)

This documents `secure/explain/`, the frontend-independent explanation
layer introduced in Product Phase 13, and how it's consumed today (the
GUI's Alerts EvidencePanel, and a small `secure explain` debug
command). Companion reading: `docs/DESIGN_SYSTEM.md` (Phase 12 — the
GUI presentation layer this phase reuses) and `PROJECT_NOTES.md`
(phase-by-phase build log, including this phase's entry).

## Why this exists

Before this phase, an alert's only explanation was whatever English
sentence the detection module happened to write into its `message`
column at alert time. That's honest, but it conflates several
different questions into one paragraph: what was observed, how sure
Secure is about what it means, what would make it benign, and what to
do about it. This phase separates those questions out, without adding
a second place that decides whether something is a finding at all.

## The one rule that matters most

**`secure/explain/` explains decisions that have already been made. It
never makes new ones.**

Concretely:
- `Explanation.severity` is always copied verbatim from the source
  alert/correlation record. Nothing in this package computes or
  overrides it — that authority stays entirely in `secure/arpwatch`,
  `secure/wifi`, `secure/bluetooth`, `secure/persistence`,
  `secure/fileintegrity`, and `secure/correlate`.
- `Explanation.confidence` is a new, separate concept this phase adds
  (see below) — but every rule that produces one is deterministic,
  documented in code, and derived only from fields already present on
  the stored record. Nothing is learned, fitted, or opaque.
- The package does no I/O. `explain(record, source_table) ->
  Explanation` is a pure function. That's what makes the same
  `Explanation` usable from the GUI today, and later the CLI,
  historical forensics exports, an API, or a local AI analyst, without
  any of them re-deriving anything or opening a second path to the
  database.
- Correlation explanations reuse `secure.correlate.analysis`'s actual
  scoring functions (`distinct_modules`, `max_strength`,
  `has_meaningful_combo`, `MEANINGFUL_MODULE_PAIRS`) by adapting
  stored data back into the shape those functions already expect —
  see "Correlation explanations" below. It is the same logic run
  again at read time, not a second implementation of it.

## The Explanation model

`secure/explain/explanation.py`:

```python
@dataclass(frozen=True)
class EvidenceItem:
    text: str
    provenance: str  # direct_observation / derived_fact / secure_interpretation

@dataclass(frozen=True)
class Explanation:
    summary: str
    severity: str                    # passthrough, never recomputed
    confidence: str                  # confirmed / likely / uncertain / insufficient_evidence
    confidence_reason: str
    significance: str
    recommended_action: str          # constrained vocabulary, see below
    recommended_action_text: str
    evidence: Tuple[EvidenceItem, ...]
    correlated_events: Tuple[str, ...]
    uncertainty_status: str          # known / none_material / insufficient_information
    uncertainty: Tuple[str, ...]
    degraded: bool = False
    degraded_reason: Optional[str] = None
```

This maps directly onto the three progressive-disclosure levels the
GUI already uses (see `docs/DESIGN_SYSTEM.md`):

| Level | Fields |
|---|---|
| Summary | `summary`, `severity`, `confidence`, `significance`, `recommended_action(_text)` |
| Evidence | `evidence`, `correlated_events`, `uncertainty_status`, `uncertainty` |
| Technical | not duplicated here — Level 3 shows the original record's own raw fields |

## Confidence — a separate axis from severity

Four levels, defined in `secure/explain/vocab.py`:

- **CONFIRMED** — the observation itself is directly established by
  the sensor. This does **not** mean the underlying cause is
  malicious — only that the reported fact isn't in doubt. Example: a
  file's content hash changing between two scans is CONFIRMED; *why*
  it changed is a completely separate, open question.
- **LIKELY** — multiple, or a particularly strong, stored observation
  supports Secure's interpretation.
- **UNCERTAIN** — the observation is real, but both benign and
  concerning interpretations remain plausible given what's stored.
- **INSUFFICIENT_EVIDENCE** — the stored record doesn't contain
  enough evidence to assess confidence either way.

Severity answers "how bad would this be if the concerning
interpretation is right." Confidence answers "how sure is Secure that
the concerning interpretation is even the right one." A finding can be
high-severity and low-confidence at the same time — e.g. a
correlation cluster whose severity is driven by strong individual
signals, but whose `context_notes` match a known benign pattern (a
`run-all` sweep, a recent boot, a likely software-update window);
severity stays exactly what the scoring model computed, confidence
drops to reflect the added context. Confidence is never averaged,
combined into severity, or displayed as a fabricated percentage — it's
always one of the four labels above, with a plain-English reason.

Per-alert-type confidence rules are documented inline in
`secure/explain/alert_explainers.py` next to each `kind`'s branch —
e.g. persistence's `unusual_unsigned_process` is LIKELY when both of
its two contributing signals (unsigned/ad-hoc code signing, unusual
install location) are present (severity=high), and UNCERTAIN when only
one is. This is explaining what severity already encodes, not
inventing anything new.

## Evidence provenance

Every `EvidenceItem` is tagged with one of three provenance labels
(`secure/explain/vocab.py`):

- **`direct_observation`** — a fact reported directly by a
  sensor/scanner (e.g. "Previous gateway MAC: cc:dd").
- **`derived_fact`** — a deterministic computation over stored/direct
  facts — a count, a comparison — not a subjective judgment (e.g. "657
  raw observations across 2 distinct modules").
- **`secure_interpretation`** — Secure's own hypothesis about what the
  observed facts might mean (e.g. "the raw observation count is
  heavily concentrated in one module and should not be interpreted as
  independent corroboration").

This is what lets a reader tell, at a glance, which parts of an
explanation are fact and which are Secure's own reasoning about that
fact — see the "PRESERVE SECURITY SEMANTICS" requirements in the
original Phase 12/13 direction.

## Uncertainty — honest, not boilerplate

Every `Explanation` carries an explicit `uncertainty_status`
(`known` / `none_material` / `insufficient_information`) alongside the
`uncertainty` list itself, so a finding is never padded with generic
filler text just to make the list non-empty. Today, every specific
per-kind explainer uses `known` (a real, meaningful benign or
concerning alternative exists and is listed); the fallback path (see
"Graceful failure" below) honestly uses
`insufficient_information` instead of guessing. `none_material` exists
in the vocabulary for a future finding kind where genuinely no
material uncertainty applies — it's not forced into use today just to
exercise all three values.

## Recommended action

A small, constrained vocabulary (`secure/explain/vocab.py`) —
`NO_ACTION`, `MONITOR`, `CLASSIFY`, `RESCAN`, `VERIFY_APPLICATION`,
`VERIFY_DEVICE`, `INSPECT_PROCESS`, `INSPECT_FILE`,
`REVIEW_PERSISTENCE`, `REVIEW_NETWORK_DESTINATION`,
`CHECK_MACOS_SETTING`, `INVESTIGATE_NOW` — each with fixed,
human-readable text. Every explainer picks from this vocabulary using
the finding's `kind` (not severity/confidence alone) — e.g. a file
integrity `created` finding recommends `REVIEW_PERSISTENCE` (it's a
new file in a watched startup-relevant location), while a persistence
`signing_changed` finding recommends `INVESTIGATE_NOW` (a code-signing
downgrade at an existing, already-trusted startup entry), even when
both share the same severity. Severity and confidence still influence
urgency within a kind (see correlation's `INVESTIGATE_NOW`-vs-
`CLASSIFY` choice below), but the kind decides which category of
action makes sense at all. **This layer only ever recommends — nothing
in `secure/explain/` executes an action.**

## Correlation explanations

`secure/explain/correlation_explainer.py` reuses
`secure.correlate.analysis`'s real functions directly, via a tiny
adapter (`_MemberSignal`) that reshapes a `CorrelationAlertRecord`'s
stored `members` (plain dicts) into the `.module`/`.strength` shape
those functions already expect. It computes and shows, all from the
same `members` list:

- **Raw observations** — `len(members)`.
- **Distinct behaviors** — the count of distinct `(module, kind)`
  pairs (not just distinct `kind`, since the same `kind` string in two
  different modules is a different real-world behavior).
- **Distinct modules** — via `distinct_modules()`.
- **Meaningful module pairs** — via `has_meaningful_combo()` and
  `MEANINGFUL_MODULE_PAIRS`, both imported unchanged from
  `secure/correlate/analysis.py`.
- **Strongest signal(s)** — via `max_strength()`, listing every member
  at that tier (capped at 5 shown, with a "+N more" note).

### Evidence concentration

In addition to the above, every correlation explanation checks whether
the cluster is dominated by one module: if a single module accounts
for at least 60% of all raw observations (and more than one module is
present at all), the explanation calls this out explicitly, e.g.:

```
Raw observations: 657
Distinct behaviors: 2
Independent modules: 2
Largest contributor: process — 612 signal(s) (93% of all observations)

"The raw observation count is heavily concentrated in one module and
should not be interpreted as that many independent sources of
corroboration."
```

When a cluster is concentrated this way, confidence is `UNCERTAIN`
even if severity is high — the raw count is real (`derived_fact`), but
it doesn't mean what a naive reading of "657 signals!" would suggest.
This is presentation/explanation only; it does not change
`correlation_score()`, `severity_for_score()`, or which pairs are
"meaningful" — those stay defined exactly once, in
`secure/correlate/analysis.py`.

### Pair rationales

`PAIR_RATIONALE` in `correlation_explainer.py` is a short, plain-English
explanation for each of the 11 pairs currently in
`MEANINGFUL_MODULE_PAIRS` — e.g. why `process`+`connections` is
treated as meaningful ("a classic pattern for malware establishing
command-and-control or exfiltrating data"). It documents the *existing*
`MEANINGFUL_MODULE_PAIRS` set; it is not a second rule table and never
changes which pairs are considered meaningful. A pair present in
`MEANINGFUL_MODULE_PAIRS` without a matching `PAIR_RATIONALE` entry
falls back to a clearly-marked generic explanation rather than being
silently omitted or crashing.
`tests/test_explain.py::test_every_meaningful_pair_has_a_documented_rationale`
asserts the two sets match, so they can't silently drift apart as
`MEANINGFUL_MODULE_PAIRS` grows in future phases.

## Graceful failure

An explainer failing to produce a specific explanation must never hide
the original alert. Two distinct, deliberately different situations:

1. **A `kind` this explainer doesn't specifically recognize yet**
   (e.g. a future module version, or a schema this file hasn't been
   updated for) — every per-module explainer falls through to
   `generic_explanation(..., degraded=False)`. This is an expected,
   documented gap: the finding's real severity and message are shown
   as-is, confidence is honestly `INSUFFICIENT_EVIDENCE`.
2. **Explanation generation itself raises** (a bug, or a record shape
   nothing anticipated) — `secure/explain/dispatch.py` wraps every
   explainer call in `try`/`except` and falls back to
   `generic_explanation(..., degraded=True, degraded_reason=...)`.
   `dispatch.explain()` also handles a completely unrecognized
   `source_table` the same way. Either way, the Alerts table stays
   usable — a single explainer bug can never take it down.

`tests/test_explain.py` covers both paths explicitly, plus missing
optional fields and malformed/empty correlation `members`.

## Historical evidence: review-state changes

Marking an alert known/unknown used to be a silent `UPDATE ... SET
known = ?` with no trace of the change. This phase adds an
append-only history entry through the *existing* generic `events`
table (no schema change) — see `secure.cli._record_alert_review_change`,
called from each of the 7 `cmd_*_mark_alert` handlers, right next to
the `find_*_alert_by_id` lookup each one already does. Recorded per
change: source table, alert id, a concise subject (not the full alert
message — deliberately, to avoid piling up duplicated long text every
time the same alert gets re-marked), severity, and an explicit
`UNKNOWN -> KNOWN` / `KNOWN -> UNKNOWN` transition. A no-op re-mark
(marking an already-known alert known again) writes nothing — only
real transitions are recorded. This doesn't change any existing
stdout text or exit code.

## `secure explain <source> <alert-id>`

A narrow, read-only developer/debug CLI command
(`secure/cli.py::cmd_explain`) that prints one alert's full
`Explanation` — summary, severity, confidence (with reason),
significance, evidence (with provenance tags), uncertainty, correlated
events, and recommended action. `<source>` is one of `arpwatch` /
`wifi` / `bluetooth` / `ble` / `persistence` / `fileintegrity` /
`correlate`. It reuses the exact same `find_*_alert_by_id` functions
the mark-alert commands already call and the exact same
`secure.explain.dispatch.explain()` the GUI calls — no new storage
access, no new explanation logic, and no way for the CLI and GUI to
ever disagree about what a given alert's explanation is. It never
mutates anything (confirmed in `tests/test_cli_alert_history.py`).
This phase deliberately does **not** rewrite any existing `list`/
`alerts` command's output — see "What's next" below.

## Where the GUI plugs in

`secure_gui/data_access.py`'s `AlertRow` gained an `explanation:
Explanation` field, computed via `secure.explain.dispatch.explain()`
inside each existing `_from_*` adapter function — the same shape of
change as everything else in that file (it was already calling
`secure.storage.models`'s `list_*` functions the same way). The
previous `explanation: str` field was renamed to `backend_text` (the
original backend-authored message/explanation string, still available
for provenance) to make room for the new, richer field without a name
collision.

`secure_gui/alerts_view.py`'s EvidencePanel (Level 2) renders the
`Explanation`: a severity badge and a confidence badge as two visually
separate widgets (different glyph set, different color palette — see
`secure_gui/tokens.py`'s `CONFIDENCE` table — so a confidence badge
can never be mistaken for a severity badge), the recommended action,
the summary/significance text, and a scrollable evidence/uncertainty/
correlated-events area (a read-only `Text` widget, reusing the same
pattern the console and Level 3 raw record already use — needed
because a correlation finding can legitimately carry hundreds of
correlated events, which doesn't fit a fixed-height `Label`). Level 1
(the table) and Level 3 (raw record) are otherwise unchanged from
Phase 12.

`secure_gui/tokens.py` gained a `CONFIDENCE` table — presentation only
(glyph/label/color), keyed by exactly `secure.explain.vocab`'s
confidence strings. It never redefines what a confidence level means;
that meaning is owned once, in `secure/explain/vocab.py`.

## File map

```
secure/explain/
    __init__.py               Package docstring / the "explain, don't detect" rules.
    vocab.py                  Pure data: CONFIDENCE_*, EVIDENCE_PROVENANCE,
                               UNCERTAINTY_*, recommended-action vocabulary.
    explanation.py             Explanation/EvidenceItem dataclasses,
                               generic_explanation() (shared fallback builder),
                               resolve_action().
    alert_explainers.py        explain_arp_alert / explain_wifi_alert /
                               explain_bluetooth_alert / explain_ble_alert /
                               explain_persistence_alert /
                               explain_file_integrity_alert.
    correlation_explainer.py   explain_correlation_alert, PAIR_RATIONALE,
                               evidence-concentration logic.
    dispatch.py                explain(record, source_table) — the one
                               entry point callers need.
tests/test_explain.py          Full test coverage (pure, no tkinter needed).
tests/test_cli_alert_history.py  History-preservation + `secure explain` tests.
secure/cli.py                   _record_alert_review_change() +
                               7 mark-alert handlers; cmd_explain +
                               `secure explain` subparser.
secure_gui/data_access.py       AlertRow.explanation field.
secure_gui/alerts_view.py       EvidencePanel rendering.
secure_gui/tokens.py            CONFIDENCE presentation table.
```

## What's next (not this phase)

- Rewriting existing per-module `list`/`alerts` CLI output to use
  `secure/explain/` — deliberately out of scope for Phase 13 (GUI-first,
  per the approved plan). `secure explain` exists precisely so this
  can happen incrementally later without new plumbing.
- Capturing more structured evidence at the source for modules that
  currently only keep `kind`/`severity`/`message` (e.g. persistence's
  signing-status before/after, BLE's RSSI before/after, file
  integrity's `rename_confidence`) — several explainers here
  deliberately stop short of `CONFIRMED` in cases like file-integrity
  `renamed` specifically because that supporting detail isn't carried
  on the alert record today, only in a separate history table. Adding
  narrow, nullable columns to capture it would let those explainers
  do better without changing detection logic — noted as a future
  option, not implemented now.
- A local AI analyst or export surface consuming the same
  `Explanation` objects — `secure/explain/` was built with this in
  mind (frontend-independent, pure, serializable) but nothing beyond
  the GUI and the debug CLI command consumes it yet.
