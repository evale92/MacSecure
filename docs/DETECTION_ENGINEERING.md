# Secure — Detection Engineering Workbench (Phase 25)

This documents `secure/detect/` — Phase 25's coherent lifecycle for
Secure-native and external detection rules. Companion reading:
`docs/INTEGRATIONS.md` (Sigma/YARA-X/Suricata themselves — this phase
never reimplements any of them), `docs/CORRELATION_CHAINS.md` (Secure's
own two correlation engines), `docs/EXPLAINABILITY.md`
(`explain_observation()`, reused verbatim for firing history), and
`PROJECT_NOTES.md`'s Phase 25 change log entry.

**Status: all 7 stages DONE (backend + CLI). No GUI wiring.**

## The problem this solves

By Phase 24, Secure had four independent ways to fire a detection: Sigma
rules, YARA-X rulesets, Suricata signatures, and its own two correlation
engines. Each had its own loader, its own notion of identity (or none at
all), and no shared answer to basic operational questions: what
telemetry does this specific detection need, can this Mac currently
evaluate it, what evidence caused it to fire historically, and has it
ever actually been tested. Phase 25's own governing instruction is
explicit about the shape of the fix: *"Create a coherent lifecycle for
Secure-native and external detection rules... Do not create a universal
rule language. Orchestrate the specialist rule systems cleanly."*

That's the whole design in one sentence: a thin catalog and lifecycle
layer sits ON TOP of the four existing systems, storing identity and
operator state, never rule content or detection logic.

## Two hard rules

Stated in `secure/detect/__init__.py`'s own docstring, and enforced in
code, not just documented:

1. **Never a fifth rule language.** `secure/detect/` never parses,
   compiles, or evaluates detection content itself. Every actual
   evaluation still happens in `secure/integrations/sigma/evaluator.py`,
   `secure/integrations/yarax/_engine.py`, Suricata's own engine (outside
   Secure entirely), or `secure/correlate/analysis.py` /
   `secure/correlate/chains.py` — exactly as before this phase.
2. **Orchestrate, don't reimplement.** Every family-specific fact this
   package surfaces (required telemetry, capability, a synthesized test
   event) is either read directly from that family's own existing code
   (`check_capability()`, `RulesetLoadError`, `parse_alert_record()`) or
   built from the rule's own already-parsed structure (Sigma's
   `detection` block) — never a second, independent interpretation of
   what a rule means.

## Design decisions the user explicitly approved

Two clarifying questions were asked before any code was written; both
were answered by selecting the recommended option:

- **YARA-X is tracked at ruleset-FILE granularity, not per named rule
  inside a file.** This matches the only granularity anything in this
  codebase can already compile, enable, or version at —
  `secure/integrations/yarax/rulesets.py` loads and versions one
  `CompiledRuleset` per `.yar` file; an individual named rule inside it
  only ever surfaces after firing, as a label on a match. Cataloging
  per-named-rule would mean inventing tracking Secure has no actual
  control lever for.
- **Enable/disable is real enforcement for Sigma and YARA-X, and honest
  tracking-only for Suricata and correlate.** Secure controls what it
  loads for the first two; it does not control Suricata's own engine
  (disabling a signature there would mean reaching into Suricata's own
  config, out of scope), and disabling a whole correlation algorithm
  (`temporal_clustering`/`chain_scoring`) was judged too coarse a lever
  to wire into every call site quietly. Rather than pretending uniform
  enforcement, the CLI and the schema record `enabled` for all four
  families but only two scanners ever consult it — and a static
  whole-repo test (`tests/test_detect_enforcement.py`) proves the other
  two never do.

## Schema (Stage 1)

Two new, purely additive tables — see `database.py`'s own schema
comments for the full reasoning:

- **`detection_rules`** — one row per `(family, rule_key)`, UNIQUE
  constraint. Tracks `title`/`source`/`version_label`/`enabled`/
  `required_telemetry`/`capability_status`+`capability_reason`/
  `validation_status`/`last_tested_at`/`false_positive_notes`/
  `first_seen_at`/`updated_at`. Never re-stores rule CONTENT — content
  stays exactly where it already lived (a `.yml`/`.yar` file on disk,
  or nowhere at all for Suricata).
- **`detection_rule_test_runs`** — append-only history, one row per
  fixture outcome per `secure detect test` invocation, linked by
  `rule_id`. Never overwritten — a rule's test history is a real
  timeline, not a single mutable "last result."

`secure/storage/models/detect.py` is the only place either table is
ever read or written. Its central function,
`upsert_detection_rule()`, carries the phase's most important storage
discipline: a routine resync must **never reset operator-owned state**
— `enabled`, `validation_status`, `last_tested_at`, and
`false_positive_notes` are only ever set by their own dedicated
setters (`set_detection_rule_enabled()`, `set_detection_rule_validation()`,
`set_detection_rule_fp_notes()`), never silently overwritten by a
resync that only refreshes discovered facts (title/source/version/
telemetry/capability). Verified directly: `tests/test_storage_detect.py`
and `tests/test_detect_enforcement.py` both assert a disabled rule
stays disabled, and an unvalidated rule stays unvalidated, across
repeated `secure detect sync` calls.

## The four families, honestly non-symmetric

`secure/detect/registry.py`'s `sync_registry(conn, cfg)` discovers and
catalogs all four in one pass. They are deliberately NOT treated the
same way, because they aren't the same kind of thing:

- **Sigma** (`_sync_sigma`) — already has real per-rule identity
  (`rule.rule_id`, a UUID). Loads every rule via the existing
  `load_rules()`, capability-checks each via the existing
  `check_capability()`, and catalogs one row per rule — evaluable or
  not. A malformed rule file is never silently cataloged; its load
  error is folded into `SyncResult.messages` instead.
- **YARA-X** (`_sync_yarax`) — one row per ruleset FILE (see "design
  decisions" above), via the existing `load_rulesets()` +
  `yarax_check_availability()`. A `RulesetLoadError` still gets cataloged,
  with `capability_status="error"` — a compile failure is a fact about
  the ruleset, not a reason to hide it from the operator.
- **Suricata** (`_sync_suricata`) — **passively discovered only after
  firing at least once.** Secure has no way to enumerate a Suricata
  signature it hasn't seen alert — there is no local rule file Secure
  reads. `_sync_suricata` aggregates distinct `(gid, signature_id)`
  pairs out of already-stored `integration_observations` (EVE JSON
  alert fields), newest occurrence winning so `title`/`version_label`
  stay current as a signature's own message text or revision changes.
  Nothing here ever proposes a signature that hasn't actually fired.
- **Secure's own correlation logic** (`_sync_correlate`) — not itemized
  rules at all. Exactly two static, hand-registered entries:
  `temporal_clustering` (`secure/correlate/analysis.py`'s
  `cluster_signals()`/`correlation_score()`) and `chain_scoring`
  (`secure/correlate/chains.py`'s `score_chain()`). Always
  `capability_status="evaluable"` — Secure always owns this code, so
  there's no "is the engine available" question to ask.

`refresh_capability(conn, cfg, record)` backs `secure detect show`'s
live capability display — it never trusts the cached `capability_status`
column, always re-derives it fresh (a Sigma rule file deleted from disk
since the last sync correctly reports `unknown`/"no longer found," not
a stale `evaluable`).

## Validation — honestly different per family (Stage 3)

`secure/detect/validate.py`'s own module docstring states this
explicitly rather than pretending one uniform meaning: **"validated"
answers a different, honestly-scoped question for each family.**

- **Sigma** — real, synthesized fire/no-fire fixtures.
  `_synthesize_sigma_suspicious_event()` builds a "suspicious" telemetry
  event by literally instantiating every selector value referenced
  anywhere in the rule's own `detection` block (works cleanly for
  AND-of-literal-selectors, including string modifiers like
  `endswith`/`contains`, since a value trivially satisfies its own
  modifier against itself); "benign" is an event with none of the
  rule's mapped fields set. Both are run through the SAME
  `evaluate_rule()` the real scanner uses. Documented limitation: a
  `not`-dependent condition may not get a faithful suspicious
  instantiation this way — `evaluate_rule()` itself, not this fixture
  generator, remains the source of truth for any Sigma rule's real
  behavior.
- **YARA-X** — compile-only. "Does this ruleset still compile," never
  "does it correctly detect its intended threat" — Secure cannot
  synthesize file content matching arbitrary YARA string/regex/hex
  patterns without implementing YARA's own grammar, which would be
  exactly the "universal rule language" the governing instruction
  forbids.
- **Suricata** — validates Secure's OWN EVE parser correctness, never
  Suricata's detection quality. Synthesizes an alert-shaped and a
  non-alert-shaped EVE JSON record and confirms `parse_alert_record()`
  recognizes/skips them correctly — Secure has no signature content to
  test against, only its own parsing of Suricata's output.
- **Correlate** — real, meaningful fixtures against the actual
  production scoring functions, since Secure owns this logic
  completely. `temporal_clustering`'s fixtures are plain in-memory
  `Signal` objects run through `cluster_signals()` — no database
  needed; a single-module signal set correctly produces `no_fire`, per
  the exact same cross-module filter `secure/correlate/scanner.py`
  itself applies before ever writing a `correlation_alerts` row.
  `chain_scoring`'s fixtures run against a **throwaway, temp-file
  SQLite database** (`tempfile.TemporaryDirectory()` + the real
  `Database` class for schema init, discarded immediately after) —
  deliberately never the operator's real database, since `score_chain()`
  needs real rows to query and a "validation" run must never write
  synthetic security findings into an operator's actual data. Verified
  by a dedicated test asserting the caller's real `process_entries`
  table stays empty after running the fixture.

`run_validation()` dispatches per family; `validate_and_record()`
persists every `FixtureOutcome` as its own append-only
`detection_rule_test_runs` row (never overwritten) and computes overall
pass/fail as ALL-outcomes-passed, then calls
`set_detection_rule_validation()`. A rule nobody has ever tested reads
`validation_status="unvalidated"` — never silently defaulted to
`"passed"` — and stays that way across any number of resyncs, since
`upsert_detection_rule()` never touches this column.

## Firing history (Stage 4)

`secure/detect/firing_history.py` adds **zero new severity/evidence
logic.** It only locates already-stored alert rows belonging to one
rule's identity, then hands each one to Phase 23's existing
`explain_observation()` — the exact same call `secure investigate` and
the Alerts table already use. "What evidence caused it to fire" is
never a second, independent explanation.

Identity-key matching is family-specific, because each family's alerts
store identity differently:

- Sigma: `identity_key == rule.rule_id` exactly.
- YARA-X: `identity_key = "{file_hash_or_path}:{ruleset_name}:{namespace}.{rule_name}"`
  — matched against the ruleset_name segment (position 2).
- Suricata: `identity_key = "{flow_id}:{gid}:{signature_id}:{rev}:{timestamp}"`
  — matched against `rule_key = "gid:signature_id"` (segments 2–3).
- Correlate: `temporal_clustering` reads every `correlation_alerts` row;
  `chain_scoring` reads every `correlation_chain_alerts` row — both via
  their own existing `list_*` storage functions, unfiltered, since
  there's exactly one engine per rule_key.

## Enforcement wiring (Stage 5)

Real enforcement for Sigma/YARA-X lives in the scanners themselves, at
the earliest possible point — before capability-check or evaluation,
not after:

```python
# secure/integrations/sigma/scanner.py, right after load_rules()
disabled_rule_ids = {r.rule_key for r in list_detection_rules(conn, family="sigma", enabled=False)}
if disabled_rule_ids:
    rules = [r for r in rules if r.rule_id not in disabled_rule_ids]
```

```python
# secure/integrations/yarax/scanner.py, right after load_rulesets()
disabled_ruleset_names = {r.rule_key for r in list_detection_rules(conn, family="yarax", enabled=False)}
if disabled_ruleset_names:
    compiled_rulesets = [c for c in compiled_rulesets if c.info.name not in disabled_ruleset_names]
```

Every `detection_rules` row defaults to `enabled=True`, and
`list_detection_rules(..., enabled=False)` returns `[]` entirely until
an operator has both run `secure detect sync` AND explicitly disabled
something — so a deployment that has never touched `secure detect` sees
scan output byte-for-byte identical to before this phase existed.
Verified directly by `tests/test_detect_enforcement.py`
(`test_sigma_scan_unaffected_before_any_sync`,
`test_sigma_scan_unaffected_after_sync_with_nothing_disabled`, and
their YARA-X equivalents), and disabling one rule is confirmed to never
affect an unrelated one in the same rules directory.

## CLI (Stage 5)

```
secure detect sync
                    Discover current rules across all four families and
                    refresh the catalog. Safe to run repeatedly — never
                    resets operator-owned state on an existing row.
secure detect list [--family F] [--enabled-only] [--disabled-only]
                    [--validation-status S] [--limit N]
                    List cataloged detection rules.
secure detect show <rule_id> [--limit N]
                    One rule's full detail: title/source/version,
                    telemetry, LIVE re-checked capability, validation
                    status + last tested date, FP notes, and recent
                    firing history (via Phase 23's own explain layer).
secure detect enable <rule_id>
secure detect disable <rule_id>
                    Real enforcement for sigma/yarax; tracking-only
                    (with an explicit printed note) for suricata/
                    correlate.
secure detect test [<rule_id>] [--family F]
                    Run deterministic benign/suspicious fixtures for one
                    rule, or every rule in a family, or every cataloged
                    rule — through that family's own existing evaluator.
                    Exit code reflects overall pass/fail.
secure detect annotate <rule_id> <notes>
                    Set this rule's free-text false-positive notes.
```

## What this phase does NOT do yet

- **No GUI wiring.** `secure_gui.py` was not touched — matching Phase
  23/24's own "backend + CLI only" scope boundary.
- **No universal rule language.** By design — see "two hard rules"
  above. Nobody can write one rule and have it apply across all four
  families; that was explicitly ruled out by the governing instruction.
- **No Suricata signature enumeration.** A signature that has never
  fired cannot be cataloged, previewed, or enabled/disabled in advance
  — there is no local Suricata rule file Secure has access to. Only
  post-hoc, after-the-fact discovery via EVE JSON.
- **No YARA-X content-matching validation.** "Validated" for YARA-X
  means "compiles," never "correctly detects" — see "validation" above.
- **No automatic sync.** `secure detect sync` is never called from
  `secure run-all` or any scan — it's an explicit, operator-initiated
  catalog refresh, same trigger discipline as `secure threatintel
  lookup` and `secure dfir collect`.
