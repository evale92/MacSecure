# Secure — External Telemetry Integrations (Phase 15, extended Phase 16/17/18/19)

This documents `secure/integrations/`, the external security-engine
integration layer introduced in Phase 15, and its five concrete
integrations: osquery (`secure/integrations/osquery/`, Phase 15), YARA-X
(`secure/integrations/yarax/`, Phase 16), Sigma
(`secure/integrations/sigma/`, Phase 17), Suricata
(`secure/integrations/suricata/`, Phase 18), and Zeek
(`secure/integrations/zeek/`, Phase 19).

## Why this exists

Every Secure module before Phase 15 was a native collector: it shelled
out to a specific macOS tool (`lsof`, `arp`, `system_profiler`, ...),
parsed the output itself, and stored what it found. Phase 15 adds the
first *external security engine* — osquery — as an **additional,
cross-checking source**, not a replacement for anything. Secure's own
native collectors are never disabled, blocked, or modified by this
layer. If osquery is missing, broken, or wrong, every existing scan
still works exactly as before.

## The generic boundary (`secure/integrations/base.py`)

Deliberately minimal — three plain dataclasses and a four-value status
vocabulary, no class hierarchy, no plugin registry:

- **`IntegrationIdentity`** — which integration this is (`name`) and
  this integration module's own normalized-shape version
  (`schema_version`). Not the external tool's own version.
- **`IntegrationHealth`** — the result of one attempt to use the
  external tool: `status` is always exactly one of `ok`, `degraded`,
  `unavailable`, or `error`; `detail` is always populated (even for
  `ok`); `tool_version` is the external tool's own runtime-discovered
  version, independent of `schema_version`. There is no fifth "quietly
  fine" state — an integration's failure can never look like a clean
  pass.
- **`ExternalObservation`** — one normalized fact: `kind` (namespaced
  per-integration), `identity_key` (a stable string identifying the
  real-world thing this observation is about — used for cross-checking,
  not a database id), `fields` (the normalized fact itself),
  `source_query` (the exact query that produced it), and its own
  `collected_at`.

A future second integration (say, a YARA-based scanner) reuses these
same dataclasses unchanged.

## osquery (`secure/integrations/osquery/`)

Queried read-only via `osqueryi --json "<SQL>"` — never `osqueryd`,
never any config install or modification. `_shell.py` is the only file
allowed to run a subprocess (mirrors every native package's own
`_shell.py`).

**Availability** (`availability.py`) is determined by actually running
one cheap query (`SELECT version FROM osquery_info`), not by checking
whether the binary is merely on `PATH` — a binary can be present but
still fail to run (wrong architecture, broken install, sandboxing). The
result classifies into exactly one of `IntegrationHealth`'s four
statuses: `unavailable` (not installed/found, or timed out before
responding), `error` (ran but this query failed, or returned something
unparseable), or `ok` (a version string was read back).

**Query subset** (`queries.py`) — the "small, high-value subset" the
phase asked for: `processes`, `process_open_sockets` (TCP/UDP only),
`listening_ports` (TCP/UDP only), and `launchd`. Each is one bare SQL
string, kept in one place so `ExternalObservation.source_query` records
exactly what was asked.

**Normalization** (`parser.py`) turns osquery's raw JSON rows (every
column always a string, osquery's own convention) into
`ExternalObservation`s. `process_open_sockets`/`listening_ports` rows
get a `process_name` filled in via a `pid -> name` map built from the
same pass's `processes` results — osquery's own socket/port tables
don't carry a process name column directly.

## The double-counting problem, and how it's structurally prevented

Phase 15's instruction was explicit: *"Prevent the same underlying
observation from being interpreted as independent corroboration merely
because native Secure and osquery both observed it."*

An earlier, weaker precedent for a similar-looking problem already
existed: `secure/correlate/analysis.py`'s `MEANINGFUL_MODULE_PAIRS`
deliberately excludes `{"file_integrity", "persistence"}`, so a cluster
containing only those two modules reporting the same underlying change
gets no artificial "+4 combination bonus." That's a **scoring-layer**
mitigation — the two signals still exist, and still count toward
`correlation_score()`'s `corroboration_bonus` (2 points per distinct
module beyond the first), so the underlying fact is still counted
twice, just with one smaller bonus removed. That isn't strong enough
for Phase 15's stricter wording.

Instead, Phase 15 fixes the problem one layer earlier, structurally:

1. `secure/integrations/osquery/crosscheck.py` compares this scan's
   osquery observations against Secure's own native identity tables
   (`listening_services` for listening ports, `persistence_entries`
   filtered to launchd-family kinds for persistence) — **at collection
   time**, the same "compare against known state" pattern
   `secure/wifi/scanner.py` already uses for its own before/after
   comparison.
2. A **match** — both sources agree — produces **nothing at all**. No
   row, no signal, no trace beyond the two sources' own already-stored
   observations.
3. Only a genuine **discrepancy** (`osquery_only` — osquery saw
   something native didn't; `native_only` — native saw something
   osquery didn't confirm this pass) becomes an `integration_alerts`
   row.
4. `secure/correlate/signals.py`'s `_collect_integrations()` reads
   **only** `integration_alerts` — never the raw `integration_observations`
   table. Since a match never reaches `integration_alerts` in the first
   place, it is structurally incapable of ever becoming a correlation
   `Signal`, let alone two. A discrepancy, by definition, is not the
   same observation restated by a second source — it's the two sources
   disagreeing, which is itself a new, real fact worth surfacing (and
   is exactly why `{"integrations", "listening"}` and
   `{"integrations", "persistence"}` ARE included in
   `MEANINGFUL_MODULE_PAIRS`, unlike `{"file_integrity", "persistence"}`
   — see that set's own comment in `analysis.py`).

Severity/strength are deliberately asymmetric:

| discrepancy    | alert severity | correlation strength | why |
|----------------|-----------------|----------------------|-----|
| `osquery_only` | `high`          | `STRONG`             | An independent second engine saw something Secure's own native scan missed — exactly what a cross-check exists to catch. |
| `native_only`  | `low`           | `WEAK`                | Already tracked and already alertable through that native collector's own alert path; osquery simply not confirming it this pass is ordinary scan-timing noise. |

v1 scope: only `listening_ports` and `launchd` are cross-checked.
`processes`/`process_open_sockets` observations are still collected and
persisted for their own diagnostic value, but process identity/matching
semantics differ enough from `process_entries`' own dedupe rules
(matched by executable path across all history, not "currently
running") to need real design work of its own — left for a later phase
rather than rushed here.

## Storage

Three new tables (`secure/storage/database.py`), mirroring
`baseline_runs`' own lifecycle-row pattern:

- **`integration_runs`** — one row per collection attempt. `status` is
  always one of `IntegrationHealth`'s four values.
- **`integration_observations`** — one row per `ExternalObservation`,
  append-only, exact `source_query`/`collected_at` provenance. The same
  "exact raw observation, never a deduped identity row" discipline
  Phase 14.5 Stage B established for connections/wifi/listening/
  persistence provenance.
- **`integration_alerts`** — discrepancies only (see above).
  `source_observation_id` references the exact `integration_observations`
  row an `osquery_only` discrepancy came from; `NULL` for `native_only`,
  which has no corresponding osquery observation.

`secure/storage/models/integrations.py` follows the already-split
`secure/storage/models/` package's own one-file-per-domain convention.

## CLI

```
secure integrations osquery status         # availability + last scan summary, no scan run
secure integrations osquery scan            # collect, store, cross-check
secure integrations osquery observations    # raw normalized facts
secure integrations osquery alerts          # discrepancies only
secure integrations osquery mark-alert <id> known|unknown
```

Structured as `integrations -> engine -> subcommand` (not flattened to
`secure osquery ...`) so a second future integration slots in as its
own engine namespace without inventing a new top-level command group.

Deliberately **not** wired into `secure run-all` in this phase —
`run-all` runs every native scan back-to-back specifically to keep
their timestamps close for the default 60-second correlation window;
osquery's own collection latency and its cross-check depending on
native tables already being populated make "just add it to the list"
a decision that deserves its own explicit follow-up, not a silent
side-effect of this phase. `secure integrations osquery scan` is run
independently.

## What was deliberately not built in Phase 15

- No `secure explain integrations <id>` in Phase 15 itself —
  `integration_alerts` wasn't registered with `secure/explain/
  dispatch.py` yet (mirrors the same deliberate choice made for
  `anomaly_events` in Phase 14.5 Stage D). **Superseded in Phase 16** —
  see below; `integration_alerts` now has a real explainer covering
  both osquery and yarax rows.
- No GUI screen.
- No second integration. **Superseded in Phase 16** — yarax is the
  second integration; see below.
- No process/socket cross-checking (see v1 scope, above) — still true.

---

# YARA-X (Phase 16)

Secure's second integration, and its first pure *content-detection*
engine (rather than a state/telemetry cross-check like osquery).
`secure/integrations/yarax/` reuses the exact same generic boundary
from `secure/integrations/base.py` osquery already validated —
`IntegrationIdentity`, `IntegrationHealth`, `ExternalObservation` — and
the same `integration_runs`/`integration_observations`/
`integration_alerts` storage tables, just with `integration="yarax"`.
No new tables were needed; Phase 15's "smallest generic boundary"
turned out to generalize cleanly to a second, quite different kind of
integration on the first try.

## Division of responsibility

File Integrity Monitoring (`secure/fileintegrity/`) answers **"what
changed"** — hashes, metadata, timing, a byte-level diff between two
scans of the same path. YARA-X answers **"what characteristics does
this file match"** — content patterns, evaluated once, with no concept
of a timeline. Neither replaces the other; Phase 16's targeting design
(below) deliberately feeds YARA-X the very files FIM just flagged, so
the two capabilities compound rather than duplicate.

## The library integration (`_engine.py`)

`yara_x` is a Python library, not a subprocess-driven CLI tool like
osquery — so instead of `_shell.py`, this integration has `_engine.py`:
the one file that imports `yara_x`, and it does so **lazily, inside
each function**, never at module load time. This mirrors
`secure/bluetooth/ble/scanner.py`'s own lazy `import bleak` inside
`_discover()` — the established pattern in this codebase for an
optional third-party dependency that shouldn't block importing (or unit
testing) the module that wraps it. Every test in
`tests/test_integrations_yarax.py` patches `_engine.py`'s three seam
functions (`engine_version`, `compile_ruleset`, `scan_bytes`) directly,
the same "patch the wrapper, not the library" discipline
`tests/test_bluetooth_ble.py` already established for bleak.

**Honesty note:** this integration was built in a sandboxed environment
with no network access, so `yara_x` could not actually be installed or
its exact Python API surface verified against a live install — unlike
bleak, whose exact version was "confirmed working via the step-zero
proof-of-concept on the actual target Mac" (see `requirements.txt`).
`_engine.py` and `parser.py` are written against yara_x's documented
public API as best understood, with `parser.py` deliberately duck-typing
every attribute access (`getattr(..., default)`) so a slightly-off
attribute name degrades to a missing field, not a crash. Confirm this
integration against a real `yara_x` install before relying on it in
production, the same way BLE's rollout required its own real-hardware
step-zero check first.

## Availability (`availability.py`)

Classified the same way osquery's is: not just "did the import
succeed," but "did a real compile+scan round-trip work." A trivial,
synthetic smoke rule (`rule _secure_yarax_smoke_test { condition: false
}`) is compiled and scanned against `b""` on every availability check.
`unavailable` — `yara_x` isn't installed. `error` — installed, but the
smoke test itself failed (broken native extension, ABI mismatch, ...).
`ok` — both succeeded, with the library's own version attached when
available.

## Configurable rulesets (`rulesets.py`)

Every `*.yar`/`*.yara` file directly inside `AppConfig.yara_rules_dir`
(default `~/.secure/yara_rules/`, new config field — see
`secure/config.py`) is its own ruleset, named by its file stem. **Secure
ships no default rules** — this is intentionally bring-your-own
detection content; Secure owns the scanning/provenance/severity
machinery, not a maintained signature library. Discovery is
**non-recursive** — a flat directory listing, never a walk — which
matters for the "avoid indiscriminate scanning" instruction applied to
rule *discovery* itself, not just target *selection*.

Rulesets have no real external version number (they're the user's own
local files), so "ruleset/version provenance" here is a SHA-256 content
fingerprint of the exact rule source text (`RulesetInfo.source_hash`,
surfaced as `<name>@<hash[:12]>` — `RulesetInfo.version_label`) rather
than a fabricated version string. Editing a rule file changes its
fingerprint; re-scanning with an unchanged file produces an identical
one. One ruleset failing to compile is recorded as a `RulesetLoadError`
and does not prevent the other rulesets in the directory from loading
and running (same "one bad item, logged and skipped" discipline
`secure/persistence/scanner.py`'s per-entry loops already use).

## Severity — the "not automatically malware" boundary (`analysis.py`)

This is the core discipline Phase 16 asked for by name. A match's
severity comes **only** from that specific rule's own declared
metadata — checked for `severity`/`threat_level`/`threatlevel` keys
(case-insensitive, common word/number variants recognized) — never from
Secure's own judgment about the file, and never a blanket "high."
**A rule with no severity metadata at all defaults to `medium`** — not
`low` (an active pattern match is worth a look), and deliberately not
`high` either (a generic/no-opinion rule must not be auto-escalated
into looking like a confirmed threat). Every match's evidence also
carries an explicit, unconditional caveat
(`match_interpretation_note()`) stating that a match reports file
*characteristics*, not a malware verdict — present regardless of
severity, exactly because the "not a verdict" boundary doesn't get
weaker just because a rule happened to declare `high`.

## Targeting — avoiding indiscriminate scanning (`targets.py`, `scanner.py`)

`scan_paths()` — the only function that actually touches file content —
**never expands a directory**; a directory path in its input list comes
back as a `skip_reason="is_a_directory"` result, not a walk. Three
scan-target sources, matching Phase 16's own priority list exactly:

- **User-requested files** — `secure integrations yarax scan-file
  <path> [<path> ...]` — whatever the user names, nothing more.
- **Security-relevant FIM events** — `targets.fim_alert_targets()` /
  `secure integrations yarax scan-fim-alerts` — files behind
  unreviewed **MEDIUM/HIGH** `file_integrity_alerts` only (LOW is
  excluded — FIM's own severity model already says LOW isn't
  security-relevant), restricted to kinds that still have a file to
  scan (`created`/`modified`/`metadata_only`/`renamed`; `deleted` is
  excluded — nothing left to read).
- **Suspicious files** — `targets.persistence_suspicious_targets()` /
  `secure integrations yarax scan-suspicious` — executables behind
  unreviewed `persistence_alerts` rows already flagged
  `unusual_unsigned_process`.

Every file is also bounded the same way `secure/fileintegrity/hashing.py`
already bounds hashing (`DEFAULT_MAX_HASH_BYTES`, 50 MiB) — an oversized
file is skipped with `skip_reason="too_large"`, never silently read in
full or truncated mid-scan.

## Timeout/error handling

Since `yara_x` scanning runs in-process (a library call, not a
subprocess with an OS-level timeout the way osquery's `subprocess.run`
gets one for free), `_engine.scan_bytes()` calls
`Scanner.set_timeout(seconds)` when the installed `yara_x` build exposes
it (checked via `hasattr` — an older/newer binding without that method
still scans, just without the extra guard). Any exception during one
ruleset's scan of one file — a timeout, a crash, anything — is caught
per-(file, ruleset) pair and recorded in that file's own
`ruleset_errors` list; it degrades that one combination, never aborts
scanning the rest of the file against other rulesets, or the rest of
the files in the batch. A run with any such error, or any ruleset that
failed to *load*, is reported `degraded`, never silently `ok`.

## Provenance

Every match becomes one `integration_observations` row carrying: the
file's own SHA-256 (reusing `secure/fileintegrity/hashing.compute_sha256`
directly, not a second hashing implementation), the matching rule's
name/namespace/tags/metadata, up to 20 matched patterns with up to 5
offset/length pairs each (bounded — never the full match bytes, and
never unbounded on a pattern that matches thousands of times), the
ruleset's name/path/content-hash, `source_query` (a human-readable
`ruleset=<name>@<hash> rule=<namespace>.<rule>` string), and its own
`collected_at`. A **zero-match scan produces zero observations** — no
"nothing found" row — the same "only real events reach the append-only
tables" philosophy `secure/integrations/osquery/parser.py` and
`secure/fileintegrity/scanner.py` both already follow; the fact that a
file *was* scanned is still visible via that pass's `integration_runs`
row.

## Explain integration (`secure/explain/integration_explainer.py`)

`integration_alerts` is now registered with `secure/explain/dispatch.py`
— one explainer, `explain_integration_alert()`, dispatching internally
on `record.integration` since osquery and yarax rows in the shared table
mean genuinely different things. For yarax: `confidence=CONFIRMED` means
only "the pattern match itself is not in doubt" (identical reasoning to
`explain_file_integrity_alert()`'s use of CONFIRMED for "the hash
changed" — never "confirmed malicious"), `recommended_action=
INSPECT_FILE`, and both `significance` and `uncertainty` explicitly
restate the "not a malware verdict" boundary, so it survives all the way
through to whatever surface renders the `Explanation` — not just present
in the raw alert message. Severity is always copied verbatim from the
record, per `secure/explain/__init__.py`'s hard rule 1 — the explainer
never recomputes it. An unrecognized future `integration` value raises
internally, which `dispatch.py`'s existing exception handling turns into
a `degraded=True` `generic_explanation()` — the same graceful-fallback
path every other explainer failure already takes.

## Correlation wiring

`secure/correlate/strength.py` gained
`classify_yarax_finding_strength(severity)` — `high`->STRONG,
`medium`->MEDIUM, `low`->WEAK — deliberately **not** a blanket STRONG
for every match, which would have silently re-introduced "match =
malware" one layer up at the scoring level even after `analysis.py`
avoided asserting it directly. `signals.py`'s `_collect_integrations()`
now dispatches per-row between this and osquery's own
discrepancy-keyed `classify_integration_alert_strength()`, since the two
integrations' `integration_alerts` rows mean different things by
"strong evidence." `{"integrations", "file_integrity"}` was added to
`MEANINGFUL_MODULE_PAIRS` — safe to do because, exactly like the
osquery pairs before it, an `integrations` signal only exists when
something was actually FOUND (never for "scanned, nothing matched"), so
it co-occurring with a `file_integrity` signal is two independent kinds
of evidence agreeing, not one fact restated twice — and Phase 16's own
targeting design (`scan_fim_alerts()`) makes this pairing fire often and
on purpose.

## CLI

```
secure integrations yarax status                 # availability + configured rulesets + last scan
secure integrations yarax scan-file <path> [...]  # user-requested files
secure integrations yarax scan-fim-alerts         # security-relevant FIM events
secure integrations yarax scan-suspicious         # suspicious files (persistence-flagged)
secure integrations yarax rulesets                # list configured/failed rulesets
secure integrations yarax observations            # raw normalized matches
secure integrations yarax alerts                  # findings only
secure integrations yarax mark-alert <id> known|unknown
```

## What's deliberately not built yet (as of Phase 16)

- No GUI screen for either integration.
- No process/socket cross-checking for osquery (v1 scope, unchanged).
- No bundled/default YARA-X rulesets — intentionally bring-your-own.
- No automatic wiring of `scan-fim-alerts`/`scan-suspicious` into
  `secure fileintegrity scan` or `secure persistence scan` themselves —
  each integration's scan commands are run independently (same
  reasoning as osquery not being folded into `run-all`), so a native
  scan's own exit code/behavior is never silently changed by whether an
  external engine happens to be installed.

These remain natural next steps, not oversights — both phases' own
instructions were to build the smallest generic boundary needed for
future engines, not the entire future unified-evidence architecture.

---

# Sigma (Phase 17)

Secure's third integration, and its first **rule-condition** engine
(rather than a state/telemetry cross-check like osquery, or a
content-pattern scanner like YARA-X). `secure/integrations/sigma/`
reuses the exact same generic boundary and storage tables the previous
two integrations already validated — no schema change, just
`integration="sigma"` rows alongside osquery's and yarax's in
`integration_runs`/`integration_observations`/`integration_alerts`.

## Why a bounded subset, not a Sigma implementation

Phase 17's own instruction was explicit: *"Add Sigma-based detection
capability without turning Secure into a second Sigma implementation
... Start with a small subset of Sigma rules genuinely supported by
Secure/osquery telemetry rather than attempting universal
compatibility."* Full Sigma is a large spec — dozens of logsource
categories, hundreds of field names per category (mostly Sysmon/Windows
event-log fields Secure has no telemetry for at all), aggregation and
correlation syntax, and modifier chaining. Building a general Sigma
engine would mean either silently approximating most of that spec (the
opposite of "if required telemetry is unavailable, report NOT
EVALUABLE") or spending most of this phase on parser completeness
instead of the actual instruction. So this integration supports
exactly:

- **Two logsource categories**: `process_creation` (backed by
  osquery's `processes` observations) and `network_connection` (backed
  by osquery's `process_open_sockets` observations).
- **A handful of fields per category** — see the capability adapter
  section below for the exact map and its documented gaps.
- **A boolean condition grammar**: a bare selection name, `and`/`or`/
  `not`, parentheses, and `1 of X`/`all of X`/`1 of them`/`all of them`
  (`X` an exact selection name or a `prefix*` glob). Explicitly **not**
  supported: Sigma's newer aggregation/correlation syntax
  (`| count() by X > N`), near/temporal correlation across rules, or
  multi-logsource backreferences — a rule using any of these was never
  going to be judged EVALUABLE by the field/category checks below
  anyway, since those constructs don't appear as plain field
  selections.
- **Field-value modifiers**: none (plain value, itself allowed to carry
  Sigma's own `*`/`?` wildcards, case-insensitive — Sigma's own
  default), `contains`, `startswith`, `endswith`, `re` (regex), and
  `|all` (AND instead of the default OR across a field's value list).
  **Modifier chaining is not supported** — `Field|contains|all` is
  rejected upstream, not partially interpreted (see below).

Any rule outside this subset is reported `NOT_EVALUABLE`, with a
specific reason — never guessed at, never silently skipped, never
reported clean.

## The capability adapter (`capability.py`) — the phase's central requirement

`check_capability(rule)` is the mechanism that makes *"if required
telemetry is unavailable, report NOT EVALUABLE — never CLEAN"* a
**structural** guarantee, not a convention: it runs before
`evaluator.py` ever queries an observation or evaluates a condition, so
a rule this function rejects never gets the chance to produce a false
"no match." Three checks, any one failing means `NOT_EVALUABLE`:

1. **`logsource.category`** must be one of the two supported
   categories.
2. **`logsource.product`**, if declared, must be macOS-compatible
   (`allowed_products = frozenset({"macos"})`). This check exists
   specifically because many published Sigma rules are Windows/Sysmon-
   only and use generically-named fields (`CommandLine`, `Image`) that
   would otherwise coincidentally overlap Secure's own field map and
   look evaluable purely by naming coincidence. A rule that omits
   `product` entirely isn't penalized for the omission — only an
   explicit, unsupported product fails this check.
3. **Every field referenced anywhere in `detection`'s selections**
   (after stripping one trailing `|modifier` suffix) must be in that
   category's field map.

Field maps, and their documented gaps:

| category             | Sigma field    | Secure/osquery field | notes |
|-----------------------|----------------|------------------------|-------|
| `process_creation`    | `Image`        | `path`                 | |
| `process_creation`    | `CommandLine`  | `cmdline`               | |
| `network_connection`  | `DestinationIp`| `remote_address`       | |
| `network_connection`  | `DestinationPort`| `remote_port`         | |
| `network_connection`  | `Protocol`     | `proto`                 | |
| `network_connection`  | `Image`        | `process_name`          | approximation — osquery's `process_open_sockets` carries only a process **name**, not a full path, unlike the real Sysmon `Image` field this category is modeled on |

Deliberately **not** supported for `process_creation`: `ParentImage`,
`User`, `ParentCommandLine`, `Hashes`, `IntegrityLevel` — Secure's
osquery `processes` observations don't carry parent-process linkage,
user context, or file hashes in v1. A rule referencing any of these is
`NOT_EVALUABLE`, with that exact field name in the reason.

## The condition engine (`condition.py`)

A small tokenizer, recursive-descent parser, and evaluator for exactly
the grammar above — not a general expression language. Field-value
matching is case-insensitive by default (matching Sigma's own default),
supports the modifiers listed above, and treats a selection's value
list as OR by default, AND under `|all`. A selection may be a single
field mapping (all fields must match) or a list of field mappings
(Sigma's own "list of maps means OR" shorthand); a plain scalar
"keywords" list (Sigma's other list form) is explicitly unsupported and
raises rather than being silently ignored.

## Loading rules (`rules.py`)

Every `*.yml`/`*.yaml` file directly inside `AppConfig.sigma_rules_dir`
(default `~/.secure/sigma_rules/`, new config field) is one rule.
**Secure ships no rules** — bring-your-own detection content, the same
stance `yarax/rulesets.py` already takes. Like YARA-X rulesets, a Sigma
rule has no real external version number, so "source/version
provenance" is the exact file path plus a SHA-256 content fingerprint
(`SigmaRule.source_hash`, surfaced as `<rule_id>@<hash[:12]>` —
`SigmaRule.version_label`). One rule file's malformed YAML or missing
required field (`id`, `title`, `logsource`, `detection.condition`) is
recorded as a `RuleLoadError` and does not prevent the other rule files
in the directory from loading — same "one bad item, logged and
skipped" discipline every other loader in this codebase already uses.
YAML parsing (`_yaml.py`) uses `yaml.safe_load`, never `yaml.load` —
Sigma rules are untrusted data, never Python objects to construct.

## Severity — kept separate from Sigma's own opinion (`analysis.py`)

Phase 17's instruction: *"keep rule matches separate from final Secure
severity/confidence decisions."* `classify_sigma_match_severity(level)`
maps Sigma's own five-level vocabulary
(`informational`/`low`/`medium`/`high`/`critical`) onto Secure's three
(`low`/`medium`/`high`) conservatively — `critical`/`high` -> `high`,
`medium` -> `medium`, everything else (including absent or
unrecognized) -> `low`, **never** assumed higher than `low` when a
rule's level is missing or not understood. This is the same
non-blind-trust discipline `yarax/analysis.py`'s
`classify_yara_match_severity()` already applies to YARA rule metadata,
adapted to Sigma's differently-shaped `level` field (which, unlike
YARA metadata, Sigma's own spec DOES define a default for —
`informational`/`low` — so Secure's own default here is `low`, not
yarax's `medium`).

## Evaluation — persisted per rule, every pass (`scanner.py`)

This is a deliberate departure from YARA-X's Phase 16 "zero matches =
zero observations" convention. Phase 17 explicitly requires every
rule's **evaluation status** to be inspectable — not just its matches —
so `scan_sigma()` persists exactly one `sigma_rule_result`
`integration_observations` row **per loaded rule, every scan pass**,
regardless of outcome: `NOT_EVALUABLE` rules get one, `EVALUABLE`
rules with zero matches get one, `EVALUABLE` rules with matches get
one. Each row carries the rule's id/title/level/tags, source path/hash/
version label, required telemetry, evaluation status, capability
reason (if `NOT_EVALUABLE`), and — for evaluated rules — how many
observations were checked, whether the match list was truncated, and
the bounded (`MAX_MATCHED_EVIDENCE = 25`) list of matched evidence
(each entry: the source `integration_observations.id`, identity key,
collected-at timestamp, and a short field summary).

Only rules with a **genuine match** additionally get an
`integration_alerts` row (`kind` = the rule's logsource category;
`discrepancy="match"`, a constant — sigma has no "native comparison
side," same as yarax; `severity` from `classify_sigma_match_severity`;
`source_observation_id`  pointing back at that rule's own
`sigma_rule_result` row, not the raw osquery observation it matched).
Telemetry is queried per observation-kind once per scan pass (not once
per rule) via `list_integration_observations(..., since=cutoff_iso)` —
the `since` parameter added to that function in this phase — over a
configurable lookback window (`--lookback-hours`, default 24).

Because `_collect_integrations()` in `secure/correlate/signals.py`
still reads **only** `integration_alerts`, never
`integration_observations`, a `sigma_rule_result` row — whether
`NOT_EVALUABLE` or evaluated-with-no-match — can never itself become a
correlation signal. Only a genuine match can, preserving the exact same
double-counting-prevention discipline osquery and YARA-X already
established.

## Correlation and explain wiring

`secure/correlate/strength.py` gained
`classify_sigma_finding_strength(severity)` — `high`->STRONG,
`medium`->MEDIUM, `low`->WEAK — the same severity-keyed shape as
yarax's own, and for the same reason: a rule with no declared (or
unrecognized) severity defaults to `low`/non-STRONG, so it can't
dominate a correlation cluster's score the way a real STRONG signal
does. `signals.py`'s `_classify_integration_signal_strength()` now
dispatches sigma rows to this function by `record.integration == "sigma"`.
`{"integrations", "process"}` and `{"integrations", "connections"}`
were added to `MEANINGFUL_MODULE_PAIRS` (with matching rationale
entries in `secure/explain/correlation_explainer.py`) — safe for the
same reason the yarax/osquery pairs before them were: an `integrations`
signal only exists when something was genuinely found, so it
co-occurring with Secure's own native `process`/`connections` activity
is independent corroborating evidence, not one fact restated twice.

`secure/explain/integration_explainer.py` gained `_explain_sigma_alert()`,
dispatched by `record.integration == "sigma"`. `recommended_action` is
`REVIEW_NETWORK_DESTINATION` for `network_connection` matches and
`INSPECT_PROCESS` for `process_creation` matches. `confidence=CONFIRMED`
means only "the rule's condition genuinely matched this telemetry" —
never "this activity is malicious" — and both `significance` and
`uncertainty` restate that boundary explicitly, plus the fact that
Secure only ever evaluates a rule it has genuinely confirmed telemetry
for.

## CLI

```
secure integrations sigma status                 # PyYAML availability + rule capability verdicts + last scan
secure integrations sigma rules                   # list configured rules + EVALUABLE/NOT_EVALUABLE verdict, no scan
secure integrations sigma scan [--lookback-hours N]
secure integrations sigma observations            # per-rule scan results (every rule, every pass)
secure integrations sigma alerts                  # genuine matches only
secure integrations sigma mark-alert <id> known|unknown
```

## What's deliberately not built yet (as of Phase 17)

- No GUI screen (consistent with osquery/yarax).
- No aggregation/correlation Sigma syntax, no logsource categories
  beyond `process_creation`/`network_connection`, no modifier chaining
  — all deliberate v1 scope boundaries, not oversights (see "Why a
  bounded subset" above).
- No bundled/default Sigma rules — intentionally bring-your-own,
  consistent with YARA-X.
- Not wired into `secure run-all` — same reasoning as osquery/yarax;
  run independently via `secure integrations sigma scan`.

These remain natural next steps, not oversights — Phase 17's own
instruction was to start with a small, genuinely-supported subset, not
attempt universal Sigma compatibility.

---

# Suricata (Phase 18)

Secure's fourth integration, and its first that involves NO detection
content of any kind owned by Secure — not even the bring-your-own rule
files osquery/YARA-X/Sigma each read. `secure/integrations/suricata/`
reuses the same generic boundary and storage tables the previous three
integrations validated, `integration="suricata"`, no schema change.

## Where Secure's responsibility ends

Phase 18's instruction is explicit: *"Do not reproduce Suricata
detection logic inside Secure."* Concretely, this integration:

- **Never installs, configures, starts, stops, or otherwise manages a
  Suricata process.** Suricata is set up entirely by the user, outside
  Secure, the same way YARA-X/Sigma rule authoring is bring-your-own.
- **Never touches a network interface, requests packet-capture
  permissions, or attempts promiscuous/monitor-mode capture.** Secure
  only reads a log file Suricata itself already wrote.
- **Owns no rule content.** There is no `rules.py` in this package —
  unlike YARA-X/Sigma, which each load and interpret user-provided rule
  files, Suricata's own engine and its own rule management (e.g.
  `suricata-update`) already fully own what counts as a match. Secure
  consumes the *result* of that decision (one EVE `alert` record per
  match) and normalizes it — it never re-evaluates whether the match
  was correct. There is deliberately no `secure integrations suricata
  rules` command, unlike sigma's `rules`/yarax's `rulesets` — there is
  nothing analogous to list.

## macOS packet-visibility honesty note

Reliable full-LAN promiscuous capture is not something this integration
assumes or requires. Modern macOS makes genuine promiscuous/monitor-mode
capture of a switched network's traffic impractical without a mirror
port, and is often restricted by the OS/Wi-Fi stack regardless. Even
with elevated permissions, a single Mac plugged into a normal switched
network mostly only sees its own traffic anyway. This integration
therefore assumes Suricata is configured to monitor THIS Mac's own
interface traffic — the same host-centric scope every other Secure
module (connections/listening/arpwatch) already has, not a claim of
network-wide IDS coverage. This is a documented scope boundary, not a
missing feature.

Given that scope, "handle unavailable packet visibility honestly"
(Phase 18's own words) becomes concrete and testable: it is not enough
to check that Suricata's log file exists. `availability.py` checks
Suricata's own periodic `stats` EVE events
(`stats.capture.kernel_packets`/`kernel_drops`, falling back to
`stats.decoder.pkts`) and reports `DEGRADED` — never `OK`, never
silently absent — whenever packet visibility cannot currently be
confirmed: no stats event found yet, a stale stats event (the log
hasn't been updated recently), or the specific case named by the phase:
**Suricata's own counters show zero packets captured.** A zero-packet
count is never read as "clean" — the health detail text says so
explicitly ("packet visibility is NOT established... treat any absence
of alerts... as unknown, not confirmed clean"). Only a fresh stats
event with a positive packet count reaches `STATUS_OK`.

Critically, a `DEGRADED` health does **not** suppress ingestion of
alerts that are already genuinely logged — `scan_suricata()` only
short-circuits on `UNAVAILABLE`/`ERROR` (log not configured/found/
unreadable). `DEGRADED` means "don't trust the absence of new alerts
right now," not "hide what's already there."

## EVE JSON ingestion (`_eve.py`, `parser.py`)

Plain stdlib `json` over a bounded tail (`DEFAULT_MAX_LINES = 50,000`)
of Suricata's own EVE log file — read-only, no subprocess. One JSON
object per line is Suricata's own format; a line that isn't valid JSON
is counted and skipped, never aborting the read (same "one bad item,
logged and skipped" discipline every other loader in this codebase
uses). Only `event_type: "alert"` records are normalized into
`ExternalObservation`s; `event_type: "stats"` records are read only for
packet-visibility health (see above) and are never persisted as their
own finding — though the LATEST stats snapshot each scan pass IS
persisted as one `capture_stats` `integration_observations` row (kind
distinct from `eve_alert`), purely for CLI/history visibility into
packet-visibility over time, not as a finding.

Normalized alert fields, matching Phase 18's own list exactly:
timestamp (Suricata's own `timestamp`), signature/rule
(`alert.signature`, `alert.signature_id`/`alert.gid`/`alert.rev` — the
exact rule identity, including revision), category/severity
(`alert.category`, `alert.severity`), source/destination (`src_ip`/
`src_port`/`dest_ip`/`dest_port`), protocol/flow identity (`proto`,
`flow_id`), and exact source provenance (`source_query` records the
literal EVE log path this record was read from). **Suricata
version/ruleset provenance**: since Suricata owns its own rule content
entirely (no `rules.py` here), the most honest per-alert "ruleset"
provenance available is the (`gid`, `signature_id`, `rev`) triple
already in the EVE record — this literally IS Suricata's own stable
rule-revision identity, more precise than trying to fingerprint a local
`.rules` file Secure never reads. Suricata's own binary version
(`tool_version`) is attached separately, via an optional, read-only
`suricata -V` call (`_shell.py`) — never required for log ingestion to
work, since the log may be readable even when the binary itself isn't
on this Mac's PATH.

Deliberately NOT ingested, even when present in a record: full HTTP/
TLS/file metadata, and raw packet/payload bytes if Suricata's own
`payload`/`packet` output options are enabled. Keeping ingestion to
exactly the fields Phase 18 asked for avoids both scope creep and
pulling potentially large or sensitive packet contents into Secure's
own database by accident.

## Severity — direction matters (`analysis.py`)

Verified against Suricata's own source
(`output-json-alert.c`: `jb_set_uint(js, "severity", pa->s->prio)`,
confirmed via a Suricata core developer's own explanation on the
project's forum): EVE `alert.severity` is a direct copy of the rule's
own `classification.config` priority — and **lower numbers mean higher
severity** (1 = highest/most severe, 3 is Suricata's own default for an
unclassified rule). This is the opposite direction from Sigma's `level`
field or common intuition. `classify_suricata_severity()` maps this
correctly: `<=1`->`high`, `2`->`medium`, `>=3`/absent/unparseable->`low`
(Secure's own conservative default, never assumed higher). Getting this
direction backwards would have silently turned Suricata's own
highest-priority alerts into Secure's LOW severity — this is called out
explicitly in the module's own docstring/comments as a correctness-
critical detail, not a stylistic choice.

## Process/connection correlation — identity AND timing, never a guess (`correlate.py`)

Phase 18's instruction: *"Correlate Suricata evidence with Secure's
process/connection context when identity and timing support it, but do
not claim process attribution unless it is actually established."*
`find_process_correlation()` is the one place this decision gets made,
conservative in both dimensions the instruction names:

- **Identity**: an exact match on (`remote_addr`, `remote_port`,
  `proto`) against Secure's own native `connection_events` — tried
  against BOTH the alert's src and dest ip/port, since Suricata's EVE
  record doesn't itself say which side is "this Mac," while
  `connection_events.remote_addr` is always the non-local side
  regardless of traffic direction.
- **Timing**: the connection_events row must fall within a bounded
  window of the alert's own timestamp (default ±300s) — native
  connection scans are periodic, not continuous, so an exact timestamp
  match isn't realistic, but "any connection ever recorded for that
  remote endpoint" would routinely misattribute one process's alert to
  an unrelated process that talked to the same destination at a
  different time.

No match on both constraints returns `None`. Every caller (the
persisted alert message, `secure/explain/integration_explainer.py`) is
required to say so explicitly — `describe_correlation(None)` produces
"process attribution is not established for this alert," embedded
directly in the alert's own message and reflected in the Explanation's
`significance` text — never a silently omitted field.

`list_recent_connection_events()` gained an additive `since` parameter
this phase (same convention as Phase 17's `list_integration_
observations(..., since=...)`), used to bound the lookup to the
correlation window rather than querying arbitrarily far back.

## Evaluation persistence (`scanner.py`)

Every genuine EVE `alert` record becomes both an `integration_
observations` row (`kind="eve_alert"`) AND an `integration_alerts` row
— unlike Sigma's "always persist status, alert only on match" split,
there is no "rule checked, nothing matched" concept here: Suricata's
own engine already did that filtering before writing anything to
eve.json at all, so every alert record IS already a genuine finding
(the same "already filtered upstream" reasoning behind YARA-X's own
"zero matches = zero observations" convention, just applied one step
earlier in the pipeline, before Secure ever sees the data). `kind` in
`integration_alerts` is the constant `"network_alert"`;
`discrepancy="match"` (no native-comparison side, mirroring yarax/
sigma's own reuse of that constant); `source_observation_id` points at
the alert's own `eve_alert` observation row.

Re-scanning the same log tail does not re-ingest already-seen alerts:
`_last_ingested_alert_timestamp()` finds the latest Suricata-own
`timestamp` string among already-persisted `eve_alert` observations
(sampled over the most recent 500), and only EVE alert records newer
than that cursor are processed — no new schema needed, the same
"derive the cursor from what's already stored" approach Sigma's own
lookback filtering uses.

## Correlation and explain wiring

`secure/correlate/strength.py` gained
`classify_suricata_finding_strength(severity)` — `high`->STRONG,
`medium`->MEDIUM, `low`->WEAK, the same severity-keyed shape as yarax/
sigma's own, for the same reason: an unclassified/low-priority
signature match must not dominate a correlation cluster's score as
though it were confirmed serious. `signals.py`'s `_classify_
integration_signal_strength()` dispatches suricata rows by
`record.integration == "suricata"`. No new `MEANINGFUL_MODULE_PAIRS`
entries were needed — the `{"integrations", "process"}`/
`{"integrations", "connections"}` pairs Phase 17 already added (keyed
by module name, not by which specific integration) already cover
suricata's own `module="integrations"` signals correctly.

`secure/explain/integration_explainer.py` gained
`_explain_suricata_alert()`, dispatched by `record.integration ==
"suricata"`. `recommended_action` is always `REVIEW_NETWORK_DESTINATION`
(this integration is fundamentally about network traffic). The
explainer inspects whether `record.message` contains the "process
attribution is not established" sentence `describe_correlation()`
embeds, and its `significance` text branches accordingly — never
claiming a specific process was involved unless the underlying
correlation genuinely found one. `confidence=CONFIRMED` means only
"Suricata's own signature match is not in doubt" — never "this traffic
is malicious" or "this process is guilty" — restated explicitly in both
`significance` and `uncertainty`.

## CLI

```
secure integrations suricata status               # EVE log + packet-visibility health + last scan
secure integrations suricata scan                  # ingest new alerts, correlate, store
secure integrations suricata observations           # eve_alert + capture_stats rows
secure integrations suricata alerts                 # IDS alerts only
secure integrations suricata mark-alert <id> known|unknown
```

No `rules`/`rulesets` subcommand exists for this integration — see
"Where Secure's responsibility ends," above.

## What's deliberately not built yet (as of Phase 18)

- No GUI screen (consistent with osquery/yarax/sigma).
- No ingestion of EVE event types beyond `alert`/`stats` (no `flow`,
  `http`, `tls`, `dns`, `fileinfo`, ...) — a deliberate v1 scope
  boundary matching "normalize USEFUL Suricata findings," not every
  possible EVE record type.
- No Suricata process management, interface configuration, or
  packet-capture permission handling of any kind — and none is
  planned; this integration reads an existing log file only.
- Not wired into `secure run-all` — same reasoning as osquery/yarax/
  sigma; run independently via `secure integrations suricata scan`.

These remain natural next steps, not oversights — Phase 18's own
instruction was to integrate Suricata "where the current macOS/network
architecture permits reliable collection," not to build a general
network-capture management layer.

---

# Zeek (Phase 19)

Zeek is Secure's fifth integration, and the first that is deliberately
**complementary to, not overlapping with**, another integration in this
app:

|              | Suricata (Phase 18)                     | Zeek (Phase 19)                                  |
|--------------|------------------------------------------|---------------------------------------------------|
| Role         | Detection / signature evidence           | Behavioral / protocol telemetry                   |
| Decides "is this bad"? | Yes — its own rule engine already did | Never — Secure never asks this about a Zeek record |
| Produces alerts? | Yes (`integration_alerts`)          | **No, structurally never**                         |
| Read from    | `eve.json` (its own decided findings)    | `conn.log`/`dns.log`/`ssl.log`/`http.log` (raw structured facts) |

## Where Secure's responsibility ends

Zeek's own analysis scripts, installed, configured, and run entirely
OUTSIDE Secure by the user, already produce rich structured facts about
network activity. Secure never runs, configures, or manages Zeek's
process lifecycle, never touches packet capture or network interfaces,
and — the phase's own explicit "Suricata = detection, Zeek = behavioral
telemetry" distinction — never treats a Zeek record as a detection
finding. This is enforced structurally, not just documented: the
`secure/integrations/zeek/` package has no `analysis.py`/severity
classifier at all, and `scanner.py` never calls `add_integration_alert()`
— there is nothing in this package that COULD write an
`integration_alerts` row. `secure integrations zeek` therefore has no
`alerts`/`mark-alert` subcommand, the same kind of deliberate omission
Suricata's own missing `rules` subcommand represents (see above) — not
an oversight, a structural guarantee.

One direct consequence: because `secure/correlate/signals.py`'s
`_collect_integrations()` only ever reads `integration_alerts` (see that
function's own docstring), Zeek can **never** produce a correlation
Signal. Zeek evidence reaches the user through
`secure integrations zeek observations`, and — for two specific
observation kinds — through the existing behavioral-baseline layer
(below), never through an inflated "this is a detection" claim.

## JSON log ingestion only (`_logs.py`, `parser.py`)

Like Suricata's own EVE JSON preference, this integration reads ONLY
Zeek's native JSON log output (`redef LogAscii::use_json = T;`, or
Zeek's `json-streaming-logs` framework script) — never Zeek's default
tab-separated format, which carries its own header/metadata lines and
escaping conventions that would need a bespoke parser, less robust than
reading the JSON Zeek can already emit. A `zeek_log_dir` pointed at
TSV-format logs simply produces unparseable/malformed lines, reported
honestly (`ZeekScanResult.malformed_lines_by_log`), never silently
misread.

Four log types are read, exactly matching the phase's own "highest-value
structured logs" bullet list:

- **conn.log** — connection/flow records: timestamp (`ts`, a UNIX epoch
  number), Zeek's own `uid` (the stable per-connection identity used as
  this integration's `identity_key` throughout), originator/responder
  address+port (`orig_h`/`orig_p`/`resp_h`/`resp_p` — Zeek's record
  doesn't say which side is "this Mac", the same ambiguity Suricata's
  own src/dest fields have), protocol, service, duration, byte/packet
  counts, connection state.
- **dns.log** — the query domain, query type, response code, answers.
- **ssl.log** — TLS version, cipher, the SNI hostname (`server_name`,
  frequently absent — a normal gap, not a parse failure), handshake
  completion, certificate validation status.
- **http.log** — method, host, URI, status code, user agent.

Every record's exact source provenance is preserved: which log file
produced it (`source_query`, e.g. `"dns.log record uid=Cxxxx
(/path/to/dns.log)"`), Zeek's own `uid`/`ts`, and this scan's own
`collected_at`. Ruleset/engine-version provenance is the optional,
read-only `zeek --version` subprocess call (`_shell.py`) — never
required; a missing/unreachable `zeek` binary only means
`tool_version` stays `None`, exactly Suricata's own `_shell.py`
convention.

## Availability — a narrower, honestly-scoped health bar (`availability.py`)

Unlike Suricata's own packet-visibility confirmation (Suricata's own
`stats` capture counters), this integration does NOT attempt to confirm
what fraction of network packets Zeek itself is seeing — that honesty
requirement was Suricata's phase-specific instruction, tied to
Suricata's role as the detection engine whose SILENCE needs to be
distinguishable from "confirmed clean." Zeek's role here is behavioral
telemetry, not detection, so a proportionate health bar is used
instead: `UNAVAILABLE` (no log directory configured/found), `ERROR`
(directory unreadable), `DEGRADED` (directory readable but either none
of the four recognized log files exist, or none of the ones that do
exist have been modified within `stale_after_seconds`, default 600s),
`OK` (at least one recognized log file present and recently modified).
File **modification time**, not log content, drives the freshness
check — cheap, and an honest signal that Zeek is still actively
writing.

## Dedup awareness — the phase's own explicit requirement (`dedup.py`)

"Implement dedup awareness for network events already seen by Secure or
Suricata." `conn.log` records — the log type that represents a genuine
"network event" the way Suricata's alerts and Secure's own native
`connection_events` both do — are classified into exactly one of three
states, embedded directly in the persisted observation's own fields
(`dedup_status`, `dedup_detail`, `dedup_matched_source_table`,
`dedup_matched_source_id`):

- `novel` — no corroborating evidence found anywhere else.
- `matches_native_connection` — matches a Secure `connection_events`
  row (from the native lsof-based connections scan) by identity
  (`remote_addr`/`remote_port`/`proto`, tried against both the record's
  "orig" and "resp" sides) AND timing (within a bounded window, default
  ±300s) — the same conservative dual-constraint discipline Suricata's
  own `correlate.py` uses for process attribution, applied here to
  connection identity instead.
- `matches_suricata_alert` — matches an already-ingested Suricata EVE
  alert observation (`integration_observations` where
  `integration="suricata"`, `kind="eve_alert"`) by the same
  identity+timing discipline.

`dns.log`/`ssl.log`/`http.log` records are NOT separately dedup-checked
— they describe protocol-level facts about a connection Zeek already
assigned a `uid` to, and that connection's own `conn.log` entry (when
present in the same ingestion batch) already carries the dedup verdict
for "is this connection itself already known elsewhere." Re-running the
same identity+timing match three more times would add no additional
information.

## Behavioral-baseline layer — dampened, not disabled (`scanner.py`, `secure/baseline/`)

The phase's own explicit ask: "Allow Secure's behavioral-baseline layer
to consume appropriate Zeek-derived observations without allowing bulk
network noise to immediately create mature baselines." Two new,
gap-filling `entity_type`s were added to `secure/baseline/entities.py`
(zero schema change — both reuse the existing `baseline_activity` table
the same way `inventory`/`process` already do):

- **`dns_query`** — the domain from a `dns.log` record (normalized:
  lowercased, one trailing root dot stripped — see
  `secure/integrations/zeek/identity.py`).
- **`tls_sni`** — the SNI hostname from a `ssl.log` record (lowercased;
  skipped entirely when no SNI was present in the handshake — a normal
  gap, never fabricated).

`conn.log` and `http.log` are deliberately NOT baselined:

- `conn.log`'s own "connection" identity is already covered by the
  EXISTING `process_destination` baseline dimension whenever a process
  can be attributed (via Secure's native lsof-based connections scan) —
  adding a second, process-less baseline dimension for the same
  underlying connections would duplicate history Phase 14's own design
  review explicitly ruled out ("do not duplicate raw feature history
  that already exists elsewhere").
- `http.log`'s own Host header is largely the same identity `dns.log`'s
  `query` domain already captures, one layer up the stack, at higher
  cardinality (full URI/user-agent) and lower interpretability — so it
  is normalized and persisted for visibility/correlation, but not fed
  into the baseline layer this phase.

**How "no bulk noise -> immediate maturity" is satisfied — by reusing
existing rules, not inventing new ones:**

1. Within one scan pass, every distinct domain/hostname is folded into
   the baseline layer **at most once**, regardless of how many raw
   `dns.log`/`ssl.log` records this pass ingested for it — the exact
   same "dedup to one call per distinct entity per scan" discipline
   `connections/scanner.py` already uses for `process_destination`
   (verified directly: 50 raw DNS records for the same domain in one
   pass still produce exactly one `baseline_entities.observation_count`
   increment).
2. Phase 14's own existing maturity rule — an entity can only reach
   ESTABLISHED once observed on `MIN_ELIGIBLE_DISTINCT_DAYS` (14)
   separate CALENDAR days, never merely enough raw volume — means the
   rate at which a domain/hostname's baseline can mature is bounded by
   how often `secure integrations zeek scan` itself runs across
   distinct days, never by how much traffic Zeek observed in one pass
   (verified directly: five scans within the same moment still advance
   `eligible_distinct_days` by exactly 1, not 5).

No additional weight-capping mechanism was invented — both effects
follow directly from patterns Phase 14 and Phase 14.5 already
established and approved.

## CLI

```
secure integrations zeek status         # log directory availability/freshness + last scan
secure integrations zeek scan           # ingest conn/dns/ssl/http records, dedup-classify, baseline, store
secure integrations zeek observations   # conn/dns/ssl/http rows
```

No `alerts`/`mark-alert` subcommand exists for this integration — see
"Where Secure's responsibility ends," above: there is structurally
nothing for it to show.

## What's deliberately not built yet (as of Phase 19)

- No GUI screen (consistent with every other integration).
- No ingestion of Zeek log types beyond `conn`/`dns`/`ssl`/`http` (no
  `weird.log`, `notice.log`, `files.log`, `x509.log`, ...) — a
  deliberate v1 scope boundary matching the phase's own "highest-value
  structured logs... such as" bullet list.
- `conn.log`/`http.log` observations are ingested and dedup-classified
  (conn.log) but not fed into the baseline layer — see above.
- No Zeek process management, interface configuration, or cluster/
  worker-topology awareness of any kind — this integration reads
  existing log files only, the same boundary Suricata's own
  availability.py documents for itself.
- Not wired into `secure run-all` — same reasoning as every other
  integration; run independently via `secure integrations zeek scan`.

These remain natural next steps, not oversights — Phase 19's own
instruction was to "begin with the highest-value structured logs," not
to build exhaustive Zeek log coverage in one pass.

## Exit codes

Every `secure integrations <engine> scan*` command (osquery `scan`, yarax
`scan-file` / `scan-fim-alerts` / `scan-suspicious`, sigma `scan`, suricata
`scan`, zeek `scan`) follows one contract:

| Exit | Meaning |
|---|---|
| 0 | Ran; nothing to review. |
| 1 | Ran; found something to review (discrepancies, matches, findings). |
| 2 | The engine was unavailable or errored this pass; nothing was checked. |

Zeek never uses 1: it records behavioural telemetry, not alerts. Before
2026-09-22 the unavailable/error branch also exited 1, so exit 1 could
mean either outcome. `status` (1 = unavailable), `rules` / `rulesets`
(1 = a rule failed to load) and `alerts` (always 0) are unchanged. Pinned
by `tests/test_cli_integrations_exit_codes.py`.

An unexpected crash (a Python traceback) also exits 2, never 1, like any
`secure` command.

`mark-alert` looks an alert up by id. Each engine's `mark-alert` refuses,
with exit 2 and the command to use instead, an id that belongs to another
integration (`tests/test_cli_integrations_mark.py`).

