# ARCHITECTURE_RULES.md

The structural rules every change to Secure must obey. `docs/ARCHITECTURE.md`
is the descriptive map of the codebase; this file is the normative subset
an author — human or agent — has to follow.

The numbered **Rules** below are complete and sized to fit inside the
per-file excerpt budget `secure/agent/context.py` applies when feeding
this file into a repair prompt. Everything after the Rules is
elaboration and may be truncated, so no rule lives down there.

## Rules

1. **A lower layer never imports from a higher one.** The layer order
   is: foundation (`config`, `logging_setup`, `storage`) → native
   sensors → external integrations → `evidence` → `baseline` →
   `correlate`/`detect` → `explain`/`threatintel` → `investigate` →
   `dfir` → `validate` → `ai` → interfaces (`cli`, `secure_gui`).
2. **`validate`, `ai`, `agent`, and `diagnostics` are peers, callable
   only from the interfaces layer.** No sensor, integration, evidence,
   baseline, correlation, or explanation module may import them, in
   either direction.
3. **Interfaces stay thin.** `secure/cli/` and `secure_gui.py` parse
   input, call downward, and format output. No detection, scoring, or
   correlation logic lives there.
4. **Only `secure/storage/models/` writes SQL.** Every other module
   goes through those functions. No raw SQL anywhere else.
5. **Schema changes are additive only.** New tables and new columns
   with safe defaults; `init_schema()` must stay safe to call on every
   run. Never drop or repurpose an existing column.
6. **Every subprocess call goes through a seam.** A module's
   `_shell.py` (or the equivalent single function), always fixed-argv,
   always `shell=False`, always timeout-bound, so tests can mock the
   one call site.
7. **Optional capability is gated by an empty-string-default config
   field**, checked before any I/O, so the feature is inert on a fresh
   install and never fails a machine that does not have the tool.
8. **New capability goes in a new package**, not bolted onto an
   existing sensor. Cross-cutting analysis reuses `evidence` for
   identity rather than inventing a second identity model.
9. **Pass values down, never import upward to fetch one.** If a lower
   layer needs something a higher layer knows, it becomes a parameter
   with a safe default.
10. **Do not reimplement what an adopted framework already does.**
    Secure owns policy, trust, verification, provenance, auditing, and
    approval. Frameworks own reasoning loops, code generation, and
    tool invocation. Do not recreate the latter inside Secure for
    architectural purity.

---

## Why the layer rule is load-bearing

`secure validate` is trustworthy as a release gate precisely because it
can exercise the detection layers in isolation with synthetic fixtures
and know the result reflects only those layers' logic — no hidden
dependency on the CLI, GUI, or AI layer above them. The same property
is why the AI layer, and later the agent layer, could each be added in
a single phase without touching detection logic anywhere below.

Breaking rule 1 does not usually break a test right away. It breaks the
argument that the tests mean anything.

## Additive-only, in practice

Most phases in this project add: one new table, a handful of config
fields with safe defaults, one new package called only from the
interfaces layer, and zero changes to existing modules. When a change
cannot be made additively, that is a signal to stop and reconsider the
design, not to start editing shared code.

## Where the boundaries are enforced by tests, not convention

Several project rules have real tests behind them rather than only
prose, each written against the actual source of every file under
`secure/` rather than against a comment: no module may write outside
`cfg.app_dir_path()`, no module may invoke `launchctl`, and — checked
by parsing the AST, not by substring match — no file under
`secure/agent/` may import or call `approve_change()`/`reject_change()`.
Prefer adding that kind of structural test over adding a comment.

Rule 6's `shell=False` discipline is currently held by convention and
code review rather than by a structural test. That is a known gap, not
a statement that the rule is optional.
