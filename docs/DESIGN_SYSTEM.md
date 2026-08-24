# Secure — GUI Design System (Product Phase 12)

This documents the design system introduced in Product Phase 12 and
implemented in `secure_gui/` (a new package) plus targeted, additive
changes to the existing `secure_gui.py` entry-point script. It's
written for whoever touches the GUI next — including future-me — so
the reasoning behind these choices doesn't have to be re-derived from
the code.

Companion reading: `SOFTWARE_ENGINEERING_PLAN.md` (the engineering
context this phase was built under) and `PROJECT_NOTES.md` (the
phase-by-phase build log, including this phase's entry).

## Why this exists

Before this phase, `secure_gui.py` was a console wrapper: every button
shelled out to the CLI and dumped raw stdout/stderr text into one
`scrolledtext.ScrolledText` widget. That's honest and simple, but it
doesn't scale to security review — severity, evidence, and review
state all collapse into plain text, indistinguishable from each other
by anything other than reading carefully. This phase adds a small,
reusable vocabulary and component set, and pilots it on one real
screen (Alerts), without rewriting the rest of the app.

## Scope of this phase

Done:
- Design tokens (spacing, color, severity, sensor health, run outcome,
  empty states) — `secure_gui/tokens.py`.
- Typography correction: system UI font for prose, monospace reserved
  for technical telemetry — `secure_gui/components.py`.
- Shared dialog/badge helpers, replacing 16 duplicated inline dialog
  chains — `secure_gui/components.py`.
- A thin, read-only display-data layer — `secure_gui/data_access.py`.
- The Alerts DataTable + EvidencePanel pilot screen —
  `secure_gui/alerts_view.py`.

Explicitly not done (deferred to the Phase 14–15 architecture/UX
consolidation milestone — see `SOFTWARE_ENGINEERING_PLAN.md`):
- Reorganizing navigation around the 10 eventual domains
  (Overview/Network/Wireless/Endpoint/Files/Alerts/Forensics/
  Privacy/Settings/Diagnostics).
- Converting every other screen (Device Inventory, Wi-Fi, Bluetooth,
  etc.) to the DataTable pattern.
- Any new GUI dependency, component-inheritance framework, custom icon
  pipeline, database redesign, or CLI redesign.

## Architectural boundary: display vs. actions

```
DISPLAY:  GUI -> read-only query/model layer -> storage
ACTIONS:  GUI -> CLI (subprocess) -> domain logic -> storage
```

`secure_gui/data_access.py` is the only place in the GUI package that
reads `secure.storage.models` directly, and it only ever reads. Every
state-changing action — every scan, every "mark known/unknown," every
config change — still runs through `secure_gui.py`'s existing
subprocess job queue, exactly as before. `alerts_view.py` never writes
to the database; when the user marks an alert, it hands an argv list
back to a `run_command` callback supplied by `secure_gui.py`, which
enqueues it through the same `Command`/`_run_command` machinery every
other button uses. That means an action taken from the Alerts table
is serialized with every other running command and shows up in the
same console transcript — there is no second, parallel way to run a
command in this app.

`data_access.py` deliberately does not become a general
repository/service layer. It exposes exactly what the Alerts pilot
needs (`AlertRow`, `list_all_alerts`, `fetch_all_alerts`,
`ALERT_MARK_COMMANDS`). If a future screen needs different read-only
data, prefer adding a narrow function here over letting Tkinter view
code reach into `secure.storage.models` directly.

### A note on the package name

`secure_gui/` (this package) and `secure_gui.py` (the entry-point
script) sit in the same directory and share a name on purpose — it
reads naturally as "the GUI's own support package." But Python can
only resolve `import secure_gui` one way: empirically, the package
wins over the script. That means `secure_gui/*.py` modules must never
import anything from the top-level `secure_gui.py` script — there's no
name left to import it by. The dependency only ever flows one
direction: the script imports from the package, never the reverse.
`alerts_view.py` follows this by taking a `run_command` callback
instead of importing `Command`/`SecureGUI` from the script.

## Typography

Two type roles, not one:

- **UI prose** — titles, headings, card text, buttons, dialogs,
  explanations, ordinary labels — uses the system's actual default UI
  font, resolved at runtime from Tk's `TkDefaultFont` / `TkHeadingFont`
  named fonts (`secure_gui/components.py:resolve_fonts()`). Never
  hardcoded to a specific family name.
- **Technical telemetry** — IP/MAC addresses, hashes, UUIDs, ports,
  filesystem paths, raw command output, raw records — uses the
  system's monospace font, resolved from `TkFixedFont`.

This reinforces a real distinction: *human explanation* reads in the
normal UI font, *technical evidence* reads in monospace. The console
pane keeps its monospace font (it's real command output). Everything
else that used to hardcode `"Menlo"` now uses the resolved system font
instead.

`resolve_fonts()` is called once, after the Tk root exists (`Tk`'s
named fonts don't exist before that), and cached for the process's
lifetime. It returns a dict of roles: `title`, `heading`, `body`,
`body_bold`, `small`, `mono`, `mono_bold`.

## Spacing and color

`secure_gui/tokens.py` — `SPACE` (xs/sm/md/lg/xl, 4–24px) and `COLORS`
(the console's existing dark palette, plus severity/sensor-health
colors chosen to stay legible on both the dark console and
`ttk.Treeview`'s default light background). Color is always paired
with a glyph and a text label everywhere it's used in this phase —
never the only signal, per the "don't rely on color alone" rule.

## Four separate vocabularies

These are kept apart deliberately — merging them would say something
the backend doesn't actually know:

| Vocabulary | Answers | Owner | Where |
|---|---|---|---|
| `SEVERITY` | How bad is this finding, if real? | Backend (must match scanner output exactly) | `tokens.SEVERITY`, `severity_text()` |
| `SENSOR_STATUS` | Did the sensor/scan itself work? | Backend, but this vocabulary is allowed to be ahead of backend support (see below) | `tokens.SENSOR_STATUS`, `sensor_status_text()` |
| `RUN_OUTCOME` | How did this button click's subprocess exit? | GUI-only | `tokens.RUN_OUTCOME`, `run_outcome_text()` |
| `EMPTY_STATE` | Why is this list showing nothing right now? | GUI-only, backed by the above | `tokens.EMPTY_STATE` |
| `CONFIDENCE` | How strongly does the stored evidence support Secure's interpretation? | Backend-owned meaning (`secure/explain/vocab.py`, Product Phase 13); this table only maps those strings to a glyph/color, same as `SEVERITY` | `tokens.CONFIDENCE`, `confidence_text()` |

Confidence is a fifth, related-but-separate vocabulary, added in
Product Phase 13 (see `docs/EXPLAINABILITY.md` for the full model —
this file only covers how the GUI presents it). It answers a
different question than severity ("how bad, if real" vs. "how sure Secure
is about the interpretation"), uses a different glyph set and color
palette than `SEVERITY` so the two badges are never visually
interchangeable, and is rendered as its own separate badge everywhere
it appears — never merged into, or displayed as a variant of, the
severity badge.

### Severity

Five levels: `critical`, `high`, `medium`, `low`, `informational`,
plus an explicit `unknown` fallback. Keys match the `severity` strings
the backend actually emits — `secure/correlate` uses all five;
`secure/fileintegrity` uses low/medium/high; older modules
(arpwatch/wifi/bluetooth/ble/persistence) currently only ever emit
medium/high. This module never invents a severity string the backend
doesn't produce; `severity_text()`/`severity_color()`/`severity_rank()`
all fall back to the `unknown` entry for anything unrecognized rather
than raising or rendering blank.

### Sensor / scan health

Seven states: `success`, `degraded`, `unavailable`,
`permission_required`, `timeout`, `failed`, `not_yet_run`, plus
`unknown`. This is independent of severity — a scan can succeed and
find nothing, succeed and find something severe, or the sensor itself
can be unavailable regardless of what it would have found.

This vocabulary is **allowed to be ahead of backend support** by
design. Today, only `secure/persistence` distinguishes `UNAVAILABLE`
(a codesign check that couldn't run); everything else only ever
produces a plain success/failure via its CLI exit code. The other five
states exist so the GUI has somewhere correct to render them once a
given backend module grows the ability to report them — this is
tracked as backend work for future phases, not faked here. Nothing in
this phase claims a module is DEGRADED or UNAVAILABLE when it's really
just "we don't have that information."

### Run outcome (GUI-only)

`secure_gui.py`'s `_execute()` reports one of `success`, `findings`,
`stopped`, `timeout`, `failed` for every button click — each with a
distinct glyph (`✓`, `⚑`, `⏹`, `⏱`, `✕`) so a real failure is never
visually adjacent to "ran fine, nothing found." This is deliberately a
different vocabulary from `SENSOR_STATUS`: a command can exit nonzero
for reasons that have nothing to do with sensor health (e.g. "no alert
with that id" — see `Command.nonzero_is_finding`'s docstring in
`secure_gui.py`), so conflating the two would misrepresent what
actually happened.

### Empty / result states

Five states that must never look the same:

| State | Glyph | Meaning |
|---|---|---|
| `no_data_yet` | `○` | Nothing scanned yet |
| `clean_result` | `✓` | Scanned, found nothing |
| `filtered_empty` | `–` | Data exists, current filter matches nothing |
| `unavailable` | `⚠` | Sensor couldn't run — not a clean result |
| `permission_required` | `🔒` | macOS permission not granted yet — not a clean result |

The Alerts pilot currently implements `no_data_yet` (nothing in any
alert table) and a load-failure state (using the `SENSOR_STATUS`
`failed` glyph, since a display-layer read failure is the same kind of
fact). `clean_result` / `filtered_empty` / `unavailable` /
`permission_required` are defined and ready for screens that have a
scan-vs-no-scan distinction or a filter — the Alerts table doesn't
filter yet, so it hasn't needed all five.

## Components (`secure_gui/components.py`)

Tkinter-dependent — like `secure_gui.py`, this file can only be
syntax-checked (`ast.parse`), not imported, in an environment without
Tkinter (see `PROJECT_NOTES.md`). Keep it thin; anything that can be
pure logic belongs in `tokens.py` or `data_access.py` instead, where
it's actually unit-tested.

- **`resolve_fonts()`** — see Typography above.
- **`severity_badge(parent, severity)`** / **`status_badge(parent, status)`**
  — small `Label` builders combining glyph + text + color from the
  token tables above.
- **`mark_state_dialog(parent, *, title, id_prompt, states=("known","unknown"))`**
  — collapses the "ask for an id, then ask which of two states"
  2-dialog chain into one call. Replaces 16 near-identical inline
  blocks that used to be written out individually in `secure_gui.py`
  (one per domain: inventory, connections, listening, arpwatch, wifi
  ×2, bluetooth ×2, BLE ×2, persistence ×3, file integrity ×2,
  correlate). `states` also covers the trusted/untrusted variants
  (Bluetooth, BLE).
- **`confirm_action(parent, *, title, body, destructive=False)`** —
  standard yes/no confirmation. Per the "avoid unnecessary
  confirmation dialogs for harmless actions" rule, this is used only
  for the two genuinely state-changing/disruptive confirmations that
  existed before this phase (marking an alert from the Alerts pilot,
  and restarting the app while a command is running) — it is not
  wrapped around read-only buttons.

Four single-value prompts (name a device, add a watch path, add a
note) and the three-way busy-conflict dialog (`_prompt_busy_conflict`)
are intentionally left as bespoke `simpledialog`/`messagebox` calls —
they don't fit the id+state shape `mark_state_dialog` was built for,
and forcing them into it would add complexity without removing
duplication.

## The Alerts pilot (`secure_gui/alerts_view.py`)

Chosen over Device Inventory specifically because it's more
architecturally demanding: it has to validate severity, multiple
source modules, evidence, correlation findings, known/acknowledged
state, timestamps, and progressive disclosure all at once, in one
screen.

Opened via a new "Open Alerts Table…" button (its own box, above the
existing per-domain categories, in the scrollable left panel). The
existing per-module console alert lists ("List Wi-Fi Alerts", "List
Bluetooth Alerts," etc.) are untouched and remain the raw/fallback
view — this phase is additive, not a replacement.

### Where the data comes from

`secure_gui/data_access.py`'s `AlertRow` normalizes all 7 existing
alert tables (`arp_alerts`, `wifi_alerts`, `bluetooth_alerts`,
`ble_alerts`, `persistence_alerts`, `file_integrity_alerts`,
`correlation_alerts`) into one shape, via the existing
`secure.storage.models.list_*_alerts()` functions — no new tables, no
schema change, no CLI change. `list_all_alerts()` is pure and
unit-tested against a real temp database
(`tests/test_gui_components.py`); `fetch_all_alerts()` is the thin
wrapper that opens the app's actual configured database
(`load_config()` + `Database`) for the live GUI to call.

`ALERT_MARK_COMMANDS` maps each source table to the exact CLI
subcommand argv that marks one of its alerts known/unknown — verified
directly against `secure/cli.py`'s argparse wiring, and identical to
the commands `secure_gui.py`'s own per-domain "Mark Alert
Known/Unknown…" buttons already run:

| Source table | CLI command |
|---|---|
| `arp_alerts` | `arpwatch mark <id> known\|unknown` |
| `wifi_alerts` | `wifi mark-alert <id> known\|unknown` |
| `bluetooth_alerts` | `bluetooth mark-alert <id> known\|unknown` |
| `ble_alerts` | `bluetooth ble mark-alert <id> known\|unknown` |
| `persistence_alerts` | `persistence mark-alert <id> known\|unknown` |
| `file_integrity_alerts` | `fileintegrity mark-alert <id> known\|unknown` |
| `correlation_alerts` | `correlate mark-alert <id> known\|unknown` |

`arpwatch` is the one exception in shape — its only markable alert
entity is `arp_alerts`, exposed as `arpwatch mark` with no `-alert`
suffix — `tests/test_gui_components.py` pins this down explicitly so
it can't be "fixed" into false consistency later.

Correlation rows additionally carry `contributing_modules`, mapped
from `secure/correlate/signals.py`'s own short module keys (e.g.
`"arpwatch"`, `"file_integrity"` — verified directly against that
file) via a **separate** lookup, `SIGNAL_MODULE_LABELS`, rather than
reusing `MODULE_LABELS` — the two vocabularies don't line up 1:1 (a
correlation can pull in `inventory`/`connections`/`listening`/
`process` signals that have no `*_alerts` table of their own at all),
and conflating them would mislabel some members. An unrecognized
module key falls back to its raw string rather than being dropped
silently.

### Progressive disclosure

- **Level 1 — table row** (`ttk.Treeview`): severity (glyph + text,
  row-tinted by severity color as reinforcement, never the only
  signal), concise finding text, source module, timestamp, review
  state. Columns are sortable by clicking their headers.
- **Level 2 — EvidencePanel** (enriched in Product Phase 13 — see
  `docs/EXPLAINABILITY.md` for the full model): a severity badge and a
  confidence badge as two separate widgets, the recommended action, a
  summary/significance line, and a scrollable evidence/uncertainty/
  correlated-events area — all sourced from `AlertRow.explanation` (a
  structured `Explanation` object built by `secure/explain/`, not
  GUI-generated prose and not the raw `backend_text`). For correlation
  findings specifically, this includes the raw-observations/distinct-
  behaviors/distinct-modules breakdown and, when one module dominates
  the raw count, an explicit note that the count shouldn't be read as
  that many independent sources of corroboration.
- **Level 3 — raw telemetry**: hidden behind a "Show Raw Record"
  toggle, not shown by default. The full source record (every
  underlying database field, via `dataclasses.asdict`) pretty-printed
  as JSON in a disabled `Text` widget — the same "read-only but
  selectable" pattern the main console already uses — plus a "Copy
  Raw" button that clipboards it directly (matching
  `secure_gui.py`'s existing `_copy_console`), so raw evidence is
  reliably copyable regardless of whether text selection inside a
  disabled Tk `Text` widget behaves consistently.

### Marking an alert from the pilot

Selecting a row enables a "Mark Known"/"Mark Unknown" button (label
reflects current state). Clicking it shows `confirm_action` (this is a
security-state change, not a read-only action), then hands
`[*mark_command, str(source_id), new_status]` to the `run_command`
callback `secure_gui.py` supplied when it opened the window — which
wraps it in the same `Command` the rest of the app uses and enqueues
it on the existing job queue. The result appears in the main window's
console, exactly like any other action. The Alerts window does not
auto-refresh after marking (no reactive state/event framework was
added, per the "keep it small" instruction) — a status line says
"check Console, then Refresh," and Refresh is a plain button.

## Component states

Buttons and the mark action follow the states already implied by
Tkinter/`ttk` widget mechanics plus this phase's additions:

- **normal** — default.
- **disabled** — Mark button is disabled until a row is selected, and
  disabled for the (currently nonexistent) case of a source table with
  no mark command.
- **selected** — a Treeview row shows the platform's native selection
  highlight, independent of the severity tint.
- **loading** — the existing "Running: <label>…" status line and
  non-modal busy state (buttons stay clickable, per the existing
  busy/queue/stop-conflict prompt — this phase doesn't change that
  behavior).
- **empty** — see Empty states above.
- **error** — see Error handling below.

Hover/focus rely on Tk/`ttk`'s native platform styling; this phase
doesn't override them (out of scope, no custom theming was added).

## Error handling

`fetch_all_alerts()`'s exceptions are caught in `alerts_view.py` and
shown as a message in the table area (using the `SENSOR_STATUS`
`failed` glyph) plus a one-line status message — never a raw
traceback in the window. Diagnostics (the existing "Run Test Suite"
category, and the console's own stderr tag) remain the place for full
detail; this phase didn't need to add anything new there since the
Alerts pilot's only failure mode is a database read.

## Accessibility

Every severity/status indicator pairs a glyph with a text label —
nothing is color-only. Labels/buttons use plain, descriptive text
("Open Alerts Table…", "Mark Known") rather than icon-only controls.
Raw telemetry is kept in a real selectable `Text` widget rather than
canvas-drawn text. Full screen-reader/VoiceOver-level accessibility
work for Tkinter is a larger undertaking and a real toolkit
limitation — Tkinter has meaningfully weaker accessibility APIs than a
modern web/native toolkit. This is tracked here as a documented,
open gap rather than silently deferred without a paper trail; this
phase didn't attempt to work around it with custom widgets, per the
"no component-inheritance framework" scope limit.

## Testability

`secure_gui/tokens.py` and `secure_gui/data_access.py` import no
Tkinter and are unit-tested normally (`tests/test_gui_components.py`)
— including against a real temp SQLite database seeded through
`secure.storage.models`, the same pattern `tests/test_correlate.py`
uses for `signals.py`. `secure_gui/components.py` and
`secure_gui/alerts_view.py` import `tkinter`, which isn't installed in
every environment this project runs test in; they're verified with
`ast.parse` (syntax only) and careful manual review, matching the
precedent `secure_gui.py` itself has had for the whole project. No
pixel-perfect screenshot testing was attempted — not a strong fit for
a small Tkinter app with no CI screenshot infrastructure.

## File map

```
secure_gui/
    __init__.py       Package docstring / module map (this doc, condensed).
    tokens.py          Pure. Spacing, color, severity, sensor-health,
                       run-outcome, empty-state vocabulary.
    components.py      Tkinter. Font resolution, badges, shared dialogs.
    data_access.py      Pure. AlertRow, list_all_alerts/fetch_all_alerts,
                       ALERT_MARK_COMMANDS, MODULE_LABELS,
                       SIGNAL_MODULE_LABELS.
    alerts_view.py      Tkinter. The Alerts DataTable + EvidencePanel.
secure_gui.py            Entry-point script. Unchanged responsibilities;
                       now imports tokens/components/alerts_view and
                       uses them where it used to hardcode fonts/colors
                       or repeat dialog code inline.
tests/test_gui_components.py   Tests for tokens.py + data_access.py.
```

## What's next (Phase 14–15, not this phase)

- Reorganize navigation around the 10 domains instead of the current
  16 phase-numbered categories.
- Decide, screen by screen, which existing console-only views become
  DataTables and which stay console (not everything needs to convert).
- Revisit `SENSOR_STATUS` against whatever backend modules have
  gained DEGRADED/UNAVAILABLE detection by then.
- Consider whether `secure_gui/` should absorb `Command`/`Category`
  from the script now that there's a real package to hold them —
  deferred this phase specifically to keep the import-direction rule
  simple (see "A note on the package name" above); revisit once
  there's a second consumer that would benefit.
