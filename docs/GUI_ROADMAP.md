# GUI roadmap (Step 4, 2026-09-22)

Decides, per CLI subsystem, whether it belongs in the GUI, stays
CLI-only, or is a cut candidate. Nothing in the code was changed.
Line numbers are at `c3e51a2`. `secure_gui/change_requests_view.py`,
`secure/cli/ai.py` and `secure/cli/agent.py` were being edited at the
same time (approval-path fix), so their line numbers may be out of date.

## 1. Inventory

### How the count was made

The full argparse tree was dumped from `secure.cli.build_parser()`
(`secure/cli/__init__.py:722`) under `.venv-tk`, not read off the
source by hand. GUI coverage was found by listing every argv the GUI
builds: the `_categories()` closures (`secure_gui.py:585-1041`), the
`run_command(...)` calls in `secure_gui/*_view.py`, and the Update
button (`secure_gui.py:1321`). Then every `data_access.fetch_*`
reader was matched to the CLI read command it mirrors.

### Real counts vs the handoff's 24 / 16 / 8

| Unit | Total | Reachable from GUI | Unreachable |
|---|---|---|---|
| `secure/cli/*.py` domain modules (excl. `__init__`) | **24** | **16** | **8** |
| Top-level `secure <cmd>` commands | **30** | 22 (20 run as argv + 2 display-only) | **8** |
| Leaf commands (runnable) | **164** | 66 run as argv, plus about 12 read-only equivalents shown by the display layer | about 86 |

The handoff's 24/16/8 is right **if "subsystem" means a module file
under `secure/cli/`**. By top-level command there are 30, because
`root.py` holds 8 commands (`init`, `status`, `add-note`, `explain`,
`check`, `snapshot`, `self`, `run-all`; `root.py:62-301`) and `ble.py`
is `bluetooth ble`, not a top-level command. Both counts give the
**same 8 unreachable subsystems**: `downloads`, `loghunt`,
`integrations`, `threatintel`, `investigate`, `dfir`, `detect`,
`validate`. The leaf count matters more than either: 7 "reachable"
subsystems are only partly reachable.

### Per-subsystem table

Legend: **Full** = every leaf runs from the GUI. **Partial** = the
missing leaves are listed. **Display** = shown read-only through
`data_access.py`, with no argv. Parser line = `secure/cli/__init__.py`.

| Top-level (parser line) | Module | GUI today | Where / missing |
|---|---|---|---|
| `init` (730) | root | Full (both roles) | `secure_gui.py:588-592`, "Identity & Setup" |
| `status` (743) | root | Full | `:594` |
| `add-note` (748) | root | Full | `:888` |
| `explain` (754) | root | Display | The Alerts panel calls `secure.explain.dispatch.explain()` in-process (`data_access.py:37,168-291`). No CLI argv. |
| `check` (766) | root | Full | `:597-601` (full and `--quick`) |
| `snapshot` (799) | root | Full | `:603` (default `--minutes` only) |
| `self` (1541) | root | Indirect | Run only by the Update button (`secure_gui.py:1321-1324`), which is correct |
| `run-all` (1791) | root | Full | `:868` |
| `inventory` (812) | inventory | Full (5/5) | `:606-635` |
| `connections` (855) | connections | Full (3/3) | `:637-652` |
| `listening` (881) | listening | Full (3/3) | `:654-669` |
| `arpwatch` (907) | arpwatch | Full (3/3) | `:671-684` |
| `wifi` (933) | wifi | Full (5/5) | `:686-713` |
| `bluetooth` (971), incl. `ble` (1023) | bluetooth, ble | Full (11/11) | `:715-778` |
| `persistence` (1070) | persistence | Full (7/7) | `:780-821` |
| `fileintegrity` (1462) | fileintegrity | **Partial 8/9** | Missing `watch-remove` (1497) |
| `correlate` (1558) | correlate | **Partial 3/6** | Missing `chains run/list/mark-alert` (1602). Chain alerts are not in the Alerts view either (`ALERT_MARK_COMMANDS`, `data_access.py:51-59`). |
| `baseline` (1639) | baseline | **Display, partial** | `baseline status` is shown by `fetch_baseline_overview` (`data_access.py:377`). Missing: `list` filters, `show`, `exclude`, `include`, `freeze`, `unfreeze`, `reset`. |
| `anomalies` (1742) | anomalies | Full in effect | `mark` via `baseline_view.py:326` (confirmed at `:324`). `list`/`show` are display (`data_access.py:498,564`). |
| `diagnostics` (2137) | diagnostics | **Partial** | `milestone record` (`performance_view.py:218-220`). `performance`/`system`/`tools`/`modules` are display (`data_access.py:625`). Missing: `history`, `report`. |
| `agent` (2207) | agent | **Partial, 7 argv of 20** | `discover`, `run` (auto and specific), `resume`, `remove-worktree`, `approve` (`agent_view.py:330-429`); `center show --diff/--tests`, `center check` (`change_requests_view.py:241-253`). `status`/`list`/`show`/`actions`/`center` are display (`data_access.py:680-736`). Missing: `supervise`, `supervisor-plist`, `supervisor-propose`, `diagnose`, `verified`, `memory`, `toolchain`, `maintain`, `promote`. |
| `ai` (2017) | ai | **Partial, 2 argv of 15** | `changes approve`/`reject` (`change_requests_view.py:273,285`, `agent_view.py:454`). Pending-only `changes list/show` equivalent via the Center. Missing: `status`, `roles`, `ask`, `history`, `show`, `verify *` (5), `changes propose`. |
| `downloads` (779) | downloads | **None** | |
| `loghunt` (789) | loghunt | **None** | |
| `integrations` (1130) | integrations | **None (0/27)** | Integration alerts are also missing from the Alerts view |
| `threatintel` (1423) | threatintel | **None** | |
| `investigate` (1801) | investigate | **None** | |
| `dfir` (1834) | dfir | **None** | |
| `detect` (1900) | detect | **None** | |
| `validate` (1973) | validate | **None** | |

One GUI button is not a `secure` command at all: "Run Test Suite
(pytest)" runs `python -m pytest -v` directly (`secure_gui.py:896-897`).
It still goes through the job queue but skips the CLI. See Q4.

## 2. Recommendations for everything not fully reachable

Rules applied: every action goes GUI, then `run_command` CLI subprocess,
then domain (`docs/DESIGN_SYSTEM.md` "display vs. actions"). Reads may
use `data_access.py`. **SEC** marks anything that approves, applies,
deletes, suppresses detection, or changes posture: it needs an explicit
`confirm_action` and its own escalated review step.

### Unreachable subsystems

| Subsystem | Decision | Form / reason |
|---|---|---|
| `downloads` | **GUI** | Buttons: "Recent Downloads" and "Flagged Downloads" (`--flagged`). Read-only. Exit 1 means UNAVAILABLE (`downloads.py:15-19`), so `nonzero_is_finding=False`. Showing it as a "finding" would hide a failed read (Invariant 5). |
| `loghunt` | **GUI** | Button "Hunt Unified Log" with default `--hours`. Read-only. Exit 1 means a hunt failed (`loghunt.py:33`), so `nonzero_is_finding=False`. Per-hunt `--hunt` stays CLI-only. Can be slow: 120 s timeout per hunt (`loghunt/_shell.py:64`). |
| `integrations` | **GUI, partly** | `status` ×5, `scan` (osquery/sigma/suricata/zeek, yarax `scan-fim-alerts`/`scan-suspicious`), `alerts` ×4, `rulesets`/`rules`: buttons. `mark-alert` ×4: the existing `mark_state_dialog` pattern, then the Alerts view (step G3). **CLI-only:** `yarax scan-file <paths>` (arbitrary paths, low value), and `observations --kind/--limit` (expert). Observation stays read-only (Invariant 4). Inert until configured (Invariant 11), so status/scan must show UNAVAILABLE honestly. |
| `threatintel` | **GUI:** `providers`, `history`. **CLI-only (user decision, Q2):** `lookup` | `lookup` is "the ONLY command that can make a real external network request" (its help text, parser at 1433). A GUI button that sends data off the machine is a posture change, so it is **SEC**. |
| `investigate` | **GUI, later as a new view** | For now, a `run_command` button: `types`, plus `show` with an entity-type chooser (`INVESTIGATE_ENTITY_TYPES`) and a key prompt. Read-only. A pivot view is higher effort and should reuse `secure.investigate` rendering (`tests/test_investigate_view.py` exists) through `data_access`. |
| `dfir` | **GUI:** `status`, `list`. **CLI-only:** `collect` | `collect` is the one exception to Invariant 4 (host-mutating collection, allowlist-gated). The CLI help says "This explicit invocation IS the approval". It needs `--artifact/--param/--reason`, which the GUI cannot safely collect. `suggest/show/evidence` need ids, so they are lower priority read buttons. |
| `detect` | **GUI:** `sync`, `list`. **SEC, confirmed, separate step:** `enable`/`disable` | Disabling a rule really stops Sigma/YARA-X evaluation (help text, parser at 1900). That reduces detection coverage, so it is **SEC**. `test`/`annotate`/`show`: CLI-only for now (expert, and they need a rule id plus free text). |
| `validate` | **GUI:** `run`, `list` | Synthetic scenarios, no host mutation (Invariant 7). A MISS must show as a real outcome. Choose `nonzero_is_finding` only after checking `cmd_validate_run`'s exit contract (**not verified**). `report` stays CLI-only: it writes `docs/generated/` into the repo. `show <run_id>` is a low-priority prompt button. |

### Partially reachable subsystems (missing leaves only)

| Missing leaf | Decision | Reason |
|---|---|---|
| `fileintegrity watch-remove` | **CLI-only (Q6)** | It stops monitoring a path, which reduces coverage. Deliberately left a command-line action. |
| `correlate chains run/list/mark-alert` | **GUI** | Same shape as `correlate`. `explain` already supports `correlation_chain_alerts` (`secure/explain/dispatch.py:31`), so chain alerts can join the Alerts view. |
| `baseline show`, `list` | **GUI (display)** | Add to `baseline_view` through a narrow `data_access` reader. |
| `baseline exclude/include/freeze/unfreeze` | **CLI-only (Q6)** | Excluding or freezing an entity changes anomaly scoring. Deliberately left a command-line action. |
| `baseline reset` | **CLI-only** | It clears learned state, and `--all/--yes` is a bulk destructive path. |
| `diagnostics history` | GUI (low) | Read-only button in the Performance window. |
| `diagnostics report` | CLI-only | Writes into `docs/generated/`. It is an artifact or scripting task. |
| `ai status`, `ai roles`, `ai history` | **GUI** | Read-only. Inert when no host is configured (Invariant 11). |
| `ai show`, `ai verify history/show/list-ops` | CLI-only for now | Need ids. Expert. |
| `ai ask` | **User decision (Q3)** | Needs a configured local model and free text. Output has to show claim tags (Invariant 6), which a console dump does not present well. |
| `ai verify run/suite` | CLI-only | The GUI's direct pytest button is removed (Q4). |
| `ai changes propose` | CLI-only | Runs two models plus tests. Long-running, expert, needs many args. |
| `agent supervise`, `diagnose`, `maintain`, `toolchain` | CLI-only | Built for automation and scheduling. Long-running and bounded by design. |
| `agent supervisor-plist`, `supervisor-propose`, `toolchain --propose` | CLI-only, SEC | Concern launchd/system changes (Invariant 12), and `propose` creates SYSTEM_CHANGE requests. |
| `agent promote [--apply]` | **CLI-only, SEC** | `--apply` writes a repair into the live working tree, the one path that crosses Invariant 8's isolation. Keeping it out of the GUI keeps it deliberate. |
| `agent verified`, `memory` | CLI-only for now (possible later read-only display) | Expert evidence views. |
| `explain` | Stays display-only | The GUI already shows the same explanation. The CLI command is labelled "Developer/debug". |

### CUT candidates

**None with strong evidence.** Every unreachable module has recent
commits or dedicated tests (for example `tests/test_downloads.py`,
`test_loghunt.py`, `test_threatintel.py`, `test_investigate_*.py`,
`test_cli_dfir.py`, `test_cli_detect.py`, `test_cli_validate.py`), and
none is marked deprecated or superseded (a `grep` for
deprecat/superseded/legacy/obsolete in `secure/cli/` found nothing).
"Not in the GUI" is not evidence of disuse, because the CLI is a primary
interface. No cut is proposed.

## 3. Prioritized GUI steps

Each step is separately reviewable. Per `docs/GUI_EXTRACTION_AUDIT.md`,
new decision logic (argv, labels, prompts, gates) goes into
`secure_gui/view_models.py` test-first, and tests go in
`tests/test_gui_*.py` (TESTING_POLICY rule 2). Every gate also needs:
the `view_models` purity guard (`test_gui_view_models.py:104,118`), the
`SecureGUI` startup-safety AST tests (`tests/test_agent.py:~1000-1070`),
and a green full suite.

**Hard limit that shapes every step:** the GUI kills any job after 60 s
(`secure_gui.py` `_execute`, `proc.communicate(timeout=60)`, ~L1169). A
default `secure loghunt` measured 51.35 s real; `--hours` up to 72 will
exceed it. `validate run`, the zeek/suricata scans and `correlate chains
run` are likely long too and are unmeasured. So the catalog carries a
per-command timeout, and `_execute` honours it.

| # | Step | Value / risk | Acceptance gate |
|---|---|---|---|
| **G1** | First step (G0 merged in). A Tk-free command catalog in `view_models.py` (label, argv, `nonzero_is_finding`, `timeout_seconds`, default 60). `_execute` honours the entry's timeout. New buttons: `downloads`, `downloads --flagged`, `loghunt`. "Prune Junk Entries" gets a confirmation (Q5). The "Run Test Suite (pytest)" button is removed (Q4). | High value, read-only; the timeout makes the new buttons reliable | New `tests/test_gui_command_catalog.py`: each catalog argv parses with `secure.cli.build_parser()` (catch `SystemExit`) and resolves to the expected handler by `func` identity; `nonzero_is_finding=False` for all three new commands (Invariant 5: exit 1 means the read failed); each timeout is pinned, loghunt's above its measured runtime. A test that `_execute` passes the entry's timeout. Prune: a declined confirm runs nothing, an accepted one runs the exact argv. Optional: pin the existing 66 argv leaves with the AST scan. |
| **G2** | Integrations: `status`, scans, `alerts`, `rulesets/rules`. **No `mark-alert`** from here: a typed id through `mark_state_dialog` can mark another integration's alert (finding 2). | High (5 engines currently invisible) | G1 catalog tests, with each scan's measured runtime behind its timeout. Exit codes checked in `secure/cli/integrations.py` before choosing each flag, with the evidence cited in the test. |
| **G2.5** SEC | CLI hardening: each `integrations <x> mark-alert` refuses an alert whose integration is not `<x>` | Closes a review-suppression path | Test-first: marking another integration's alert id exits non-zero and leaves `known` unchanged; marking its own still works. Escalate. |
| **G3** | Alerts view coverage: add `integration_alerts` and `correlation_chain_alerts` to `list_all_alerts`, plus `correlate chains run/list` buttons. Marking integration alerts happens here, per row. | High (one review queue) | `data_access` test on a `tmp_path` DB returns both new sources with explanations. `alert_mark_request` tests pin the per-row argv. **Design point:** `ALERT_MARK_COMMANDS` is keyed by table, but `integration_alerts` needs `integrations <name> mark-alert` per row, and it must not rely on pre-G2.5 behaviour. Escalate the shape. |
| **G4** | Catalog: `validate run/list`, `detect list`, `threatintel providers/history`, `dfir status/list`, `ai status/roles/history`, `diagnostics history`. `detect sync` only if its gate passes. | Medium, low risk | G1 catalog tests. `validate run` returns 1 exactly on a MISS (`return 0 if summary.count("MISS") == 0 else 1`), so `nonzero_is_finding=True`, but the test must first confirm 1 is never also an error. **`detect sync` is not read-only:** it writes the rule registry (`secure/cli/detect.py:28-45`). Include it only with a test that sync never re-enables a rule a human disabled and never disables one; otherwise it stays CLI-only. |
| **G5** | `investigate types` and `show` (type chooser plus key prompt) | Medium | A `view_models` builder returns argv or a refusal for an unknown type (test-first). |
| ~~G6a/b/c~~ | Dropped (Q6): `baseline exclude/include/freeze/unfreeze`, `fileintegrity watch-remove`, `detect enable/disable` stay CLI-only. | | |
| **G7** | Investigate pivot view (new window). **Not planned.** | Higher effort | Only after G5 shows the operator wants it. |

Order: G1 → G2 → G2.5 → G3 → G4 → G5. G1 comes first because every
later step depends on argv that cannot silently drift and on a timeout
that fits the command; it also delivers buttons, so it is not a
foundation-only step. G2.5 must land before G3 so per-row marking never
depends on the id-only lookup. Detection-reducing actions are out (Q6).
Tier A of the extraction audit (A1/A4/A7: approvals and deletion) stays
ahead of or apart from this roadmap and must not be mixed into it.

## 4. Adjacent findings (not fixed, out of scope)

1. "Prune Junk Entries" runs `inventory prune` with no confirmation
   (`secure_gui.py:634`), and it deletes rows (`inventory.py:161`,
   `delete_junk_devices`). The scope is narrow (empty, broadcast and
   multicast records), but it is a delete. Q5.
2. The four `integrations <x> mark-alert` handlers look up the alert by
   id alone (for example `integrations.py:201`) and do not check that it
   belongs to that integration. So `osquery mark-alert` can mark a Sigma
   alert (confirmed in review: `find_integration_alert_by_id`, then
   `UPDATE integration_alerts SET known = ? WHERE id = ?`,
   storage/models/integrations.py:319). Marking known removes an alert
   from review, so this is not cosmetic. Addressed by G2.5.
3. Docstrings in `data_access.py:44` and `secure_gui.py:5` still name
   `secure/cli.py`, which is now a package. Cosmetic.
4. Resolved: the approval-route fix landed in `909e2fc`, and
   `GUI_EXTRACTION_AUDIT.md`'s routing note was updated in the same commit.

## 5. Uncertainties

- The leaf counts for display equivalents are judgment calls (for
  example, whether the Performance window "is" `diagnostics tools`).
  Counts that are exact: 30 top-level, 164 leaves, 66 run as argv.
- Exit contracts for `validate run`, the integration scans and
  `threatintel` were **not** checked. G2 and G4 must check them.
- `_execute` kills every job at 60 s (checked in review); see §3. Runtimes
  of `validate run`, the integration scans and `correlate chains run` are
  still unmeasured; each step measures its own before pinning a timeout.

## 6. Questions only the user can answer

- **Q1.** Is "subsystem" meant as a module file (24) or a top-level
  command (30)? Both give the same 8 unreachable, but it decides how
  progress is reported.
- **Q2.** Should the GUI ever send a `threatintel lookup` off the
  machine (network egress, opt-in provider)? Default here: CLI-only.
- **Q3.** Do you want `ai ask` in the GUI, and if so as a view that
  shows claim tags rather than raw console text? Default: not now.
- **Q4.** Should the "Run Test Suite (pytest)" button go through
  `secure ai verify suite` (audited, allowlisted), keep calling pytest
  directly, or be removed? This is the only possible cut in scope, and
  it is yours to decide.
- **Q5.** Should "Prune Junk Entries" get a confirmation dialog?
- **Q6.** Are `baseline exclude/freeze`, `detect disable` and
  `fileintegrity watch-remove` wanted in the GUI at all (step G6)? Or
  should changes that reduce detection stay CLI-only as a deliberate
  speed bump?
- **CUT:** none proposed. If you believe a subsystem is unused, say
  which one and it can be checked.

### Decisions (2026-09-22)

The user delegated these to the driver with the instruction "aim for
leanness and efficiency":

- **Q1: module file (24).** Matches the handoff; progress is reported
  against the 8 unreachable modules.
- **Q2: CLI-only.** No network egress from the GUI.
- **Q3: not now.**
- **Q4: remove the button.** Re-decided after review: it runs
  `python -m pytest -v` (`secure_gui.py:896-897`), the full suite takes
  206-259 s, and the GUI kills jobs at 60 s, so it can never finish.
  The command line covers it. Removed in G1.
- **Q5: yes.** "Prune Junk Entries" gets a confirmation dialog, in G1.
- **Q6: CLI-only, deliberately.** Step G6 is dropped: changes that reduce
  detection stay a command-line action.
- **CUT: none.**
