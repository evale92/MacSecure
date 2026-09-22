# GUI extraction audit (Step 2, 2026-09-21)

Scope: the `secure_gui/` package (not the `secure_gui.py` entry script).
Goal: list the pure logic trapped inside `open_*_window()` closures, so it
can be moved where tests can reach it. Nothing in the code was changed by
this audit. Revised after review (first draft over-counted test coverage
and missed six functions).

## Method

- An AST pass over every function nested inside a top-level function in
  `secure_gui/*.py`: what it captures from the enclosing scope, whether it
  calls Tk, runs a command, hits the database, or writes captured state.
- Every flagged function was then read by hand. The heuristic alone
  misfiles some (e.g. `_toggle_raw` looks pure but only drives widgets).
- Test coverage was checked by reading each test reference, not by
  counting name matches (a name match can be a docstring or a negative
  assertion; see headline 2).
- Interpreter: `.venv-tk` (Python 3.14.7, Tk 9.0). All `secure_gui`
  modules import cleanly there.

## Headline findings

1. **54 nested functions** across five views (agent 13, alerts 14,
   baseline 14, change_requests 10, performance 3). Only 4 are pure as
   written (`_row_values`, `_sort_key` in alerts and baseline). Most
   extractable logic is *inside* Tk-bound functions: text, labels, argv,
   status gates, eligibility.
2. **No view-module helper is tested today: 12 are untested.** The views
   define 11 private top-level pure helpers plus the public `detail_text`.
   - `detail_text`: `tests/test_agent_center.py` (docstring, L10-17) says
     the module is never imported; it tests equivalent fields on
     `ChangeRequestView` instead.
   - `_format_evidence_panel_text`: appears in tests only in a docstring
     and in a *negative* check that baseline_view does not define it
     (`test_gui_baseline_formatters.py:256`). The alerts_view copy is
     untested.
3. **Step 3's premise is stale.** `baseline_view._mark()` is at line 318
   and acts: commit `b6312ce` (2026-09-16) fixed the self-write no-op, and
   `test_baseline_view_mark_tells_the_operator_what_happened` pins the fix.
   The handoff's "line 388" is from an older file (at `2f246ef` it was 427
   lines with the no-op at L388; `9d522cc` moved it). `b6312ce` states the
   widget was never imported or rendered (no `_tkinter`). That is the open
   gap.
4. **alerts_view and baseline_view are near-copies.** Row values, sort
   keys, sort-state toggling, raw-record text, status text and the mark
   flow are duplicated with small differences.

Checked and ruled out: `baseline_view._mark` has no `mark_command is None`
guard, unlike alerts, but `AnomalyRow.mark_command` (data_access.py:437)
always returns `("anomalies", "mark")`. The change-request window's
"N change request(s) awaiting approval" is accurate: it loads only pending
requests (`list_pending_change_requests`, data_access.py:724).

## Extraction list

Line numbers are the `def` of the enclosing nested function at `34424de`.

### Tier A: decides what gets run, approved or deleted (highest value)

| # | Where | Logic to extract | Proposed pure function |
|---|---|---|---|
| A1 | `agent_view.py` `_approve_selected` L390, `_reject_selected` L433 | Identical 3-step eligibility check: no CR on the run / CR not loadable / CR not pending, each with its own message and severity | `repair_cr_check(run, overview, verb) -> (ok, level, message)` |
| A2 | `agent_view.py` `_reload` L225 | "Ready to run repairs." vs "Not ready: …" from `git_ok`, `tool_available`, `ollama_configured` | `agent_readiness_text(overview)` |
| A3 | `agent_view.py` `_run_specific` L344 | Trigger-kind validation against `_TRIGGER_KIND_CHOICES` and the `agent run` argv | `specific_trigger_command(kind, ref) -> argv or error` |
| A4 | `change_requests_view.py` `_approve` L255, `_reject` L277 | Confirmation text and argv. **Approve: done** (`view_models.cr_approve_request`, with the approval-route fix). Reject still inline | `reject_command(view)` |
| A5 | `baseline_view.py` `_mark` L318, `alerts_view.py` `_mark` L376 | `new_status`, confirmation body, argv, console label (alerts: plus the "no mark action defined" case) | `anomaly_mark_request(row)`, `alert_mark_request(row)` |
| A6 | `agent_view.py` `_resume_selected` L364 | Status gate (`run.status != "running"` refuses) and `agent resume` argv | `resume_command(run) -> argv or refusal` |
| A7 | `agent_view.py` `_remove_worktree_selected` L377 | Confirmation text and `agent remove-worktree` argv. **Destructive** (deletes the worktree from disk) | `remove_worktree_prompt(run)`, `remove_worktree_command(run)` |
| A8 | `agent_view.py` `_run_auto` L332 | Confirmation text and `agent run` argv | `auto_repair_prompt()`, `auto_repair_command()` |

**Approval routing: pin it exactly.** Every approval of an
agent-originated change request goes through the revalidation gate,
whichever surface triggers it (fixed 2026-09-22; before that the Center
sent agent requests to plain `ai changes approve`, which skipped the
re-check). Extraction tests must pin each argv:

- agent_view approve: `["agent", "approve", run_id, "--cr-id", cr_id]`
  (`view_models.agent_approve_args`), the `revalidate_before_approval` gate (comment at agent_view.py L422-426).
- agent_view reject: `["ai", "changes", "reject", cr_id]`.
- Change Request Center approve: `["agent", "approve", run_id, "--cr-id",
  cr_id]` when a
  repair run proposed the request, otherwise `["ai", "changes", "approve",
  cr_id, revision_hash]`; built by `view_models.cr_approve_request`.
  Center reject: `["ai", "changes", "reject", cr_id]`.
- `secure ai changes approve` itself refuses agent-originated requests,
  and `agent approve --cr-id` refuses if the run now links a different
  request (a stale screen after a drift must not approve the replacement).

### Tier B: display logic, mostly duplicated

| # | Where | Logic | Proposed |
|---|---|---|---|
| B1 | `alerts_view` `_row_values` L268; `baseline_view` `_row_values` L203 | Tree row tuple. Baseline computes an unused local `observed` (dead code) | `alert_row_values(row)`, `anomaly_row_values(row)` |
| B2 | `alerts_view` `_sort_key` L295; `baseline_view` `_sort_key` L243 | Column sort keys (severity rank, entity, known) | `alert_sort_key(row, col)`, `anomaly_sort_key(row, col)` |
| B3 | `_sort_by` in both (alerts L302, baseline L252) | Next `(column, reverse)` state and heading arrow text | `next_sort_state(prev, col, default_desc)`, `heading_label(col, active, reverse)` |
| B4 | `_select` in both (alerts L351, baseline L299) | Panel title, badge text/colour, score line, button label/enabled | a small view-model per row type |
| B5 | `_show_raw` and `_copy_raw` in both (alerts L405/L420, baseline L345/L360) | `json.dumps(row.raw, indent=2, default=str)`, written four times | `raw_record_text(row)` |
| B6 | `agent_view` `_reload` rows (in L225), `_load_actions_for_run` L281 | Run row tuple; action row with "mutating"/"read-only" | `run_row_values(run, overview)`, `action_row_values(action)` |
| B7 | `performance_view` `_reload` L189 | Module row with `?` for missing CPU/observations/findings | `module_run_row_values(run)` |
| B8 | `change_requests_view` `_reload` L195; `alerts_view` `_reload` L315 (status at L330-334) | Row tuple and status lines: "N change request(s) awaiting approval…" and its twin "N alert(s) — M not yet reviewed." | `cr_row_values(view)`, `cr_status_text(count)`, `alert_status_text(rows)` |
| B9 | `agent_view` `_on_action_select` L301 | Action detail text: argv joined, cwd, `approval_required` yes/no, result | `action_detail_text(action)` |
| B10 | `agent_view` `_selected_run` L319 | Look up the selected run in the overview (the "Select a run first." dialog stays in the view) | `find_run(overview, run_id)` |

### Tier C: already top-level and pure, but untested (12)

`change_requests_view`: `detail_text`, `_tests_cell`, `_reviewer_cell`.
`agent_view`: `_verification_text`, `_cr_text`, `_detail_text`.
`alerts_view`: `_format_evidence_panel_text`.
`performance_view`: `_fmt_bytes`, `_system_text`, `_secure_text`,
`_integrations_tools_text`, `_warnings_text`.

These need to be **moved, then tested**; testing them in place is not
enough. A test that imports a view module needs tkinter, so it must use
`importorskip("tkinter")` and would silently skip under an interpreter
without it. The product's own verification runs `sys.executable -m pytest
tests`, and `b6312ce` records that the Agent venv has no `_tkinter`, so
that coverage would vanish exactly where verification runs. Moving them
into the Tk-free module below is mechanical. (Indirect coverage was not
traced.)

### Not worth extracting

Widget wiring with no decision in it: `_show_message`, `_populate`,
`_set_*_text`, `_on_select`, `_hide_raw`/`_toggle_raw`, the clipboard part
of `_copy_raw`, `_section`, and the one-line command buttons (`_discover`,
`_view_diff`, `_view_tests`, `_check`). `performance_view._record_milestone`
L212 builds a trivial argv (`["diagnostics", "milestone", "record",
label]`); list it here unless it grows a gate.

## Decisions (from review)

1. **Destination: a new Tk-free module, `secure_gui/view_models.py`, not
   `data_access.py`.** `docs/DESIGN_SYSTEM.md` defines `data_access.py`
   as the read-only display layer and the only reader of storage; Tier A
   builds actions, which would blur that boundary. `data_access.py`
   imports storage, so it cannot promise "no I/O"; a new module can
   promise no tkinter, no `secure.storage` and no subprocess, and a guard
   test can enforce it. Conditions:
   - Leave existing items where they are: `ALERT_MARK_COMMANDS`,
     `AlertRow.mark_command`, `AnomalyRow.mark_command`,
     `format_baseline_overview_text`, `format_anomaly_evidence_text`.
     `view_models` consumes them.
   - `view_models` may import `secure_gui.tokens` (already Tk-free);
     import `data_access` types only under `TYPE_CHECKING`, or duck-type.
   - Update the DESIGN_SYSTEM.md Components section ("pure logic belongs
     in tokens.py or data_access.py") in the same change.
   - Tests go in `tests/test_gui_*.py` so TESTING_POLICY's targeted tier
     finds them.
2. **Step 3 re-scope, in this order:**
   1. Close `b6312ce`'s real gap first: a behavioural test of the baseline
      window under Tk. Monkeypatch `fetch_baseline_overview_now`,
      `fetch_all_anomalies` and `confirm_action` in the
      `secure_gui.baseline_view` namespace; build the window, select a
      row, `mark_btn.invoke()`; assert `run_command` received exactly
      `(label, ["anomalies", "mark", str(id), "known"], False)` and the
      status line is set. Guard with `pytest.importorskip("tkinter")` plus
      a skip on `TclError` when creating the root, so it cannot break the
      suite under a no-Tk interpreter.
   2. Then extract A5 test-first into `view_models.py` as the pilot.
      A1, A4 and A7 touch approvals or deletion; do them as separate,
      escalated steps.
   3. The existing AST test `_mark_feedback_violations`
      (`test_gui_baseline_formatters.py`, around L300-330) requires `_mark`
      to contain one bare `run_command(...)` followed by
      `status_var.set("<string literal>")`. Do not edit it to make an
      extraction pass (AGENTS.md rule 3). Keep that literal in the view,
      or retire the AST test as its own reviewed change once the
      behavioural test covers the same property.
3. **Order after Step 3:** Tier A (approvals, deletion, command gates),
   then B5/B1/B2/B3/B8 as one de-duplication pass across alerts and
   baseline, then move-and-test Tier C.
