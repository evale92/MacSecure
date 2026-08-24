"""The Agent -> Repairs screen (Phase 31).

Same DISPLAY/ACTIONS split every other GUI screen in this package
follows (docs/DESIGN_SYSTEM.md, see secure_gui/performance_view.py's
own docstring for the fullest statement of the convention): everything
shown here comes from secure_gui.data_access.fetch_agent_repairs_overview_now(),
a read-only query against Secure's own database. Nothing here decides
policy, runs an isolated worktree, invokes an external tool, verifies
anything, or approves/rejects a change request in Python — every
button shells out to the real `secure agent ...` / `secure ai changes
...` CLI subprocess via the caller-supplied `run_command`, so every
action narrates into the same console transcript as everything else
and goes through the exact same code path a terminal user would.

This window can never approve its own output. "Approve" here is
nothing more than a convenience for typing
`secure ai changes approve <cr_id> <revision_hash>` — the exact
revision hash shown come from the database record itself (never
retyped by hand), and Phase 28's approve_change() still independently
verifies it matches before doing anything. A human still has to click
the button; nothing in this package or secure/agent/ can trigger it.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import Callable, List

from secure_gui.components import resolve_fonts
from secure_gui.data_access import AgentRepairsOverview, fetch_agent_actions_now, fetch_agent_repairs_overview_now

RunCommand = Callable[[str, List[str], bool], None]

_RUN_COLUMNS = ("run_id", "status", "trigger", "attempt", "verification", "change_request")
_RUN_HEADINGS = {
    "run_id": "Run",
    "status": "Status",
    "trigger": "Trigger",
    "attempt": "Attempt",
    "verification": "Verification",
    "change_request": "Change Request",
}

# Phase 31.5: the Actions panel — same rows `secure agent actions
# --run-id <id>` prints, for whichever run is currently selected above.
_ACTION_COLUMNS = ("timestamp", "component", "action", "kind", "exit_code", "duration", "target")
_ACTION_HEADINGS = {
    "timestamp": "Time",
    "component": "Component",
    "action": "Action",
    "kind": "Kind",
    "exit_code": "Exit",
    "duration": "Duration (s)",
    "target": "Target",
}

_TRIGGER_KIND_CHOICES = ["pytest_failure", "validate_scenario_failure", "detect_rule_test_failure"]


def _verification_text(run) -> str:
    if run.verification_passed is True:
        return "passed"
    if run.verification_passed is False:
        return "failed"
    parts = []
    if run.pytest_status:
        parts.append(f"pytest={run.pytest_status}")
    if run.validate_status:
        parts.append(f"validate={run.validate_status}")
    return ", ".join(parts) if parts else "(not run)"


def _cr_text(run, overview: AgentRepairsOverview) -> str:
    if not run.change_request_id:
        return ""
    cr = overview.change_requests.get(run.change_request_id)
    if cr is None:
        return run.change_request_id
    return f"{cr.cr_id} ({cr.status})"


def _detail_text(run, overview: AgentRepairsOverview) -> str:
    lines = [
        f"Run:            {run.run_id}    Status: {run.status}    Attempt {run.attempt_number}/{run.max_attempts}",
        f"Trigger:        {run.trigger_kind}  {run.trigger_ref}",
        f"Detail:         {run.trigger_detail}",
        f"Created:        {run.created_at}    Completed: {run.completed_at or '(still running)'}",
        f"Base commit:    {run.base_commit}",
        f"Worktree:       {run.worktree_path}",
        f"Tool:           {run.tool_name} {run.tool_version}    Model: {run.model_name}",
        f"Agent exit:     {run.agent_exit_status or '(none)'}",
        f"Transcript:     {run.transcript_path or '(none)'}",
        "",
        f"Diff:           {run.diff_path or '(no diff)'}",
        f"Diff SHA-256:   {run.diff_hash or '(none)'}",
        f"Changed files:  {', '.join(run.changed_files) or '(none)'}",
        f"Denylist:       {run.denylist_violation or '(no violation)'}",
        "",
        f"pytest:         {run.pytest_status or '(not run)'}  {run.pytest_summary}",
        f"secure validate:{run.validate_status or '(not run)'}  {run.validate_summary}",
        f"Overall passed: {run.verification_passed}",
        "",
        f"Stop reason:    {run.stop_reason}",
    ]
    if run.change_request_id:
        cr = overview.change_requests.get(run.change_request_id)
        lines.append("")
        lines.append(f"Change request: {run.change_request_id}")
        if cr is not None:
            lines.append(f"  status:         {cr.status}")
            lines.append(f"  revision_hash:  {cr.revision_hash}")
            lines.append(f"  approved_by:    {cr.approved_by or '(none)'}")
            lines.append(f"  approved_at:    {cr.approved_at or '(none)'}")
            lines.append("")
            lines.append("  A passing verification result is NOT authorization.")
            lines.append("  Review the diff yourself (see `secure ai changes show "
                          f"{cr.cr_id}`) before approving.")
    return "\n".join(lines)


def open_agent_window(parent: tk.Misc, *, run_command: RunCommand) -> tk.Toplevel:
    """Open the Agent -> Repairs window."""
    fonts = resolve_fonts()

    win = tk.Toplevel(parent)
    win.title("Agent — Repairs")
    win.geometry("980x760")
    win.minsize(760, 520)

    state = {"overview": None, "selected_run_id": None, "actions": []}

    header = tk.Frame(win, padx=10, pady=8)
    header.pack(fill=tk.X)
    tk.Label(header, text="Agent — Repairs", font=fonts["title"]).pack(side=tk.LEFT)
    tk.Label(
        header,
        text="Supervised, human-approved autonomous repair (Phase 31).\n"
        "A passing verification result is never authorization — a human always approves.",
        font=fonts["small"],
        fg="#888",
        justify="right",
    ).pack(side=tk.RIGHT)

    status_label = tk.Label(win, text="", font=fonts["small"], fg="#888", padx=10, anchor="w", justify="left")
    status_label.pack(fill=tk.X)

    toolbar = tk.Frame(win, padx=10)
    toolbar.pack(fill=tk.X, pady=(4, 0))
    tk.Button(toolbar, text="Refresh", command=lambda: _reload()).pack(side=tk.LEFT)
    tk.Button(toolbar, text="Discover Candidates", command=lambda: _discover()).pack(side=tk.LEFT, padx=(8, 0))
    tk.Button(toolbar, text="Run (auto-discover)…", command=lambda: _run_auto()).pack(side=tk.LEFT, padx=(8, 0))
    tk.Button(toolbar, text="Run Specific Trigger…", command=lambda: _run_specific()).pack(side=tk.LEFT, padx=(8, 0))

    paned = tk.PanedWindow(win, orient=tk.VERTICAL, sashrelief=tk.RAISED)
    paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=(8, 10))

    list_frame = tk.Frame(paned)
    runs_tree = ttk.Treeview(list_frame, columns=_RUN_COLUMNS, show="headings", selectmode="browse", height=10)
    for col in _RUN_COLUMNS:
        runs_tree.heading(col, text=_RUN_HEADINGS[col])
    runs_tree.column("run_id", width=70, anchor="w")
    runs_tree.column("status", width=170, anchor="w")
    runs_tree.column("trigger", width=260, anchor="w")
    runs_tree.column("attempt", width=70, anchor="center")
    runs_tree.column("verification", width=160, anchor="w")
    runs_tree.column("change_request", width=170, anchor="w")
    runs_tree.pack(fill=tk.BOTH, expand=True)
    paned.add(list_frame, height=260)

    detail_frame = tk.LabelFrame(paned, text="Detail", padx=8, pady=6, font=fonts["body_bold"])
    detail_text = tk.Text(detail_frame, font=fonts["mono"], wrap=tk.WORD, height=16, state=tk.DISABLED)
    detail_scroll = ttk.Scrollbar(detail_frame, orient="vertical", command=detail_text.yview)
    detail_text.configure(yscrollcommand=detail_scroll.set)
    detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    detail_scroll.pack(side=tk.LEFT, fill=tk.Y)
    paned.add(detail_frame, height=340)

    # Phase 31.5: Actions panel — every audited subprocess/git/
    # filesystem/proposed-system-change action secure/agent/ recorded
    # for the currently selected run, read-only, same rows `secure
    # agent actions --run-id <id>` prints. Selecting a row here shows
    # its full argv/result/target in the label below (avoids a second
    # popup/window for what is still just a display concern).
    actions_frame = tk.LabelFrame(paned, text="Audited Actions (Phase 31.5)", padx=8, pady=6, font=fonts["body_bold"])
    actions_tree = ttk.Treeview(
        actions_frame, columns=_ACTION_COLUMNS, show="headings", selectmode="browse", height=8
    )
    for col in _ACTION_COLUMNS:
        actions_tree.heading(col, text=_ACTION_HEADINGS[col])
    actions_tree.column("timestamp", width=170, anchor="w")
    actions_tree.column("component", width=110, anchor="w")
    actions_tree.column("action", width=220, anchor="w")
    actions_tree.column("kind", width=90, anchor="center")
    actions_tree.column("exit_code", width=50, anchor="center")
    actions_tree.column("duration", width=90, anchor="center")
    actions_tree.column("target", width=220, anchor="w")
    actions_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    action_detail_label = tk.Label(
        actions_frame, text="Select an action above to see its full argv/result.",
        font=fonts["small"], fg="#888", anchor="w", justify="left", wraplength=900,
    )
    action_detail_label.pack(side=tk.TOP, fill=tk.X, pady=(4, 0))
    paned.add(actions_frame, height=200)

    actions = tk.Frame(win, padx=10)
    actions.pack(fill=tk.X, pady=(0, 10))
    tk.Button(actions, text="Resume Selected Run", command=lambda: _resume_selected()).pack(side=tk.LEFT)
    tk.Button(actions, text="Remove Worktree", command=lambda: _remove_worktree_selected()).pack(
        side=tk.LEFT, padx=(8, 0)
    )
    tk.Button(actions, text="Approve Change Request…", command=lambda: _approve_selected()).pack(
        side=tk.LEFT, padx=(24, 0)
    )
    tk.Button(actions, text="Reject Change Request…", command=lambda: _reject_selected()).pack(
        side=tk.LEFT, padx=(8, 0)
    )

    def _set_detail(text: str) -> None:
        detail_text.configure(state=tk.NORMAL)
        detail_text.delete("1.0", tk.END)
        detail_text.insert("1.0", text)
        detail_text.configure(state=tk.DISABLED)

    def _reload() -> None:
        try:
            overview = fetch_agent_repairs_overview_now()
        except Exception as exc:  # noqa: BLE001 — surfaced to the user, not swallowed
            status_label.configure(text=f"Could not load agent data: {exc}")
            return

        state["overview"] = overview
        readiness = []
        if not overview.git_ok:
            readiness.append("live checkout is NOT a git repository — repairs cannot run")
        if not overview.tool_available:
            readiness.append("agent tool not configured/on PATH")
        if not overview.ollama_configured:
            readiness.append("Ollama not configured")
        status_label.configure(
            text="Ready to run repairs." if not readiness else "Not ready: " + "; ".join(readiness)
        )

        runs_tree.delete(*runs_tree.get_children())
        for run in overview.runs:
            runs_tree.insert(
                "", tk.END, iid=run.run_id,
                values=(
                    run.run_id, run.status, f"{run.trigger_kind}: {run.trigger_ref}",
                    f"{run.attempt_number}/{run.max_attempts}", _verification_text(run),
                    _cr_text(run, overview),
                ),
            )

        if state["selected_run_id"] and runs_tree.exists(state["selected_run_id"]):
            runs_tree.selection_set(state["selected_run_id"])
        else:
            _set_detail("Select a run above to see its full detail.")
            state["selected_run_id"] = None
            actions_tree.delete(*actions_tree.get_children())
            state["actions"] = []
            action_detail_label.configure(text="Select an action above to see its full argv/result.")

    def _on_select(_event=None) -> None:
        selection = runs_tree.selection()
        if not selection:
            return
        run_id = selection[0]
        state["selected_run_id"] = run_id
        overview = state["overview"]
        if overview is None:
            return
        run = next((r for r in overview.runs if r.run_id == run_id), None)
        if run is None:
            return
        _set_detail(_detail_text(run, overview))
        _load_actions_for_run(run_id)

    runs_tree.bind("<<TreeviewSelect>>", _on_select)

    def _load_actions_for_run(run_id: str) -> None:
        """Phase 31.5: populate the Actions panel for the just-selected
        run — read-only, same rows `secure agent actions --run-id
        <id>` prints; see secure_gui.data_access.fetch_agent_actions_now()."""
        actions_tree.delete(*actions_tree.get_children())
        action_detail_label.configure(text="Select an action above to see its full argv/result.")
        try:
            actions = fetch_agent_actions_now(run_id=run_id)
        except Exception as exc:  # noqa: BLE001 — surfaced to the user, not swallowed
            state["actions"] = []
            action_detail_label.configure(text=f"Could not load audited actions: {exc}")
            return
        state["actions"] = actions
        for a in actions:
            kind = "mutating" if a.mutating else "read-only"
            actions_tree.insert(
                "", tk.END, iid=str(a.id),
                values=(a.timestamp, a.component, a.action, kind, a.exit_code, a.duration_seconds, a.target),
            )

    def _on_action_select(_event=None) -> None:
        selection = actions_tree.selection()
        if not selection:
            return
        action_id = int(selection[0])
        action = next((a for a in state["actions"] if a.id == action_id), None)
        if action is None:
            return
        argv_text = " ".join(action.argv) if action.argv else "(none)"
        approval = "yes" if action.approval_required else "no"
        action_detail_label.configure(
            text=f"argv: {argv_text}\n"
            f"cwd: {action.cwd or '(none)'}    approval_required: {approval}\n"
            f"result: {action.result_summary or '(none)'}"
        )

    actions_tree.bind("<<TreeviewSelect>>", _on_action_select)

    def _selected_run():
        overview = state["overview"]
        if overview is None or not state["selected_run_id"]:
            messagebox.showinfo("Agent — Repairs", "Select a run first.", parent=win)
            return None
        run = next((r for r in overview.runs if r.run_id == state["selected_run_id"]), None)
        if run is None:
            messagebox.showinfo("Agent — Repairs", "Select a run first.", parent=win)
        return run

    def _discover() -> None:
        run_command("Discover Repair Candidates", ["agent", "discover"], False)

    def _run_auto() -> None:
        if not messagebox.askyesno(
            "Agent — Repairs",
            "This will auto-discover the first eligible deterministic test/validation "
            "failure and attempt one autonomous repair against it in an isolated git "
            "worktree. It will NOT modify the live repository and will NOT apply or "
            "approve anything on its own. Continue?",
            parent=win,
        ):
            return
        run_command("Attempt Autonomous Repair (auto-discover)", ["agent", "run"], False)

    def _run_specific() -> None:
        kind = simpledialog.askstring(
            "Run Specific Trigger",
            f"Trigger kind ({', '.join(_TRIGGER_KIND_CHOICES)}):",
            parent=win,
        )
        if not kind:
            return
        if kind not in _TRIGGER_KIND_CHOICES:
            messagebox.showerror("Agent — Repairs", f"Unknown trigger kind: {kind!r}", parent=win)
            return
        ref = simpledialog.askstring("Run Specific Trigger", "Trigger ref (e.g. a test node id):", parent=win)
        if not ref:
            return
        run_command(
            f"Attempt Autonomous Repair ({kind}: {ref})",
            ["agent", "run", "--trigger-kind", kind, "--trigger-ref", ref],
            False,
        )

    def _resume_selected() -> None:
        run = _selected_run()
        if run is None:
            return
        if run.status != "running":
            messagebox.showinfo(
                "Agent — Repairs",
                f"{run.run_id} is not 'running' (current status: {run.status!r}) — nothing to resume.",
                parent=win,
            )
            return
        run_command(f"Resume Repair Run ({run.run_id})", ["agent", "resume", run.run_id], False)

    def _remove_worktree_selected() -> None:
        run = _selected_run()
        if run is None:
            return
        if not messagebox.askyesno(
            "Agent — Repairs",
            f"Delete the isolated worktree for {run.run_id} from disk? The database "
            "record (including the diff and transcript paths) is kept.",
            parent=win,
        ):
            return
        run_command(f"Remove Repair Worktree ({run.run_id})", ["agent", "remove-worktree", run.run_id], False)

    def _approve_selected() -> None:
        run = _selected_run()
        if run is None:
            return
        overview = state["overview"]
        if not run.change_request_id:
            messagebox.showinfo("Agent — Repairs", f"{run.run_id} has no change request to approve.", parent=win)
            return
        cr = overview.change_requests.get(run.change_request_id) if overview else None
        if cr is None:
            messagebox.showerror(
                "Agent — Repairs", f"Could not load change request {run.change_request_id}.", parent=win
            )
            return
        if cr.status != "pending":
            messagebox.showinfo(
                "Agent — Repairs", f"{cr.cr_id} is already {cr.status!r} — nothing to approve.", parent=win
            )
            return
        if not messagebox.askyesno(
            "Approve Change Request",
            f"Approve {cr.cr_id}?\n\nTitle: {cr.title}\n\n"
            "Secure will first re-check that the worktree's current diff still matches "
            "what was proposed — if it has drifted, this will refuse to approve and "
            "instead supersede this change request and (if re-verification of the "
            "current worktree still passes) generate a fresh one for you to review. "
            "Approving still only records authorization; Secure will not apply the diff "
            f"to the live repository automatically. Review the diff yourself first (see "
            f"`secure ai changes show {cr.cr_id}`) if you haven't already.",
            parent=win,
        ):
            return
        # Routed through `secure agent approve <run_id>`, never directly
        # through `secure ai changes approve` — this is the pre-approval
        # diff revalidation gate (secure/agent/orchestrator.py's
        # revalidate_before_approval()), a stricter path specifically
        # for agent-originated change requests.
        run_command(
            f"Approve Agent Repair Change Request ({cr.cr_id})",
            ["agent", "approve", run.run_id],
            False,
        )

    def _reject_selected() -> None:
        run = _selected_run()
        if run is None:
            return
        overview = state["overview"]
        if not run.change_request_id:
            messagebox.showinfo("Agent — Repairs", f"{run.run_id} has no change request to reject.", parent=win)
            return
        cr = overview.change_requests.get(run.change_request_id) if overview else None
        if cr is None:
            messagebox.showerror(
                "Agent — Repairs", f"Could not load change request {run.change_request_id}.", parent=win
            )
            return
        if cr.status != "pending":
            messagebox.showinfo(
                "Agent — Repairs", f"{cr.cr_id} is already {cr.status!r} — nothing to reject.", parent=win
            )
            return
        if not messagebox.askyesno("Reject Change Request", f"Reject {cr.cr_id}?", parent=win):
            return
        run_command(f"Reject AI Change Request ({cr.cr_id})", ["ai", "changes", "reject", cr.cr_id], False)

    _reload()
    return win
