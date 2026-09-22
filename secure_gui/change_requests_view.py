"""The Agent -> Change Requests screen (Phase 40, "Change Request Center").

Same DISPLAY/ACTIONS split every other GUI screen in this package
follows (docs/DESIGN_SYSTEM.md): everything shown here comes from
secure_gui.data_access.fetch_change_request_center_now(), a read-only
query against Secure's own database, and every ACTION shells out to the
real `secure ...` CLI subprocess via the caller-supplied `run_command`
so it narrates into the same console transcript and goes through the
exact same code path a terminal user would.

This window CANNOT approve anything by itself. Its Approve button is a
convenience for typing the approval command a terminal user would:

    secure agent approve <run_id>                    (a repair run proposed it)
    secure ai changes approve <cr_id> <revision_hash> (anything else)

An agent-originated request must go through `secure agent approve`, the
revalidation gate that re-checks the worktree diff first (Phase 31); plain
`ai changes approve` refuses those. The choice and the dialog text live in
secure_gui/view_models.py's cr_approve_request(). A human still has to click.
Nothing in secure/agent/ can trigger this window or its buttons.

Where agent_view.py is RUN-centric (one row per repair attempt), this
screen is CHANGE-REQUEST-centric: one row per thing a human actually
has to decide about. That is the distinction Phase 40 asked for, and
it is why this is a separate screen rather than another panel bolted
onto the existing one.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Callable, List

from secure_gui.components import resolve_fonts
from secure_gui.data_access import fetch_change_request_center_now
from secure_gui.view_models import cr_approve_request

RunCommand = Callable[[str, List[str], bool], None]

_COLUMNS = ("cr_id", "classification", "status", "title", "run_id", "reviewer", "tests")
_HEADINGS = {
    "cr_id": "Request",
    "classification": "Class",
    "status": "Status",
    "title": "Title",
    "run_id": "Run",
    "reviewer": "Reviewer",
    "tests": "Tests",
}


def _tests_cell(view) -> str:
    if view.verification_passed is True:
        return "passed"
    if view.verification_passed is False:
        return "FAILED"
    if view.pytest_status or view.validate_status:
        return f"pytest={view.pytest_status} validate={view.validate_status}"
    return "(none recorded)"


def _reviewer_cell(view) -> str:
    if not view.review_status:
        return "(none)"
    if view.review_blocking:
        return f"BLOCKING: {', '.join(view.review_blocking)}"
    return view.review_status


def detail_text(view) -> str:
    """Every field the Phase 40 governing text lists, in one pane.

    Pure and Tkinter-free on purpose, so the content of this screen can
    be tested without a display — the same reason
    secure_gui/agent_view.py keeps `_detail_text()` separate.
    """
    lines = [
        f"Request ID:        {view.cr_id}",
        f"Status:            {view.status}",
        f"Created:           {view.created_at}",
        f"Classification:    {view.classification or '(unclassified)'}"
        f"    requires human approval: {view.requires_human_approval}",
        "",
        f"Requesting run:    {view.run_id or '(none — not from an agent repair)'}",
        f"Requesting model:  {view.requesting_tool or '(none)'} / {view.requesting_model or '(none)'}",
        "",
        f"Title:             {view.title}",
        "",
        "Reason:",
        f"  {view.reason}",
        "",
        "Exact proposed action:",
        f"  {view.proposed_action}",
        "",
        f"Revision hash:     {view.revision_hash}",
        f"Diff SHA-256:      {view.diff_hash or '(no diff)'}",
        f"Diff file:         {view.diff_path or '(none)'}",
        f"Affected:          {view.affected_component}",
        f"Changed files:     {', '.join(view.changed_files) or '(none)'}",
        "",
        "Tests performed and results:",
        f"  pytest:          {view.pytest_status or '(not run)'}  {view.pytest_summary}",
        f"  secure validate: {view.validate_status or '(not run)'}  {view.validate_summary}",
        f"  overall passed:  {view.verification_passed}",
        "",
        "Independent reviewer assessment:",
        f"  {view.review_provider or '(none)'}/{view.review_model or '(none)'}"
        f"  status={view.review_status or '(none)'}",
        f"  blocking: {', '.join(view.review_blocking) if view.review_blocking else '(none)'}",
        f"  {view.review_summary or '(no summary)'}",
        "",
        f"Commands involved: {len(view.commands)} audited action(s)"
        + (f" — see `secure agent actions --run-id {view.run_id}`" if view.run_id else ""),
        "",
        "Rollback strategy:",
        f"  {view.rollback}",
        "",
        "Risks (this is the text your approval hash covers):",
        f"  {view.risks}",
        "",
        "A passing verification result is NOT authorization. A second model raising no",
        "blocking findings is NOT an approval. Read the diff before you decide.",
    ]
    return "\n".join(lines)


def open_change_requests_window(parent: tk.Misc, *, run_command: RunCommand) -> tk.Toplevel:
    """Open the Agent -> Change Requests window."""
    fonts = resolve_fonts()

    win = tk.Toplevel(parent)
    win.title("Agent — Change Requests")
    win.geometry("1040x780")
    win.minsize(820, 560)

    state = {"views": [], "selected": None}

    header = tk.Frame(win, padx=10, pady=8)
    header.pack(fill=tk.X)
    tk.Label(header, text="Agent — Change Requests", font=fonts["title"]).pack(side=tk.LEFT)
    tk.Label(
        header,
        text="Everything awaiting your decision (Phase 40).\n"
        "Approval is bound to the exact revision shown — changed content is superseded, never inherited.",
        font=fonts["small"],
        fg="#888",
        justify="right",
    ).pack(side=tk.RIGHT)

    status_label = tk.Label(win, text="", font=fonts["small"], fg="#888", padx=10, anchor="w", justify="left")
    status_label.pack(fill=tk.X)

    toolbar = tk.Frame(win, padx=10)
    toolbar.pack(fill=tk.X, pady=(4, 0))
    tk.Button(toolbar, text="Refresh", command=lambda: _reload()).pack(side=tk.LEFT)
    tk.Button(toolbar, text="View Diff", command=lambda: _view_diff()).pack(side=tk.LEFT, padx=(8, 0))
    tk.Button(toolbar, text="View Tests", command=lambda: _view_tests()).pack(side=tk.LEFT, padx=(8, 0))
    tk.Button(toolbar, text="Re-check Integrity", command=lambda: _check()).pack(side=tk.LEFT, padx=(8, 0))
    tk.Button(toolbar, text="Approve…", command=lambda: _approve()).pack(side=tk.RIGHT)
    tk.Button(toolbar, text="Reject…", command=lambda: _reject()).pack(side=tk.RIGHT, padx=(0, 8))

    paned = tk.PanedWindow(win, orient=tk.VERTICAL, sashrelief=tk.RAISED)
    paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=(8, 10))

    list_frame = tk.Frame(paned)
    tree = ttk.Treeview(list_frame, columns=_COLUMNS, show="headings", selectmode="browse", height=9)
    for col in _COLUMNS:
        tree.heading(col, text=_HEADINGS[col])
    tree.column("cr_id", width=80, anchor="w")
    tree.column("classification", width=190, anchor="w")
    tree.column("status", width=90, anchor="w")
    tree.column("title", width=280, anchor="w")
    tree.column("run_id", width=70, anchor="w")
    tree.column("reviewer", width=170, anchor="w")
    tree.column("tests", width=120, anchor="w")
    tree.pack(fill=tk.BOTH, expand=True)
    paned.add(list_frame, height=240)

    detail_frame = tk.LabelFrame(paned, text="Details", padx=8, pady=6, font=fonts["body_bold"])
    detail_widget = tk.Text(detail_frame, font=fonts["mono"], wrap=tk.WORD, height=18, state=tk.DISABLED)
    detail_scroll = ttk.Scrollbar(detail_frame, orient="vertical", command=detail_widget.yview)
    detail_widget.configure(yscrollcommand=detail_scroll.set)
    detail_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    detail_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    paned.add(detail_frame)

    def _set_detail(text: str) -> None:
        detail_widget.configure(state=tk.NORMAL)
        detail_widget.delete("1.0", tk.END)
        detail_widget.insert("1.0", text)
        detail_widget.configure(state=tk.DISABLED)

    def _selected():
        return state["selected"]

    def _reload() -> None:
        try:
            views = fetch_change_request_center_now()
        except Exception as exc:  # noqa: BLE001 — a read failure must not kill the window
            status_label.configure(text=f"Could not read change requests: {exc}")
            return
        state["views"] = views
        tree.delete(*tree.get_children())
        for view in views:
            tree.insert(
                "", tk.END, iid=view.cr_id,
                values=(
                    view.cr_id, view.classification or "(unclassified)", view.status, view.title,
                    view.run_id or "", _reviewer_cell(view), _tests_cell(view),
                ),
            )
        status_label.configure(
            text=f"{len(views)} change request(s) awaiting approval. "
            "Nothing here has been applied to the live checkout."
        )
        state["selected"] = None
        _set_detail("Select a change request above to see its full detail.")

    def _on_select(_event=None) -> None:
        selection = tree.selection()
        if not selection:
            return
        cr_id = selection[0]
        for view in state["views"]:
            if view.cr_id == cr_id:
                state["selected"] = view
                _set_detail(detail_text(view))
                return

    tree.bind("<<TreeviewSelect>>", _on_select)

    def _require_selection():
        view = _selected()
        if view is None:
            messagebox.showinfo("No selection", "Select a change request first.", parent=win)
        return view

    def _view_diff() -> None:
        view = _require_selection()
        if view is None:
            return
        run_command(f"secure agent center show {view.cr_id} --diff", ["agent", "center", "show", view.cr_id, "--diff"], False)

    def _view_tests() -> None:
        view = _require_selection()
        if view is None:
            return
        run_command(f"secure agent center show {view.cr_id} --tests", ["agent", "center", "show", view.cr_id, "--tests"], False)

    def _check() -> None:
        view = _require_selection()
        if view is None:
            return
        run_command(f"secure agent center check {view.cr_id}", ["agent", "center", "check", view.cr_id], True)

    def _approve() -> None:
        view = _require_selection()
        if view is None:
            return
        req = cr_approve_request(view)
        if not messagebox.askyesno(req.confirm_title, req.confirm_body, parent=win):
            return
        run_command(req.label, list(req.args), False)

    def _reject() -> None:
        view = _require_selection()
        if view is None:
            return
        confirmed = messagebox.askyesno("Reject change request", f"Reject {view.cr_id}?", parent=win)
        if not confirmed:
            return
        run_command(
            f"secure ai changes reject {view.cr_id}", ["ai", "changes", "reject", view.cr_id], False
        )

    _reload()
    return win
