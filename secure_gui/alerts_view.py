"""The Alerts DataTable + EvidencePanel pilot screen.

This is Product Phase 12's pilot for a structured (non-console)
screen — see docs/DESIGN_SYSTEM.md. Alerts was chosen over Device
Inventory specifically because it exercises severity, multiple source
modules, evidence, correlation findings, known/acknowledged state,
timestamps, and progressive disclosure all at once.

It lists every alert source data_access.list_all_alerts() merges: the
seven native alert tables, correlation chains, and integration alerts
(osquery, YARA-X, Sigma, Suricata). An integration alert is marked by its
own engine's command; one whose engine has no mark command is shown but
its Mark button stays disabled.

This module is Tkinter-dependent and, like secure_gui.py itself, can
only be syntax-checked (not executed) in an environment without
Tkinter installed — see PROJECT_NOTES.md. Keep any genuinely testable
logic (normalization, sorting keys, command routing) in
secure_gui/data_access.py instead, where it actually gets exercised by
tests/test_gui_components.py.

Dependency direction: this module reads secure_gui.data_access
(DISPLAY) and calls back into the caller-supplied `run_command`
(ACTIONS) — it does not import anything from the top-level
secure_gui.py script. That's deliberate, not an oversight: the
package (secure_gui/) provides reusable pieces to the entry-point
script, never the other way around, and `secure_gui.py` (the script)
and `secure_gui/` (this package) can't safely import from each other
by name — see docs/DESIGN_SYSTEM.md's implementation notes.

Progressive disclosure, exactly as specified:
    Level 1 (table row):     severity, concise finding, source, when
    Level 2 (EvidencePanel): significance, confidence (a separate
                              badge from severity — see
                              docs/DESIGN_SYSTEM.md), evidence tagged
                              by provenance, uncertainty, correlated
                              events, recommended action — all sourced
                              from the AlertRow.explanation built by
                              secure/explain/ (Product Phase 13). This
                              module renders that structured object;
                              it does not compute any of it.
    Level 3 (raw telemetry):  the full source record, selectable/
                              copyable, hidden until asked for
"""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional

from secure_gui import tokens
from secure_gui.components import confirm_action, resolve_fonts
from secure_gui.data_access import AlertRow, fetch_all_alerts
from secure_gui.view_models import alert_mark_request

# (label, argv, nonzero_is_finding) -> enqueue it exactly like any
# other button in the main window, so it runs through the same
# serialized job queue and narrates into the same console transcript.
# Supplied by the caller (secure_gui.py) rather than imported, so this
# module never needs to import the entry-point script — see the
# module docstring.
RunCommand = Callable[[str, List[str], bool], None]

_COLUMNS = ("severity", "summary", "module", "created_at", "known")
_HEADINGS = {
    "severity": "Severity",
    "summary": "Finding",
    "module": "Source",
    "created_at": "When",
    "known": "Reviewed",
}

# Short display labels for secure.explain.vocab's evidence-provenance
# keys — GUI wording choices only, not a redefinition of what each
# means (see docs/DESIGN_SYSTEM.md / docs/EXPLAINABILITY.md for that).
_PROVENANCE_LABELS = {
    "direct_observation": "OBSERVED",
    "derived_fact": "DERIVED",
    "secure_interpretation": "SECURE'S INTERPRETATION",
}

# How many correlated-event lines to render directly in the panel
# before summarizing the rest — a cluster can legitimately have
# hundreds of members (see the evidence-concentration example in
# docs/EXPLAINABILITY.md), and rendering all of them as individual
# Text lines doesn't help readability. The full list is always still
# available via Show Raw Record (Level 3).
_MAX_CORRELATED_EVENTS_SHOWN = 50


def _format_evidence_panel_text(row: AlertRow) -> str:
    """Level 2 body text: significance, evidence (tagged by
    provenance), uncertainty, and correlated events, in that order.
    Pure formatting over an already-built Explanation — computes
    nothing new.
    """
    exp = row.explanation
    lines = []

    lines.append(exp.significance)
    if exp.degraded:
        lines.append("")
        lines.append(f"(A richer explanation was unavailable: {exp.degraded_reason})")

    lines.append("")
    lines.append("Evidence:")
    if exp.evidence:
        for item in exp.evidence:
            tag = _PROVENANCE_LABELS.get(item.provenance, item.provenance.upper())
            lines.append(f"  [{tag}] {item.text}")
    else:
        lines.append("  (No specific evidence items are recorded for this finding.)")

    lines.append("")
    lines.append(f"Uncertainty ({exp.uncertainty_status.replace('_', ' ')}):")
    if exp.uncertainty:
        for note in exp.uncertainty:
            lines.append(f"  - {note}")
    else:
        lines.append("  (None recorded.)")

    if exp.correlated_events:
        lines.append("")
        total = len(exp.correlated_events)
        lines.append(f"Correlated events ({total}):")
        shown = exp.correlated_events[:_MAX_CORRELATED_EVENTS_SHOWN]
        for event in shown:
            lines.append(f"  - {event}")
        if total > _MAX_CORRELATED_EVENTS_SHOWN:
            lines.append(f"  ... and {total - _MAX_CORRELATED_EVENTS_SHOWN} more (see Show Raw Record for the full list).")

    return "\n".join(lines)


def open_alerts_window(parent: tk.Misc, *, run_command: RunCommand) -> tk.Toplevel:
    """Open the Alerts table as a new window.

    The existing per-domain console alert lists ("List Wi-Fi Alerts",
    etc.) remain exactly as they were — this is an additive screen,
    not a replacement, per docs/DESIGN_SYSTEM.md.
    """
    fonts = resolve_fonts()

    win = tk.Toplevel(parent)
    win.title("Alerts — All Modules")
    win.geometry("980x620")
    win.minsize(760, 420)

    state: Dict[str, object] = {"rows": [], "by_id": {}, "selected": None}
    sort_state = {"column": "created_at", "reverse": True}

    # ---------- header ----------
    header = tk.Frame(win, padx=10, pady=8)
    header.pack(fill=tk.X)
    tk.Label(header, text="Alerts", font=fonts["title"]).pack(side=tk.LEFT)
    status_var = tk.StringVar(value="")
    tk.Label(header, textvariable=status_var, font=fonts["small"], fg="#666").pack(
        side=tk.LEFT, padx=(12, 0)
    )
    tk.Label(
        header,
        text="Read-only view. Marking an alert here runs the same command as "
        "the matching CLI/console button — check Console in the main window.",
        font=fonts["small"],
        fg="#888",
        wraplength=260,
        justify="right",
    ).pack(side=tk.RIGHT)

    toolbar = tk.Frame(win, padx=10)
    toolbar.pack(fill=tk.X)
    refresh_btn = tk.Button(toolbar, text="Refresh", command=lambda: _reload())
    refresh_btn.pack(side=tk.LEFT)

    body = tk.PanedWindow(win, orient=tk.VERTICAL, sashwidth=6)
    body.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # ---------- Level 1: table ----------
    table_frame = tk.Frame(body)
    tree = ttk.Treeview(table_frame, columns=_COLUMNS, show="headings", selectmode="browse")
    for col in _COLUMNS:
        tree.heading(col, text=_HEADINGS[col], command=lambda c=col: _sort_by(c))
    tree.column("severity", width=140, anchor="w")
    tree.column("summary", width=380, anchor="w")
    tree.column("module", width=160, anchor="w")
    tree.column("created_at", width=150, anchor="w")
    tree.column("known", width=100, anchor="center")

    vsb = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    vsb.pack(side=tk.LEFT, fill=tk.Y)

    # Row background/foreground reinforces severity but is never the
    # only signal — every row's Severity cell also carries the glyph
    # + text label from tokens.severity_text().
    for key, entry in tokens.SEVERITY.items():
        tree.tag_configure(f"sev_{key}", foreground=entry["color"])

    empty_label = tk.Label(
        table_frame, text="", font=fonts["body"], fg="#666", justify="center"
    )

    body.add(table_frame, minsize=220)

    # ---------- Level 2: EvidencePanel ----------
    panel = tk.Frame(body, padx=4, pady=4)
    body.add(panel, minsize=170)

    panel_title = tk.Label(
        panel, text="Select a row to see details", font=fonts["heading"], anchor="w"
    )
    panel_title.pack(fill=tk.X)

    # Severity and confidence are always shown as two SEPARATE badges,
    # never merged into one — a potentially severe finding can still
    # carry low confidence, and this panel must not visually imply
    # otherwise. See docs/DESIGN_SYSTEM.md / docs/EXPLAINABILITY.md.
    badges_row = tk.Frame(panel)
    badges_row.pack(fill=tk.X, pady=(4, 4), anchor="w")
    severity_badge_label = tk.Label(badges_row, text="", font=fonts["body_bold"])
    severity_badge_label.pack(side=tk.LEFT)
    confidence_badge_label = tk.Label(badges_row, text="", font=fonts["body_bold"])
    confidence_badge_label.pack(side=tk.LEFT, padx=(16, 0))
    action_label = tk.Label(badges_row, text="", font=fonts["body"], fg="#444")
    action_label.pack(side=tk.LEFT, padx=(16, 0))

    summary_var = tk.StringVar(value="")
    tk.Label(
        panel,
        textvariable=summary_var,
        font=fonts["body_bold"],
        anchor="w",
        justify="left",
        wraplength=880,
    ).pack(fill=tk.X, pady=(2, 6))

    # Significance/evidence/uncertainty/correlated-events, as a
    # read-only, scrollable Text widget rather than stacked Labels — a
    # correlation finding can legitimately carry hundreds of
    # correlated events (see docs/EXPLAINABILITY.md's evidence-
    # concentration example), and this reuses the same "read-only but
    # selectable" pattern the console and Level 3 raw record already
    # use, rather than a new UI pattern.
    evidence_frame = tk.Frame(panel)
    evidence_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 6))
    evidence_text = tk.Text(evidence_frame, height=8, font=fonts["body"], wrap=tk.WORD)
    evidence_vsb = ttk.Scrollbar(evidence_frame, orient="vertical", command=evidence_text.yview)
    evidence_text.configure(yscrollcommand=evidence_vsb.set, state=tk.DISABLED)
    evidence_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    evidence_vsb.pack(side=tk.LEFT, fill=tk.Y)

    actions = tk.Frame(panel)
    actions.pack(fill=tk.X, pady=(4, 4))
    mark_btn = tk.Button(actions, text="Mark Known", command=lambda: _mark(), state=tk.DISABLED)
    mark_btn.pack(side=tk.LEFT)
    raw_toggle_btn = tk.Button(actions, text="Show Raw Record ▸", command=lambda: _toggle_raw())
    raw_toggle_btn.pack(side=tk.LEFT, padx=(8, 0))
    copy_raw_btn = tk.Button(actions, text="Copy Raw", command=lambda: _copy_raw())
    copy_raw_btn.pack(side=tk.LEFT, padx=(8, 0))

    # ---------- Level 3: raw telemetry (hidden until asked for) ----------
    # A disabled Text widget, not a Label: this is the same
    # "read-only but selectable/copyable" pattern the main console
    # already uses (see secure_gui.py's _copy_console) — Copy Raw
    # reads and clipboards it directly rather than relying on
    # mouse-drag selection working reliably inside a disabled widget.
    raw_text = tk.Text(panel, height=10, font=fonts["mono"], wrap=tk.NONE)
    raw_text.configure(state=tk.DISABLED)

    # ---------- behavior ----------

    def _row_values(row: AlertRow):
        known_text = "✓ known" if row.known else "— unreviewed"
        return (tokens.severity_text(row.severity), row.summary, row.module, row.created_at, known_text)

    def _show_message(glyph: str, heading: str, body_text: str) -> None:
        tree.delete(*tree.get_children())
        empty_label.configure(text=f"{glyph}  {heading}\n{body_text}")
        empty_label.place(relx=0.5, rely=0.4, anchor="center")

    def _populate(rows: List[AlertRow]) -> None:
        tree.delete(*tree.get_children())
        if not rows:
            state["rows"] = []
            es = tokens.EMPTY_STATE["no_data_yet"]
            _show_message(es["glyph"], es["heading"], es["body"])
            return
        empty_label.place_forget()
        for row in rows:
            iid = f"{row.source_table}:{row.source_id}"
            tree.insert(
                "",
                tk.END,
                iid=iid,
                values=_row_values(row),
                tags=(f"sev_{(row.severity or '').lower()}",),
            )

    def _sort_key(row: AlertRow, col: str):
        if col == "severity":
            return tokens.severity_rank(row.severity)
        if col == "known":
            return row.known
        return getattr(row, col, "")

    def _sort_by(col: str) -> None:
        reverse = not sort_state["reverse"] if sort_state["column"] == col else col == "created_at"
        sort_state["column"] = col
        sort_state["reverse"] = reverse
        rows = sorted(state["rows"], key=lambda r: _sort_key(r, col), reverse=reverse)
        state["rows"] = rows
        _populate(rows)
        for c in _COLUMNS:
            arrow = ""
            if c == col:
                arrow = " ▼" if reverse else " ▲"
            tree.heading(c, text=_HEADINGS[c] + arrow)

    def _reload() -> None:
        try:
            rows = fetch_all_alerts(limit=300)
        except Exception as exc:  # noqa: BLE001 — surfaced to the user, not swallowed
            entry = tokens.SENSOR_STATUS["failed"]
            _show_message(entry["glyph"], "Could not load alerts", str(exc))
            status_var.set(f"{entry['glyph']} {entry['label']} — see message above.")
            state["rows"] = []
            state["by_id"] = {}
            _select(None)
            return

        state["rows"] = rows
        state["by_id"] = {f"{r.source_table}:{r.source_id}": r for r in rows}
        _populate(rows)
        unreviewed = sum(1 for r in rows if not r.known)
        if rows:
            status_var.set(f"{len(rows)} alert(s) — {unreviewed} not yet reviewed.")
        else:
            status_var.set("")
        _select(None)

    def _on_select(_event=None) -> None:
        selection = tree.selection()
        if not selection:
            _select(None)
            return
        by_id = state["by_id"]
        _select(by_id.get(selection[0]))

    def _set_evidence_text(text: str) -> None:
        evidence_text.configure(state=tk.NORMAL)
        evidence_text.delete("1.0", tk.END)
        evidence_text.insert(tk.END, text)
        evidence_text.configure(state=tk.DISABLED)

    def _select(row: Optional[AlertRow]) -> None:
        state["selected"] = row
        _hide_raw()
        if row is None:
            panel_title.configure(text="Select a row to see details")
            severity_badge_label.configure(text="")
            confidence_badge_label.configure(text="")
            action_label.configure(text="")
            summary_var.set("")
            _set_evidence_text("")
            mark_btn.configure(state=tk.DISABLED)
            return

        exp = row.explanation
        panel_title.configure(text=f"{row.module} — {row.subject}")
        severity_badge_label.configure(text=tokens.severity_text(exp.severity), fg=tokens.severity_color(exp.severity))
        confidence_badge_label.configure(text=tokens.confidence_text(exp.confidence), fg=tokens.confidence_color(exp.confidence))
        action_label.configure(text=f"Recommended: {exp.recommended_action_text}")
        summary_var.set(exp.summary)
        _set_evidence_text(_format_evidence_panel_text(row))
        mark_btn.configure(
            state=(tk.NORMAL if row.mark_command else tk.DISABLED),
            text=("Mark Unknown" if row.known else "Mark Known"),
        )

    def _mark() -> None:
        row = state["selected"]
        if row is None:
            return
        req = alert_mark_request(row)
        if req is None:
            status_var.set(f"No mark action is defined for {row.source_table}.")
            return
        if not confirm_action(win, title=req.confirm_title, body=req.confirm_body):
            return
        run_command(req.label, list(req.args), False)
        status_var.set(
            "Sent — check Console in the main window for the result, then Refresh."
        )

    def _toggle_raw() -> None:
        if raw_text.winfo_ismapped():
            _hide_raw()
        else:
            _show_raw()

    def _show_raw() -> None:
        row = state["selected"]
        if row is None:
            return
        raw_text.configure(state=tk.NORMAL)
        raw_text.delete("1.0", tk.END)
        raw_text.insert(tk.END, json.dumps(row.raw, indent=2, default=str))
        raw_text.configure(state=tk.DISABLED)
        raw_text.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        raw_toggle_btn.configure(text="Hide Raw Record ▾")

    def _hide_raw() -> None:
        raw_text.pack_forget()
        raw_toggle_btn.configure(text="Show Raw Record ▸")

    def _copy_raw() -> None:
        row = state["selected"]
        if row is None:
            return
        text = json.dumps(row.raw, indent=2, default=str)
        win.clipboard_clear()
        win.clipboard_append(text)
        win.update()
        original = copy_raw_btn.cget("text")
        copy_raw_btn.config(text="Copied!")
        win.after(1200, lambda: copy_raw_btn.config(text=original))

    tree.bind("<<TreeviewSelect>>", _on_select)

    _reload()
    return win
