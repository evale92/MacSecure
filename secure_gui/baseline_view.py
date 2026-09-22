"""The Baseline & Anomalies DataTable + EvidencePanel screen.

Phase 14.5 Stage D: Phase 14 (behavioral baselining / anomaly
detection) has had zero GUI representation until now — see
PROJECT_NOTES.md's Phase 14.5 change-log entry. This reuses the exact
DataTable + EvidencePanel pattern secure_gui/alerts_view.py already
established (Product Phase 12's pilot), rather than inventing a second
UI pattern, and is wired into secure_gui.py via one new button
mirroring "Open Alerts Table…" — see that file's `_build_alerts_launcher`
docstring for why it's a plain button rather than a Command.

Like alerts_view.py, this module is Tkinter-dependent and can only be
syntax-checked (`ast.parse`), not executed, in an environment without
Tkinter installed. Keep genuinely testable logic in
secure_gui/data_access.py instead — see tests/test_gui_components.py.

Dependency direction: this module reads secure_gui.data_access
(DISPLAY) and calls back into the caller-supplied `run_command`
(ACTIONS) — same rule alerts_view.py follows, and for the same reason
(secure_gui.py the script and secure_gui/ this package can't safely
import from each other by name — see docs/DESIGN_SYSTEM.md).

Progressive disclosure:
    Level 1 (table row):     tier, entity, feature, observed value,
                              observed_at, reviewed
    Level 2 (EvidencePanel): expected_summary, score breakdown,
                              maturity context, source reference,
                              caveats — see AnomalyRow's docstring for
                              why this does NOT go through
                              secure.explain.dispatch.explain() yet
    Level 3 (raw telemetry):  the full anomaly_events record,
                              selectable/copyable, hidden until asked
                              for
"""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional

from secure_gui import tokens
from secure_gui.components import confirm_action, resolve_fonts
from secure_gui.data_access import (
    AnomalyRow,
    fetch_all_anomalies,
    fetch_baseline_overview_now,
    format_anomaly_evidence_text,
    format_baseline_overview_text,
)
from secure_gui.view_models import anomaly_mark_request

# Same shape as alerts_view.py's RunCommand — supplied by the caller
# (secure_gui.py) rather than imported, so this module never needs to
# import the entry-point script.
RunCommand = Callable[[str, List[str], bool], None]

_COLUMNS = ("tier", "entity", "feature", "observed_value", "observed_at", "known")
_HEADINGS = {
    "tier": "Tier",
    "entity": "Entity",
    "feature": "Feature",
    "observed_value": "Observed",
    "observed_at": "When",
    "known": "Reviewed",
}


# The window's two text formatters are pure functions over
# BaselineOverview / AnomalyRow and live in secure_gui/data_access.py,
# where a test can import them — see this module's docstring ("Keep
# genuinely testable logic in secure_gui/data_access.py instead") and
# tests/test_gui_baseline_formatters.py.


def open_baseline_window(parent: tk.Misc, *, run_command: RunCommand) -> tk.Toplevel:
    """Open the Baseline & Anomalies table as a new window.

    Every existing `secure baseline ...` / `secure anomalies ...` CLI
    command remains exactly as it was — this is an additive screen,
    not a replacement, same rule the Alerts pilot follows.
    """
    fonts = resolve_fonts()

    win = tk.Toplevel(parent)
    win.title("Baseline & Anomalies")
    win.geometry("1020x680")
    win.minsize(780, 460)

    state: Dict[str, object] = {"rows": [], "by_id": {}, "selected": None}
    sort_state = {"column": "observed_at", "reverse": True}

    # ---------- header ----------
    header = tk.Frame(win, padx=10, pady=8)
    header.pack(fill=tk.X)
    tk.Label(header, text="Baseline & Anomalies", font=fonts["title"]).pack(side=tk.LEFT, anchor="n")

    overview_var = tk.StringVar(value="")
    tk.Label(
        header,
        textvariable=overview_var,
        font=fonts["small"],
        fg="#444",
        justify="left",
        anchor="w",
    ).pack(side=tk.LEFT, padx=(16, 0), anchor="n")

    tk.Label(
        header,
        text="Read-only view. Marking an anomaly here runs the same\n"
        "`secure anomalies mark` command as the CLI — check Console\n"
        "in the main window. Exclude/freeze/reset are CLI-only for now.",
        font=fonts["small"],
        fg="#888",
        wraplength=280,
        justify="right",
    ).pack(side=tk.RIGHT, anchor="n")

    toolbar = tk.Frame(win, padx=10)
    toolbar.pack(fill=tk.X)
    refresh_btn = tk.Button(toolbar, text="Refresh", command=lambda: _reload())
    refresh_btn.pack(side=tk.LEFT)
    # Per-action status, next to the button it points the operator at.
    # overview_var carries the multi-line overview and cannot double as it.
    status_var = tk.StringVar(value="")
    tk.Label(toolbar, textvariable=status_var, font=fonts["small"], fg="#666").pack(
        side=tk.LEFT, padx=(12, 0)
    )

    body = tk.PanedWindow(win, orient=tk.VERTICAL, sashwidth=6)
    body.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # ---------- Level 1: table ----------
    table_frame = tk.Frame(body)
    tree = ttk.Treeview(table_frame, columns=_COLUMNS, show="headings", selectmode="browse")
    for col in _COLUMNS:
        tree.heading(col, text=_HEADINGS[col], command=lambda c=col: _sort_by(c))
    tree.column("tier", width=120, anchor="w")
    tree.column("entity", width=280, anchor="w")
    tree.column("feature", width=140, anchor="w")
    tree.column("observed_value", width=160, anchor="w")
    tree.column("observed_at", width=150, anchor="w")
    tree.column("known", width=100, anchor="center")

    vsb = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    vsb.pack(side=tk.LEFT, fill=tk.Y)

    # Anomaly tiers (low/medium/high/critical) reuse tokens.SEVERITY's
    # existing vocabulary directly — anomaly_events never stores tier
    # "none" (see maybe_record_anomaly_event()'s docstring: no row is
    # written at all for a "none" tier), so every real tier value here
    # is already one SEVERITY already defines. Not a new vocabulary.
    for key, entry in tokens.SEVERITY.items():
        tree.tag_configure(f"tier_{key}", foreground=entry["color"])

    empty_label = tk.Label(
        table_frame, text="", font=fonts["body"], fg="#666", justify="center"
    )

    body.add(table_frame, minsize=220)

    # ---------- Level 2: EvidencePanel ----------
    panel = tk.Frame(body, padx=4, pady=4)
    body.add(panel, minsize=200)

    panel_title = tk.Label(
        panel, text="Select a row to see details", font=fonts["heading"], anchor="w"
    )
    panel_title.pack(fill=tk.X)

    badges_row = tk.Frame(panel)
    badges_row.pack(fill=tk.X, pady=(4, 4), anchor="w")
    tier_badge_label = tk.Label(badges_row, text="", font=fonts["body_bold"])
    tier_badge_label.pack(side=tk.LEFT)
    score_label = tk.Label(badges_row, text="", font=fonts["body"], fg="#444")
    score_label.pack(side=tk.LEFT, padx=(16, 0))

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
    raw_text = tk.Text(panel, height=10, font=fonts["mono"], wrap=tk.NONE)
    raw_text.configure(state=tk.DISABLED)

    # ---------- behavior ----------

    def _row_values(row: AnomalyRow):
        known_text = "✓ known" if row.known else "— unreviewed"
        entity = f"{row.entity_type}/{row.entity_key}"
        observed = f"{row.feature_name}={row.observed_value}"
        return (
            tokens.severity_text(row.anomaly_tier),
            entity,
            row.feature_name,
            row.observed_value if row.observed_value is not None else "-",
            row.observed_at,
            known_text,
        )

    def _show_message(glyph: str, heading: str, body_text: str) -> None:
        tree.delete(*tree.get_children())
        empty_label.configure(text=f"{glyph}  {heading}\n{body_text}")
        empty_label.place(relx=0.5, rely=0.4, anchor="center")

    def _populate(rows: List[AnomalyRow]) -> None:
        tree.delete(*tree.get_children())
        if not rows:
            state["rows"] = []
            es = tokens.EMPTY_STATE["no_data_yet"]
            _show_message(
                es["glyph"], es["heading"],
                "No anomalies recorded yet. Run scans and `secure run-all` "
                "to build up baseline history.",
            )
            return
        empty_label.place_forget()
        for row in rows:
            iid = str(row.id)
            tree.insert(
                "",
                tk.END,
                iid=iid,
                values=_row_values(row),
                tags=(f"tier_{(row.anomaly_tier or '').lower()}",),
            )

    def _sort_key(row: AnomalyRow, col: str):
        if col == "tier":
            return tokens.severity_rank(row.anomaly_tier)
        if col == "entity":
            return f"{row.entity_type}/{row.entity_key}"
        if col == "known":
            return row.known
        return getattr(row, col, "") or ""

    def _sort_by(col: str) -> None:
        reverse = not sort_state["reverse"] if sort_state["column"] == col else col == "observed_at"
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
        status_var.set("")
        try:
            overview = fetch_baseline_overview_now()
            rows = fetch_all_anomalies(limit=300)
        except Exception as exc:  # noqa: BLE001 — surfaced to the user, not swallowed
            entry = tokens.SENSOR_STATUS["failed"]
            _show_message(entry["glyph"], "Could not load baseline data", str(exc))
            overview_var.set(f"{entry['glyph']} {entry['label']} — see message above.")
            state["rows"] = []
            state["by_id"] = {}
            _select(None)
            return

        overview_var.set(format_baseline_overview_text(overview))
        state["rows"] = rows
        state["by_id"] = {str(r.id): r for r in rows}
        _populate(rows)
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

    def _select(row: Optional[AnomalyRow]) -> None:
        state["selected"] = row
        _hide_raw()
        if row is None:
            panel_title.configure(text="Select a row to see details")
            tier_badge_label.configure(text="")
            score_label.configure(text="")
            _set_evidence_text("")
            mark_btn.configure(state=tk.DISABLED)
            return

        panel_title.configure(text=f"{row.entity_type}/{row.entity_key} — {row.feature_name}")
        tier_badge_label.configure(
            text=tokens.severity_text(row.anomaly_tier), fg=tokens.severity_color(row.anomaly_tier)
        )
        score_label.configure(text=f"Score: {row.anomaly_score}  (run {row.run_id})")
        _set_evidence_text(format_anomaly_evidence_text(row))
        mark_btn.configure(text=("Mark Unknown" if row.known else "Mark Known"), state=tk.NORMAL)

    def _mark() -> None:
        row = state["selected"]
        if row is None:
            return
        req = anomaly_mark_request(row)
        if not confirm_action(win, title=req.confirm_title, body=req.confirm_body):
            return
        run_command(req.label, list(req.args), False)
        status_var.set(
            "Sent — check Console in the main window for the result, then Refresh."
        )
        _hide_raw()

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
