"""The Remediation Panel — automated response dashboard and execution monitor.

Phase 52: GUI panel for automated remediation and response orchestration.
Shows execution history, pending actions, and approval queue. All state-
changing actions (run, approve) go through the CLI subprocess via run_command,
preserving the audit trail through Phase 47's safe-code infrastructure.

This module follows the same design as alerts_view.py:
- DISPLAY: reads data_access.fetch_remediation_dashboard_now()
- ACTIONS: calls run_command() for CLI subprocess execution
- Progressive disclosure: Level 1 (table), Level 2 (detail panel)
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional

from secure_gui import tokens
from secure_gui.components import confirm_action, resolve_fonts
from secure_gui.data_access import (
    RemediationDashboard,
    RemediationExecution,
    fetch_remediation_dashboard_now,
)

RunCommand = Callable[[str, List[str], bool], None]

_COLUMNS = ("action_id", "status", "started_at", "completed_at")
_HEADINGS = {
    "action_id": "Action",
    "status": "Status",
    "started_at": "Started",
    "completed_at": "Completed",
}

_STATUS_COLORS = {
    "PENDING": "#FF9500",
    "SUCCESS": "#34C759",
    "FAILED": "#FF3B30",
    "RUNNING": "#5AC8FA",
}


def _status_tag(status: str) -> str:
    """Format status for display with appropriate styling."""
    icons = {
        "PENDING": "⏳",
        "SUCCESS": "✓",
        "FAILED": "✗",
        "RUNNING": "◐",
    }
    icon = icons.get(status, "?")
    return f"{icon} {status}"


def open_remediation_window(parent: tk.Misc, *, run_command: RunCommand) -> tk.Toplevel:
    """Open the Remediation dashboard as a new window.

    Shows execution stats, recent executions, and approval queue.
    All mutations go through the CLI subprocess (run_command).
    """
    fonts = resolve_fonts()

    win = tk.Toplevel(parent)
    win.title("Remediation — Execution Monitor")
    win.geometry("900x650")
    win.minsize(700, 450)

    state: Dict[str, object] = {
        "dashboard": None,
        "rows": [],
        "by_id": {},
        "selected": None,
    }
    sort_state = {"column": "started_at", "reverse": True}

    # ---------- header ----------
    header = tk.Frame(win, padx=10, pady=8)
    header.pack(fill=tk.X)
    tk.Label(header, text="Remediation", font=fonts["title"]).pack(side=tk.LEFT)
    status_var = tk.StringVar(value="")
    tk.Label(header, textvariable=status_var, font=fonts["small"], fg="#666").pack(
        side=tk.LEFT, padx=(12, 0)
    )
    tk.Label(
        header,
        text="Automated response execution monitor. All actions route through CLI.",
        font=fonts["small"],
        fg="#888",
        wraplength=280,
        justify="right",
    ).pack(side=tk.RIGHT)

    # ---------- toolbar ----------
    toolbar = tk.Frame(win, padx=10)
    toolbar.pack(fill=tk.X)
    refresh_btn = tk.Button(toolbar, text="Refresh", command=lambda: _reload())
    refresh_btn.pack(side=tk.LEFT)

    # ---------- stats frame ----------
    stats_frame = tk.Frame(win, padx=10, pady=8)
    stats_frame.pack(fill=tk.X)

    pending_var = tk.StringVar(value="Pending: —")
    success_var = tk.StringVar(value="Successful: —")
    failed_var = tk.StringVar(value="Failed: —")

    tk.Label(stats_frame, textvariable=pending_var, font=fonts["normal"], fg="#FF9500").pack(
        side=tk.LEFT, padx=10
    )
    tk.Label(stats_frame, textvariable=success_var, font=fonts["normal"], fg="#34C759").pack(
        side=tk.LEFT, padx=10
    )
    tk.Label(stats_frame, textvariable=failed_var, font=fonts["normal"], fg="#FF3B30").pack(
        side=tk.LEFT, padx=10
    )

    body = tk.PanedWindow(win, orient=tk.VERTICAL, sashwidth=6)
    body.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # ---------- Level 1: execution history table ----------
    table_frame = tk.Frame(body)
    tree = ttk.Treeview(table_frame, columns=_COLUMNS, show="headings", selectmode="browse")
    for col in _COLUMNS:
        tree.heading(col, text=_HEADINGS[col], command=lambda c=col: _sort_by(c))
    tree.column("action_id", width=200, anchor="w")
    tree.column("status", width=120, anchor="w")
    tree.column("started_at", width=180, anchor="w")
    tree.column("completed_at", width=180, anchor="w")

    vsb = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    vsb.pack(side=tk.LEFT, fill=tk.Y)

    # Color code status by execution state
    for status, color in _STATUS_COLORS.items():
        tree.tag_configure(f"status_{status}", foreground=color)

    # Level 2: detail panel
    detail_frame = tk.Frame(body)
    detail_text = tk.Text(detail_frame, font=fonts["mono"], height=8, wrap=tk.WORD)
    detail_text.pack(fill=tk.BOTH, expand=True)

    body.add(table_frame, height=200)
    body.add(detail_frame, height=150)

    def _load_data():
        """Load remediation dashboard data and populate table."""
        try:
            dashboard = fetch_remediation_dashboard_now(limit=50)
            state["dashboard"] = dashboard

            # Update stats
            total = dashboard.pending_count + dashboard.successful_count + dashboard.failed_count
            pending_var.set(f"Pending: {dashboard.pending_count}")
            success_var.set(f"Successful: {dashboard.successful_count}")
            failed_var.set(f"Failed: {dashboard.failed_count}")
            status_var.set(f"Total: {total}")

            # Clear and repopulate table
            for item in tree.get_children():
                tree.delete(item)
            state["rows"] = []
            state["by_id"] = {}

            for execution in dashboard.recent_executions:
                row_id = tree.insert(
                    "",
                    "end",
                    values=(
                        execution.action_id,
                        _status_tag(execution.status),
                        execution.started_at,
                        execution.completed_at or "—",
                    ),
                    tags=(f"status_{execution.status}",),
                )
                state["rows"].append(execution)
                state["by_id"][row_id] = execution

        except Exception as e:
            status_var.set(f"Error loading data: {e}")

    def _reload():
        """Refresh data and UI."""
        _load_data()

    def _sort_by(column: str):
        """Sort table by column."""
        reverse = sort_state["reverse"] if sort_state["column"] == column else False
        sort_state["column"] = column
        sort_state["reverse"] = not reverse

        # Re-sort rows
        if state["rows"]:
            reverse_bool = sort_state["reverse"]
            if column == "started_at":
                sorted_rows = sorted(
                    state["rows"],
                    key=lambda r: r.started_at or "",
                    reverse=reverse_bool,
                )
            elif column == "completed_at":
                sorted_rows = sorted(
                    state["rows"],
                    key=lambda r: r.completed_at or "",
                    reverse=reverse_bool,
                )
            else:
                sorted_rows = sorted(
                    state["rows"],
                    key=lambda r: getattr(r, column, ""),
                    reverse=reverse_bool,
                )

            for item in tree.get_children():
                tree.delete(item)

            for execution in sorted_rows:
                tree.insert(
                    "",
                    "end",
                    values=(
                        execution.action_id,
                        _status_tag(execution.status),
                        execution.started_at,
                        execution.completed_at or "—",
                    ),
                    tags=(f"status_{execution.status}",),
                )

    def _on_select(event=None):
        """Show detail when a row is selected."""
        selection = tree.selection()
        if not selection:
            detail_text.config(state=tk.NORMAL)
            detail_text.delete("1.0", tk.END)
            detail_text.insert("1.0", "(Select an execution to see details)")
            detail_text.config(state=tk.DISABLED)
            return

        row_id = selection[0]
        execution = state["by_id"].get(row_id)
        if not execution:
            return

        state["selected"] = execution

        detail_text.config(state=tk.NORMAL)
        detail_text.delete("1.0", tk.END)

        lines = [
            f"Execution ID:  {execution.execution_id}",
            f"Action ID:     {execution.action_id}",
            f"Status:        {execution.status}",
            f"Risk Level:    {execution.risk_level}",
            f"Started:       {execution.started_at}",
            f"Completed:     {execution.completed_at or '(still running)'}",
        ]

        detail_text.insert("1.0", "\n".join(lines))
        detail_text.config(state=tk.DISABLED)

    tree.bind("<<TreeviewSelect>>", _on_select)

    # Initial load
    _load_data()

    return win
