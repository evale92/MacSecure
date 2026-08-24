"""The Diagnostics -> Performance screen (Phase 30).

Ordinary, always-on — no "Developer Mode" toggle, no gating (see
secure/cli/diagnostics.py's own module docstring for why). Read-only
display, same DISPLAY/ACTIONS split every other GUI screen in this
package follows (docs/DESIGN_SYSTEM.md): everything shown here comes
from secure_gui.data_access.fetch_performance_overview_now(), which
reads secure/diagnostics/'s own collectors — nothing here computes a
measurement itself, and nothing here writes to the database except
"Record Milestone", which — like every action screen in this package —
still runs through the caller-supplied `run_command` and the same CLI
subprocess (`secure diagnostics milestone record`) the terminal would
use, so it narrates into the same console transcript as everything
else.

Four sections, per the approved design: SYSTEM, SECURE, MODULES,
INTEGRATIONS / TOOLS — plus a WARNINGS strip at the top (diagnostics,
never security alerts — see secure/diagnostics/budgets.py's own
docstring) and a Refresh action.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List

from secure_gui.components import resolve_fonts
from secure_gui.data_access import PerformanceOverview, fetch_performance_overview_now

RunCommand = Callable[[str, List[str], bool], None]

_MODULE_COLUMNS = ("module", "operation", "duration", "cpu", "observations", "findings", "error")
_MODULE_HEADINGS = {
    "module": "Module",
    "operation": "Op",
    "duration": "Duration",
    "cpu": "CPU",
    "observations": "Obs",
    "findings": "Findings",
    "error": "Error",
}


def _fmt_bytes(n) -> str:
    if n is None:
        return "(unavailable)"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024:
            return f"{value:.1f}{unit}" if unit != "B" else f"{int(value)}{unit}"
        value /= 1024
    return f"{value:.1f}PB"


def _system_text(overview: PerformanceOverview) -> str:
    hw, sh = overview.hardware, overview.system_health
    lines = [
        f"Mac model: {hw.mac_model or '(unavailable)'}    Architecture: {hw.architecture}",
        f"CPU: {hw.cpu_brand or '(unavailable)'}    "
        f"Cores: {hw.logical_cores or '?'} logical / {hw.physical_cores or '?'} physical",
        f"RAM: {_fmt_bytes(hw.total_ram_bytes)}    macOS: {hw.macos_version or '(unavailable)'}    "
        f"Python: {hw.python_version}",
        "",
        f"Load average (1/5/15m): {sh.load_avg_1m or '?'} / {sh.load_avg_5m or '?'} / {sh.load_avg_15m or '?'}",
        f"Memory free: {_fmt_bytes(sh.mem_free_bytes)}    Disk free: {_fmt_bytes(sh.disk_free_bytes)}",
        f"Battery/AC: {sh.battery_state or '(unavailable)'}    Thermal: {sh.thermal_pressure or '(unavailable)'}",
    ]
    unavailable = sorted(set(hw.unavailable) | set(sh.unavailable))
    if unavailable:
        lines.append("")
        lines.append(f"Unavailable on this platform: {', '.join(unavailable)}")
    return "\n".join(lines)


def _secure_text(overview: PerformanceOverview) -> str:
    su = overview.self_usage
    return "\n".join([
        f"PID: {su.pid}    Runtime: {su.runtime_seconds:.2f}s    CPU time: {su.cpu_time_seconds:.2f}s",
        f"Peak RSS: {_fmt_bytes(su.peak_rss_bytes)}    Threads (Python-level): {su.thread_count}",
        f"Database: {_fmt_bytes(su.db_size_bytes)}    Log: {_fmt_bytes(su.log_size_bytes)}",
        f"Total events: {su.events_count}    Total findings: {su.findings_count}",
    ])


def _integrations_tools_text(overview: PerformanceOverview) -> str:
    lines = []
    for name, health in overview.integration_health:
        version_note = f" (v{health.tool_version})" if health.tool_version else ""
        lines.append(f"{name:<14} {health.status.upper():<12}{version_note} — {health.detail}")
    lines.append("")
    lines.append("Development tools (process name / CPU% / RSS only):")
    if not overview.dev_tool_usage:
        lines.append("  (none configured)")
    for usage in overview.dev_tool_usage:
        if usage.process_count == 0:
            lines.append(f"  {usage.pattern:<14} not currently running")
        else:
            lines.append(
                f"  {usage.pattern:<14} {usage.process_count} process(es), "
                f"{usage.total_cpu_percent:.1f}% CPU, {_fmt_bytes(usage.total_rss_bytes)} RSS"
            )
    return "\n".join(lines)


def _warnings_text(overview: PerformanceOverview) -> str:
    if not overview.warnings:
        return "No configured performance budget exceeded."
    return "\n".join(f"[{w.kind}] {w.message}" for w in overview.warnings)


def open_performance_window(parent: tk.Misc, *, run_command: RunCommand) -> tk.Toplevel:
    """Open the Diagnostics -> Performance window."""
    fonts = resolve_fonts()

    win = tk.Toplevel(parent)
    win.title("Diagnostics — Performance")
    win.geometry("920x760")
    win.minsize(680, 480)

    state = {"overview": None}

    header = tk.Frame(win, padx=10, pady=8)
    header.pack(fill=tk.X)
    tk.Label(header, text="Diagnostics — Performance", font=fonts["title"]).pack(side=tk.LEFT)
    tk.Label(
        header,
        text="Diagnostics only — never a security finding.\nMeasurement never changes any scan's own results.",
        font=fonts["small"],
        fg="#888",
        justify="right",
    ).pack(side=tk.RIGHT)

    toolbar = tk.Frame(win, padx=10)
    toolbar.pack(fill=tk.X)
    tk.Button(toolbar, text="Refresh", command=lambda: _reload()).pack(side=tk.LEFT)
    tk.Button(toolbar, text="Record Milestone…", command=lambda: _record_milestone()).pack(
        side=tk.LEFT, padx=(8, 0)
    )

    # Scrollable body — same canvas+scrollbar pattern secure_gui.py's
    # own category panel uses, since this window can grow taller than
    # the screen once the module table has real rows.
    canvas = tk.Canvas(win, highlightthickness=0)
    vsb = ttk.Scrollbar(win, orient="vertical", command=canvas.yview)
    body = tk.Frame(canvas)
    body.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.create_window((0, 0), window=body, anchor="nw")
    canvas.configure(yscrollcommand=vsb.set)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=(0, 10))
    vsb.pack(side=tk.LEFT, fill=tk.Y, pady=(0, 10))

    def _section(title: str) -> tk.LabelFrame:
        box = tk.LabelFrame(body, text=title, padx=8, pady=6, font=fonts["body_bold"])
        box.pack(fill=tk.X, pady=(0, 8), padx=(0, 10))
        return box

    warnings_box = _section("WARNINGS")
    warnings_label = tk.Label(warnings_box, text="", font=fonts["body"], justify="left", anchor="w")
    warnings_label.pack(fill=tk.X)

    system_box = _section("SYSTEM")
    system_label = tk.Label(system_box, text="", font=fonts["small"], justify="left", anchor="w")
    system_label.pack(fill=tk.X)

    secure_box = _section("SECURE")
    secure_label = tk.Label(secure_box, text="", font=fonts["small"], justify="left", anchor="w")
    secure_label.pack(fill=tk.X)

    modules_box = _section("MODULES")
    modules_tree = ttk.Treeview(
        modules_box, columns=_MODULE_COLUMNS, show="headings", selectmode="none", height=10
    )
    for col in _MODULE_COLUMNS:
        modules_tree.heading(col, text=_MODULE_HEADINGS[col])
    modules_tree.column("module", width=140, anchor="w")
    modules_tree.column("operation", width=70, anchor="w")
    modules_tree.column("duration", width=90, anchor="e")
    modules_tree.column("cpu", width=80, anchor="e")
    modules_tree.column("observations", width=80, anchor="e")
    modules_tree.column("findings", width=80, anchor="e")
    modules_tree.column("error", width=200, anchor="w")
    modules_tree.pack(fill=tk.X)

    tools_box = _section("INTEGRATIONS / TOOLS")
    tools_label = tk.Label(tools_box, text="", font=fonts["small"], justify="left", anchor="w")
    tools_label.pack(fill=tk.X)

    def _reload() -> None:
        try:
            overview = fetch_performance_overview_now()
        except Exception as exc:  # noqa: BLE001 — surfaced to the user, not swallowed
            warnings_label.configure(text=f"Could not load performance data: {exc}")
            return

        state["overview"] = overview
        warnings_label.configure(text=_warnings_text(overview))
        system_label.configure(text=_system_text(overview))
        secure_label.configure(text=_secure_text(overview))
        tools_label.configure(text=_integrations_tools_text(overview))

        modules_tree.delete(*modules_tree.get_children())
        for run in overview.module_runs:
            cpu = f"{run.cpu_time_seconds:.3f}s" if run.cpu_time_seconds is not None else "?"
            obs = run.observations_processed if run.observations_processed is not None else "?"
            find = run.findings_produced if run.findings_produced is not None else "?"
            modules_tree.insert(
                "", tk.END,
                values=(run.module, run.operation, f"{run.duration_seconds:.3f}s", cpu, obs, find, run.error or ""),
            )

    def _record_milestone() -> None:
        from tkinter import simpledialog

        label = simpledialog.askstring("Record Milestone", "Label for this milestone (e.g. \"Phase 30\"):", parent=win)
        if not label:
            return
        run_command(
            f'Record Performance Milestone… ("{label}")',
            ["diagnostics", "milestone", "record", label],
            False,
        )

    _reload()
    return win
