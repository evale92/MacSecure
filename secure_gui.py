"""
secure_gui.py — a small desktop control panel for the Secure CLI.

This is a thin GUI wrapper around the existing `secure` command-line
tool (see secure.cli) — it doesn't add any new capability. Buttons
are grouped into categories (the same categories the CLI already
covers), and clicking one runs the exact same command you'd type
yourself. The console pane on the right shows the command that ran
and the real stdout/stderr/exit code that came back from Terminal —
nothing is faked or summarized. Every `scan` command (plus `check`,
`snapshot`, and `bluetooth state`) deliberately exits 1 when it finds
something worth reviewing — that's the CLI contract, so it stays
scriptable from cron — and the GUI reports that case as "findings
above worth reviewing," not as a failure; see Command.nonzero_is_finding
and _execute()'s docstring below for exactly which commands that
applies to and why.

Categories -> commands:

    Identity & Setup   -> secure init --role server
                          secure init --role workstation
    Status             -> secure status
    Security Posture   -> secure check
                          secure check --quick
    Continuity         -> secure snapshot
    Device Inventory   -> secure inventory scan
                          secure inventory list
                          secure inventory name <id> "Name"
                          secure inventory mark <id> known|unknown
                          secure inventory prune
    Active Connections -> secure connections scan
                          secure connections endpoints
                          secure connections mark <id> known|unknown
    Listening Services -> secure listening scan
                          secure listening list
                          secure listening mark <id> known|unknown
    ARP Watch          -> secure arpwatch scan
                          secure arpwatch list
                          secure arpwatch mark <id> known|unknown
    Wi-Fi Security     -> secure wifi scan
                          secure wifi list
                          secure wifi mark <id> known|unknown
                          secure wifi alerts
                          secure wifi mark-alert <id> known|unknown
    Bluetooth          -> secure bluetooth scan
                          secure bluetooth list
                          secure bluetooth mark <id> trusted|untrusted
                          secure bluetooth alerts
                          secure bluetooth mark-alert <id> known|unknown
                          secure bluetooth state
                          secure bluetooth ble scan
                          secure bluetooth ble list
                          secure bluetooth ble mark <id> trusted|untrusted
                          secure bluetooth ble alerts
                          secure bluetooth ble mark-alert <id> known|unknown
    Process &            secure persistence scan
      Persistence      -> secure persistence processes
                          secure persistence mark-process <id> known|unknown
                          secure persistence items
                          secure persistence mark-item <id> known|unknown
                          secure persistence alerts
                          secure persistence mark-alert <id> known|unknown
    File Integrity     -> secure fileintegrity scan
                          secure fileintegrity watch-list
                          secure fileintegrity watch-add <path>
                          secure fileintegrity files
                          secure fileintegrity mark-file <id> known|unknown
                          secure fileintegrity events
                          secure fileintegrity alerts
                          secure fileintegrity mark-alert <id> known|unknown
    Correlation        -> secure correlate run
                          secure correlate list
                          secure correlate mark-alert <id> known|unknown
    Downloads & Logs   -> secure downloads
                          secure downloads --flagged
                          secure loghunt
    Integrations       -> secure integrations osquery status|scan|alerts
                          secure integrations yarax status|rulesets|alerts
                          secure integrations yarax scan-fim-alerts|scan-suspicious
                          secure integrations sigma status|rules|scan|alerts
                          secure integrations suricata status|scan|alerts
                          secure integrations zeek status|scan
    Correlation Chains -> secure correlate chains run
                          secure correlate chains list
    Validation &       -> secure validate run|list
      Detection           secure detect list
    Threat Intel &     -> secure threatintel providers|history
      DFIR                secure dfir status|list
    AI & Performance   -> secure ai status|roles|history
                          secure diagnostics history
    Investigate        -> secure investigate types
                          secure investigate show <type> <key>
    Event Log          -> secure add-note "..."

    Run Everything      A single button (top of the category list) that
                        runs `secure run-all` — every scan above
                        (including a file integrity scan), back-to-back
                        in one process, then a correlation pass over the
                        result. See "Cross-Module Correlation" and "File
                        Integrity Monitoring" in PROJECT_NOTES.md.

Commands run one at a time, in click order — there's a single
background worker thread pulling jobs off a queue, not one thread per
click. That's on purpose: the "Run Full Check" button runs
`secure check`, which includes the one check that talks to the
network and can take several seconds, and without serializing,
clicking other buttons while it's running could make their (faster)
output appear in the console before the full check's own output,
which is confusing to read back. The status line under the app title
always shows what's currently running.

Every click is logged to the console the instant it happens (tagged
"click", timestamped), separately from the "$ ..." line that appears
when the command actually starts — so if you click something while
another command is still running, you can see exactly when you
clicked it versus when it started. Clicking a button while something
else is running prompts you: stop the running command and run the new
one immediately, queue the new one to run right after, or don't run
it. Choosing "stop" sends the running process a terminate signal (no
sudo, no force-kill unless it outlives the command's timeout, 60s by
default) rather than
silently letting two commands race each other.

Three buttons can touch the network: the pending-updates check (talks
to Apple's servers), "Scan Network" under Device Inventory (pings hosts
on this Mac's own local subnet only — never anything outside it), and
"AI Provider Status", which sends a liveness GET (with the configured
auth header, no user data) to each configured AI host, normally on this
Mac, and does nothing when none is configured. Nothing here does anything the CLI itself
couldn't already do — see PROJECT_NOTES.md ("What's deliberately NOT
here yet") for what this project intentionally does not include yet.

The "Update" button next to "Copy" restarts this GUI process in place
so it picks up whatever code is currently on disk in this project
folder, without you closing and reopening the window yourself. It does
NOT fetch anything itself — it's meant to pair with Syncthing (or any
other folder-sync tool) syncing this project directory across your
machines in the background; see "Keeping the app itself up to date" in
PROJECT_NOTES.md.

Run it:
    cd Secure
    python3 secure_gui.py

    It automatically uses .venv/bin/python if a .venv exists next to
    this file (create one first — see PROJECT_NOTES.md), otherwise it
    falls back to whatever `python3` launched the GUI.

Requires: Tkinter, which ships with the standard python.org macOS
installer. If you installed Python via Homebrew and get a
"No module named _tkinter" / "ModuleNotFoundError: tkinter" error,
run: brew install python-tk

Phase 14.5 Stage D — this file is FROZEN from new per-category
screens. Every category above (Device Inventory, Active Connections,
...) stays exactly as it is; no new category boxes should be added
here going forward. New GUI work belongs in secure_gui/ instead,
built on its DataTable + EvidencePanel pattern (see
secure_gui/alerts_view.py, the Product Phase 12 pilot, and
secure_gui/baseline_view.py, its Phase 14.5 Stage D counterpart for
Baseline & Anomalies) and wired in here via one small launcher
method + button, the same way `_build_alerts_launcher`/
`_build_baseline_launcher` are — never by growing this file's
category list or its `_categories()` method further. This keeps this
script shrinking toward "thin launcher + job queue + console," its
actually-durable job, while every new investigative screen goes
through the newer, testable, structured pattern. See PROJECT_NOTES.md's
Phase 14.5 change-log entry for the full rationale.
"""

from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, scrolledtext, simpledialog
from typing import Callable, List, Optional

from secure_gui import tokens
from secure_gui.alerts_view import open_alerts_window
from secure_gui.baseline_view import open_baseline_window
from secure_gui.performance_view import open_performance_window
from secure_gui.agent_view import open_agent_window
from secure_gui.change_requests_view import open_change_requests_window
from secure_gui.remediation_view import open_remediation_window
from secure_gui.components import confirm_action, mark_state_dialog, resolve_fonts
from secure_gui.tile_view import TileView, TileCategory
from secure_gui.view_models import (
    COMMAND_CATALOG,
    DEFAULT_TIMEOUT_SECONDS,
    INVESTIGATE,
    INVESTIGATE_ENTITY_TYPES,
    PRUNE_CONFIRM_BODY,
    PRUNE_CONFIRM_TITLE,
    confirmed_args,
    investigate_show_request,
)

PROJECT_ROOT = Path(__file__).resolve().parent


def _python_executable() -> str:
    """Prefer the project's own .venv, fall back to whatever ran this GUI."""
    venv_python = PROJECT_ROOT / ".venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


# Trackpad pixels that must accumulate before one scroll unit is emitted.
# Higher = slower/less sensitive. Tk 9 trackpads fire many tiny deltas.
TRACKPAD_THRESHOLD = 34

CONSOLE_W = 620
MIN_W = 560


@dataclass
class Command:
    label: str
    # Returns the argv list to run, or None to cancel (e.g. a dialog
    # was dismissed). Deferred to click-time so things like "Add
    # Note" can prompt for input first.
    build_args: Callable[[], Optional[List[str]]]
    # True for commands whose CLI exit code deliberately doubles as a
    # "was there anything worth reviewing" signal — every `scan`
    # (and `check`/`snapshot`/`state`) command in the CLI returns
    # exit 1 when it finds something new or notable, purely so it stays
    # scriptable (e.g. from cron). That's the right contract for a
    # command line, but a GUI user reading "exit code 1" naturally reads
    # it as "this failed," which it didn't — the scan ran fine and did
    # exactly what it's supposed to do. When this is True, exit code 1
    # is reported as a finding to review, not an error; anything other
    # than 0 or 1 is still always reported as a real failure. Left
    # False (the default) for commands where a nonzero exit genuinely
    # does mean something went wrong (an id wasn't found, a test
    # failed, etc.) — see _execute()'s docstring for the exact
    # distinction.
    nonzero_is_finding: bool = False
    # Seconds before _execute kills the job. Catalog entries override it
    # (secure_gui/view_models.py COMMAND_CATALOG); everything else keeps
    # the long-standing 60 s.
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS


@dataclass
class Category:
    title: str
    commands: List[Command] = field(default_factory=list)


class SecureGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure — Control Panel")
        self.geometry("870x640")
        self.minsize(730, 480)

        # View mode: "list" (default) or "tiles"
        self._view_mode = "list"
        self._categories_frame: Optional[tk.Widget] = None
        self._tile_view: Optional[tk.Widget] = None
        self._console_visible = True
        self._console_space = True
        self._console_pane: Optional[tk.Widget] = None
        self._view_container: Optional[tk.Widget] = None

        # Commands run one at a time, in the order they were clicked.
        # Every button click just enqueues a job here; a single
        # background worker thread pulls jobs off and runs them
        # sequentially. Without this, two overlapping clicks (e.g. a
        # slow network-dependent check started, then a fast one right
        # after) can finish out of order and their output would land
        # in the console out of order too — confusing, since the
        # console is supposed to read like a real terminal session.
        # (label, argv, nonzero_is_finding, timeout_seconds)
        self._job_queue: "queue.Queue[tuple[str, List[str], bool, int]]" = queue.Queue()

        # The worker thread only ever talks back to the GUI through
        # this queue — Tkinter widgets aren't thread-safe, so no
        # widget is ever touched from the worker thread directly.
        self._queue: "queue.Queue[tuple[str, str]]" = queue.Queue()

        # Tracks what's currently running, so a click while something
        # is busy can offer to stop it. Only ever read/written on the
        # main thread (set in _set_busy/_set_idle, which only run from
        # _poll_queue), so no lock is needed for these two.
        self._busy = False
        self._current_label: Optional[str] = None

        # The live subprocess for whatever command is currently
        # running, guarded by a lock because it's written from the
        # worker thread but can be read/terminated from the main
        # thread (when the user chooses "stop it now"). _stop_requested
        # records that a stop was asked for, so _execute can report
        # "stopped by you" instead of a raw exit code.
        self._process_lock = threading.Lock()
        self._current_process: Optional[subprocess.Popen] = None
        self._stop_requested = False

        self._build_layout()
        self._poll_queue()

        threading.Thread(target=self._worker_loop, daemon=True).start()

    # ---------- layout ----------

    def _build_layout(self) -> None:
        # Fonts must be resolved after this Tk root exists (Tk's named
        # fonts don't exist beforehand) — see resolve_fonts()'s
        # docstring. Ordinary UI prose (titles, headings, labels,
        # buttons, dialogs) uses the system's actual default UI font;
        # only technical telemetry (the console, and later raw
        # evidence) uses the monospace font — see docs/DESIGN_SYSTEM.md.
        self._fonts = resolve_fonts()

        outer = tk.Frame(self, padx=10, pady=10)
        outer.pack(fill=tk.BOTH, expand=True)
        self._outer = outer

        # Left: cascading category -> button panel.
        left = tk.Frame(outer)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        self._left_pane = left

        # Title and view toggle
        title_frame = tk.Frame(left)
        title_frame.pack(anchor="w", fill=tk.X, pady=(0, 6))

        tk.Label(title_frame, text="Secure", font=self._fonts["title"]).pack(side=tk.LEFT, anchor="w")

        # View toggle button
        self._view_toggle_btn = self._flat_button(title_frame, "📋 List", self._toggle_view)
        self._view_toggle_btn.pack(side=tk.RIGHT, anchor="e")

        # Console toggle — only meaningful in tile view, where the console
        # is detached into its own window. Hidden in list view.
        self._console_btn = self._flat_button(title_frame, "🖥 Console", self._toggle_console_window)

        self.update_button = self._flat_button(title_frame, "⟳ Update", self._update_and_restart)

        # A Label + popup Menu, not tk.OptionMenu: OptionMenu is a Menubutton
        # and macOS draws it with the native style, ignoring bg/fg — which
        # left it an unreadable blank box in the dark themes.
        self._theme_var = tk.StringVar(value=tokens.theme_name())
        self._theme_btn = self._flat_button(
            title_frame, f"🎨 {tokens.theme_name()}", self._open_theme_menu
        )
        self._theme_menu = tk.Menu(self, tearoff=0)
        for _name in tokens.THEMES:
            self._theme_menu.add_command(
                label=_name, command=lambda n=_name: self._on_theme_change(n)
            )

        self.update_button = self._flat_button(title_frame, "⟳ Update", self._update_and_restart)

        tk.Label(
            left,
            text="Foundation control panel\n(plumbing + Phase 2 posture\nchecks — no live monitoring)",
            font=self._fonts["small"],
            fg="#666",
            justify="left",
        ).pack(anchor="w", pady=(0, 6))

        self.status_var = tk.StringVar(value="Idle")
        tk.Label(
            left,
            textvariable=self.status_var,
            font=self._fonts["body_bold"],
            fg=tokens.COLORS["status_success"],
            justify="left",
            wraplength=200,
        ).pack(anchor="w", pady=(0, 12))

        # Categories go in a scrollable area, not packed directly into
        # `left` — there are enough categories now (and more will get
        # added as later phases land) that they no longer reliably fit
        # in the window's fixed height. Without this, categories past
        # whatever the window happens to be tall enough for are simply
        # invisible, with no error and no visual hint they exist — which
        # looks exactly like "the app isn't updating" from the outside.
        category_area = tk.Frame(left)
        category_area.pack(fill=tk.BOTH, expand=True)

        self._canvas = tk.Canvas(category_area, highlightthickness=0, width=230)
        self._canvas.pack(fill=tk.BOTH, expand=True)

        self._categories_window_id: Optional[int] = None
        self._category_area = category_area

        def _on_mousewheel(event):
            # macOS reports small delta values directly (no /120 scaling
            # like Windows) — this only needs to feel right on macOS,
            # the only platform this app targets.
            self._canvas.yview_scroll(int(-1 * event.delta), "units")

        def _bind_mousewheel_recursive(widget) -> None:
            # <MouseWheel> only fires on the exact widget under the
            # cursor, and buttons/labels inside the canvas are real
            # separate widgets, not part of the canvas's own drawing —
            # so scrolling only works while hovering bare canvas
            # background unless every descendant gets this binding too.
            widget.bind("<MouseWheel>", _on_mousewheel)
            for child in widget.winfo_children():
                _bind_mousewheel_recursive(child)

        # wheel handled app-wide by _on_global_wheel

        # Build initial list view
        self._rebuild_categories_view()

        if self._categories_frame is not None:
            pass  # wheel handled app-wide by _on_global_wheel

        # Right: console.
        right = tk.Frame(outer)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._console_pane = right

        header = tk.Frame(right)
        header.pack(fill=tk.X)
        tk.Label(header, text="Console", font=self._fonts["heading"]).pack(side=tk.LEFT)
        tk.Button(header, text="Clear", command=self._clear_console).pack(side=tk.RIGHT)
        self.copy_button = tk.Button(header, text="Copy", command=self._copy_console)
        self.copy_button.pack(side=tk.RIGHT, padx=(0, 6))

        # The console shows real command lines and real stdout/stderr
        # text — technical telemetry, not UI prose — so it keeps the
        # monospace font even though the rest of the window now uses
        # the system UI font. See docs/DESIGN_SYSTEM.md.
        self.console = tk.Text(
            right,
            bg=tokens.COLORS["console_bg"],
            fg=tokens.COLORS["console_fg"],
            insertbackground=tokens.COLORS["console_fg"],
            font=self._fonts["mono"],
            wrap=tk.WORD,
        )
        self.console.pack(fill=tk.BOTH, expand=True, pady=(6, 0))
        self.console.configure(state=tk.DISABLED)

        self.console.tag_config("cmd", foreground=tokens.COLORS["console_cmd"])
        self.console.tag_config("stdout", foreground=tokens.COLORS["console_fg"])
        self.console.tag_config("stderr", foreground=tokens.COLORS["console_stderr"])
        self.console.tag_config("meta", foreground=tokens.COLORS["console_meta"])
        self.console.tag_config("click", foreground=tokens.COLORS["console_click"])

        self._log(f"Python:  {_python_executable()}", "meta")
        self._log(f"Project: {PROJECT_ROOT}", "meta")
        self._log("Ready.\n", "meta")

        # Console exists now — apply the mode the current view wants.
        self._apply_console_mode()
        self._apply_theme()

        for seq in ("<MouseWheel>", "<Shift-MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_all(seq, self._on_global_wheel)
        # Tk 9 on macOS: two-finger trackpad scrolling arrives here, NOT as
        # <MouseWheel>. Without this the trackpad does nothing at all.
        self.bind_all("<TouchpadScroll>", self._on_touchpad_scroll)
        # Belt and braces: bind the canvas itself too. bind_all fires at the
        # "all" tag, which some macOS Tk builds skip for scroll events.
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self._canvas.bind(seq, self._on_global_wheel)
        self._canvas.bind("<TouchpadScroll>", self._on_touchpad_scroll)

        # Build initial list view
        self._rebuild_categories_view()

    def _toggle_view(self) -> None:
        """Switch between list and tile views."""
        if self._view_mode == "list":
            self._view_mode = "tiles"
            self._view_toggle_btn.config(text="🔲 Tiles")
            # Tiles get the full width; the console is behind the toggle.
            self._console_visible = False
        else:
            self._view_mode = "list"
            self._view_toggle_btn.config(text="📋 List")
        self._rebuild_categories_view()

    def _rebuild_categories_view(self) -> None:
        """Clear and rebuild the categories view based on current mode."""
        # Tear down the tile view if it is up; it is a real packed widget,
        # not a canvas item, so canvas.delete() would leave it on screen.
        if self._tile_view is not None:
            self._tile_view.destroy()
            self._tile_view = None
        self._canvas.delete("all")
        self._categories_frame = None

        if self._view_mode == "list":
            # Restore the scrolling canvas the tile view hid.
            if not self._canvas.winfo_ismapped():
                self._canvas.pack(fill=tk.BOTH, expand=True)
            self._build_list_view()
        else:
            self._build_tile_view()

        self._apply_console_mode()

    # ---- console detach/reattach (tile view only) -------------------------
    #
    # Tk cannot reparent a widget, so instead of building a second console
    # and mirroring output into it, the existing console pane is promoted
    # to a real top-level window with `wm manage` and returned with
    # `wm forget`. Same widget, same text buffer, no duplicated logging.

    # ---- scrolling ---------------------------------------------------
    #
    # Per-widget <MouseWheel> bindings are fragile here: every tile, label
    # and dropdown is its own widget, and dropdowns are created on hover
    # after any recursive bind has already run. One bind_all handler on
    # the toplevel sees every wheel event, walks up from whatever is under
    # the pointer, and scrolls the first scrollable ancestor it finds.

    def _scrollables(self):
        """Widgets the wheel may scroll, most specific first."""
        targets = [getattr(self, "console", None)]
        if self._view_mode == "tiles" and self._tile_view is not None:
            targets.append(getattr(self._tile_view, "canvas", None))
        else:
            targets.append(getattr(self, "_canvas", None))
        return [t for t in targets if t is not None]

    def _on_global_wheel(self, event):
        # Record every arrival, even ones that scroll nothing — an empty log
        # means no handler is firing at all, which is a different bug.
        if getattr(self, "_wheel_seen", 0) < 40:
            self._wheel_seen = getattr(self, "_wheel_seen", 0) + 1
            try:
                with open("/tmp/secure_wheel.log", "a") as fh:
                    fh.write(f"ARRIVED delta={getattr(event,'delta','?')!r} "
                             f"num={getattr(event,'num','?')!r} "
                             f"widget={getattr(event,'widget','?')}\n")
            except OSError:
                pass
        targets = self._scrollables()
        if not targets:
            return
        widget = event.widget
        # Walk up from the widget under the cursor looking for a target.
        node = widget
        for _ in range(40):
            if node in targets:
                self._wheel_scroll(node, event)
                return "break"
            parent_name = node.winfo_parent() if hasattr(node, "winfo_parent") else ""
            if not parent_name:
                break
            node = node.nametowidget(parent_name)
        # Pointer is over the pane but not inside any target's subtree
        # (e.g. the tile grid's padding) — scroll the active view's canvas.
        fallback = self._fallback_target()
        if fallback is not None:
            self._wheel_scroll(fallback, event)
        return "break"

    def _wheel_scroll(self, canvas, event) -> None:
        """Scroll `canvas` from a wheel/trackpad event.

        macOS trackpads are awkward here: delta can be a float, can be very
        small, and for a slow two-finger drag can even arrive as 0. Treating
        0 as "no scroll" is why this silently did nothing.
        """
        delta = getattr(event, "delta", 0) or 0
        num = getattr(event, "num", None)

        if num == 4:
            step = -1
        elif num == 5:
            step = 1
        else:
            try:
                d = float(delta)
            except (TypeError, ValueError):
                d = 0.0
            if abs(d) >= 120:          # Windows-style notches
                step = int(-d / 120) or (-1 if d > 0 else 1)
            elif d:                     # macOS: small signed values
                step = -1 if d > 0 else 1
            else:
                # delta == 0 on a slow trackpad drag. Fall back to the
                # accumulated direction of the previous event.
                step = getattr(self, "_last_wheel_step", 0)
                if not step:
                    return
        self._last_wheel_step = step

        # Respect "natural scrolling": Tk already reports the sign the user
        # configured, so no inversion here on purpose.
        try:
            canvas.yview_scroll(step, "units")
        except tk.TclError:
            pass

        # Diagnostics to a file, not the console: the console is read-only
        # output, and a file can be read back without any UI interaction.
        if getattr(self, "_wheel_debug", 0) < 40:
            self._wheel_debug = getattr(self, "_wheel_debug", 0) + 1
            try:
                with open("/tmp/secure_wheel.log", "a") as fh:
                    fh.write(f"delta={delta!r} num={num!r} step={step} "
                             f"target={canvas.winfo_class()} "
                             f"widget={getattr(event, 'widget', '?')}\n")
            except OSError:
                pass

    # ---- Tk 9 trackpad ---------------------------------------------------
    #
    # Tk 9.0 stopped sending <MouseWheel> for two-finger trackpad scrolling
    # on aqua and win32; it sends <TouchpadScroll> instead. Native widgets
    # got updated class bindings, but a canvas+inner-frame scroll region
    # relies on application bindings, so the events were dropped entirely.
    #
    # <TouchpadScroll> packs BOTH axes into event.delta: high 16 bits are
    # deltaX, low 16 bits are deltaY, each a signed 16-bit value.

    @staticmethod
    def _unpack_touchpad_delta(raw):
        try:
            v = int(raw) & 0xFFFFFFFF
        except (TypeError, ValueError):
            return 0, 0
        dy = v & 0xFFFF
        dx = (v >> 16) & 0xFFFF
        if dy >= 0x8000:
            dy -= 0x10000
        if dx >= 0x8000:
            dx -= 0x10000
        return dx, dy

    def _on_touchpad_scroll(self, event):
        dx, dy = self._unpack_touchpad_delta(getattr(event, "delta", 0))
        if dy == 0:
            return "break"

        # Trackpads fire many high-resolution events; accumulate so one
        # scroll unit is emitted per few pixels rather than per event.
        self._tp_accum = getattr(self, "_tp_accum", 0) + dy
        if abs(self._tp_accum) < TRACKPAD_THRESHOLD:
            return "break"
        step = -1 if self._tp_accum > 0 else 1
        self._tp_accum = 0

        target = self._target_under(getattr(event, "widget", None)) or self._fallback_target()
        if target is not None:
            try:
                target.yview_scroll(step, "units")
            except tk.TclError:
                pass
        if getattr(self, "_wheel_seen", 0) < 40:
            self._wheel_seen = getattr(self, "_wheel_seen", 0) + 1
            try:
                with open("/tmp/secure_wheel.log", "a") as fh:
                    fh.write(f"TOUCHPAD raw={getattr(event,'delta','?')!r} "
                             f"dx={dx} dy={dy} step={step}\n")
            except OSError:
                pass
        return "break"

    def _target_under(self, widget):
        """First scrollable ancestor of `widget`, or None."""
        targets = self._scrollables()
        node = widget
        for _ in range(40):
            if node is None:
                return None
            if node in targets:
                return node
            parent = node.winfo_parent() if hasattr(node, "winfo_parent") else ""
            if not parent:
                return None
            try:
                node = node.nametowidget(parent)
            except tk.TclError:
                return None
        return None

    def _fallback_target(self):
        """The pane-level scrollable for the active view."""
        if self._view_mode == "tiles" and self._tile_view is not None:
            return getattr(self._tile_view, "canvas", None)
        return getattr(self, "_canvas", None)

    def _flat_button(self, parent, text, command):
        """A button that actually honours theme colours.

        macOS draws tk.Button with the native Aqua style and ignores `bg`,
        so in a dark theme the text goes light on a light chrome button and
        becomes unreadable. A Label with bindings renders exactly what we
        ask for on every platform.
        """
        lbl = tk.Label(
            parent, text=text, font=self._fonts["body"],
            padx=10, pady=3, relief=tk.FLAT, borderwidth=1, cursor="hand2",
        )
        lbl.bind("<Button-1>", lambda e: command())
        lbl.bind("<Enter>", lambda e: lbl.configure(bg=tokens.ui("btn_active")))
        lbl.bind("<Leave>", lambda e: lbl.configure(
            bg=tokens.ui("btn_active") if getattr(lbl, "_on", False) else tokens.ui("btn_bg")))
        lbl._on = False
        lbl._is_chrome = True      # skipped by _recolour_tree
        return lbl

    def _open_theme_menu(self) -> None:
        """Post the theme menu under the button.

        No grab_release() in a finally here: on macOS that fires while the
        menu is still up and dismisses it immediately, which looks exactly
        like the button doing nothing.
        """
        b = self._theme_btn
        x = b.winfo_rootx()
        y = b.winfo_rooty() + b.winfo_height() + 2
        try:
            self._theme_menu.tk_popup(x, y)
        except tk.TclError:
            self._theme_menu.post(x, y)

    def _on_theme_change(self, name: str) -> None:
        tokens.set_theme(name)
        self._theme_var.set(name)
        self._theme_btn.configure(text=f"🎨 {name}")
        self._apply_theme()
        self._rebuild_categories_view()

    def _apply_theme(self) -> None:
        """Recolour the window chrome. Severity/status colours are left
        alone on purpose — they are a backend vocabulary, not decoration."""
        bg = tokens.ui("app_bg")
        fg = tokens.ui("text")
        self.configure(bg=bg)
        for w in (self._outer, getattr(self, "_category_area", None)):
            if w is not None:
                try:
                    w.configure(bg=bg)
                except tk.TclError:
                    pass
        try:
            self._canvas.configure(bg=bg)
        except tk.TclError:
            pass
        for btn in (self._view_toggle_btn, self._console_btn, self.update_button):
            btn.configure(
                bg=tokens.ui("btn_active") if getattr(btn, "_on", False) else tokens.ui("btn_bg"),
                fg=fg, highlightbackground=tokens.ui("tile_border"),
            )
        self._theme_btn.configure(bg=tokens.ui("btn_bg"), fg=fg,
                                  highlightbackground=tokens.ui("tile_border"))
        self._theme_menu.configure(bg=tokens.ui("panel_bg"), fg=fg,
                                   activebackground=tokens.ui("accent"),
                                   activeforeground=tokens.ui("accent_text"))
        self._recolour_tree(self._outer, bg, fg)

    def _recolour_tree(self, widget, bg: str, fg: str) -> None:
        for child in widget.winfo_children():
            cls = child.winfo_class()
            try:
                if cls in ("Frame", "Labelframe"):
                    child.configure(bg=bg)
                elif cls == "Label":
                    if getattr(child, "_is_chrome", False):
                        continue   # button-styled labels keep their own colours
                    child.configure(bg=bg, fg=fg)
            except tk.TclError:
                pass
            self._recolour_tree(child, bg, fg)

    def _apply_console_mode(self) -> None:
        """List view keeps the console docked; tile view hides it behind a
        toggle. The console is always a side panel of the main window —
        never a floating window that can cover the tiles."""
        if getattr(self, "_console_pane", None) is None:
            return  # layout still being built; called again at the end
        self.update_button.pack_forget()
        # In tile view the left pane owns the full width (there is no docked
        # console), so the tile grid centres against the window rather than
        # against a narrow category column.
        # pack_configure, NOT pack_forget+pack: re-packing appends the pane to
        # the end of the parent's pack order, which flips it to the right of
        # the console. pack_configure changes options and keeps the position.
        if self._view_mode == "tiles":
            # padx=0: the (0,10) right-only padding used in list view to
            # separate the categories from the console made the tile
            # gutters asymmetric by exactly 10px.
            self._left_pane.pack_configure(fill=tk.BOTH, expand=True, padx=0)
        else:
            self._left_pane.pack_configure(fill=tk.Y, expand=False, padx=(0, 10))
        if self._view_mode == "tiles":
            self._console_btn.pack(side=tk.RIGHT, anchor="e", padx=(0, 6))
            if self._console_visible:
                self._show_console_panel()
            else:
                self._hide_console_panel()
        else:
            self._console_btn.pack_forget()
            self._console_visible = True
            self._show_console_panel()
        # Packed last -> leftmost of the right-aligned button group.
        self.update_button.pack(side=tk.RIGHT, anchor="e", padx=(0, 6))
        self._theme_btn.pack_forget()
        self._theme_btn.pack(side=tk.RIGHT, anchor="e", padx=(0, 6))

    def _show_console_panel(self) -> None:
        if not self._console_pane.winfo_manager():
            self._console_pane.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._console_btn._on = True
        self._console_btn.configure(relief=tk.SOLID, bg=tokens.ui("btn_active"))
        self._grow_for_console(True)

    def _hide_console_panel(self) -> None:
        if self._console_pane.winfo_manager():
            self._console_pane.pack_forget()
        self._console_btn._on = False
        self._console_btn.configure(relief=tk.FLAT, bg=tokens.ui("btn_bg"))
        self._grow_for_console(False)

    def _grow_for_console(self, showing: bool) -> None:
        """Widen/narrow the window so the console sits beside the tiles
        instead of on top of them."""
        self.update_idletasks()
        try:
            w = self.winfo_width()
            h = self.winfo_height()
            x = self.winfo_x()
            y = self.winfo_y()
        except tk.TclError:
            return
        if w <= 1:
            return
        if showing and not self._console_space:
            self.geometry(f"{w + CONSOLE_W}x{h}+{x}+{y}")
            self._console_space = True
        elif not showing and self._console_space:
            self.geometry(f"{max(w - CONSOLE_W, MIN_W)}x{h}+{x}+{y}")
            self._console_space = False

    def _toggle_console_window(self) -> None:
        """Toggle the console side panel (tile view only)."""
        self._console_visible = not self._console_visible
        if self._console_visible:
            self._show_console_panel()
        else:
            self._hide_console_panel()

    def _build_list_view(self) -> None:
        """Build the traditional list-based button view."""
        categories_frame = tk.Frame(self._canvas)
        self._categories_frame = categories_frame

        def _on_frame_configure(_event=None):
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))

        def _on_canvas_configure(event):
            self._canvas.itemconfig(self._categories_window_id, width=event.width)

        categories_frame.bind("<Configure>", _on_frame_configure)
        self._canvas.bind("<Configure>", _on_canvas_configure)

        # Add special launchers
        self._build_alerts_launcher(categories_frame)
        self._build_baseline_launcher(categories_frame)
        self._build_performance_launcher(categories_frame)
        self._build_agent_launcher(categories_frame)
        self._build_remediation_launcher(categories_frame)

        # Add regular categories
        for category in self._categories():
            self._build_category(categories_frame, category)

        self._categories_window_id = self._canvas.create_window((0, 0), window=categories_frame, anchor="nw")

    def _build_tile_view(self) -> None:
        """Build the tile-based category view with hover dropdowns."""
        # Convert categories to TileCategory objects
        tile_categories = []
        for category in self._categories():
            # Pass build_args through UNCALLED — some commands open a
            # dialog to gather input, and that must happen on click,
            # not while the tile grid is being built.
            commands = [(cmd.label, cmd.build_args, cmd.nonzero_is_finding) for cmd in category.commands]
            tile_categories.append(TileCategory(category.title, commands))

        # TileView owns its own canvas + scrollbar, so it must NOT be
        # embedded in the outer scrolling canvas (a canvas inside a canvas
        # window gets no size and renders nothing). Pack it directly and
        # hide the list-view canvas instead.
        self._canvas.pack_forget()

        tile_view = TileView(
            self._category_area,
            tile_categories,
            self._run_command_from_tile,
            self._fonts,
        )
        tile_view.pack(fill=tk.BOTH, expand=True)
        self._tile_view = tile_view

    def _run_command_from_tile(self, label: str, build_args, nonzero_is_finding: bool) -> None:
        """Run a command chosen from the tile view.

        `build_args` is the Command's own deferred arg builder, passed
        through untouched so dialogs still prompt at click time.
        """
        cmd = Command(label, build_args, nonzero_is_finding)
        self._run_command(cmd)

    def _build_alerts_launcher(self, parent: tk.Widget) -> None:
        box = tk.LabelFrame(parent, text="Alerts", padx=8, pady=8, font=self._fonts["body_bold"])
        box.pack(fill=tk.X, pady=(0, 10))
        tk.Button(
            box,
            text="Open Alerts Table…",
            width=26,
            anchor="w",
            command=self._open_alerts_table,
        ).pack(fill=tk.X, pady=2)
        tk.Label(
            box,
            text="Every alert, all modules, one table.\nThe per-module alert lists below\nstill work exactly as before.",
            font=self._fonts["small"],
            fg="#666",
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

    def _open_alerts_table(self) -> None:
        """Open the Alerts DataTable pilot window (Product Phase 12).

        Reads are display-only, straight from the database — see
        secure_gui/data_access.py. Any action taken from that window
        (marking an alert known/unknown) is routed back through this
        method's `run_command` callback into the exact same
        Command/job-queue/console pipeline every other button already
        uses, so it's serialized with everything else and its result
        shows up in the same console transcript.
        """

        def run_command(label: str, args: List[str], nonzero_is_finding: bool) -> None:
            self._run_command(Command(label, (lambda a=args: a), nonzero_is_finding))

        open_alerts_window(self, run_command=run_command)

    def _build_baseline_launcher(self, parent: tk.Widget) -> None:
        box = tk.LabelFrame(
            parent, text="Baseline & Anomalies", padx=8, pady=8, font=self._fonts["body_bold"]
        )
        box.pack(fill=tk.X, pady=(0, 10))
        tk.Button(
            box,
            text="Open Baseline & Anomalies…",
            width=26,
            anchor="w",
            command=self._open_baseline_window,
        ).pack(fill=tk.X, pady=2)
        tk.Label(
            box,
            text="Behavioral baseline status and every recorded\n"
            "anomaly, across all modules. Exclude/freeze/reset\n"
            "an entity via `secure baseline ...` in a terminal.",
            font=self._fonts["small"],
            fg="#666",
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

    def _open_baseline_window(self) -> None:
        """Open the Baseline & Anomalies DataTable window (Phase 14.5
        Stage D). Same read-only-display / CLI-subprocess-for-actions
        split as _open_alerts_table() above — see that method's
        docstring.
        """

        def run_command(label: str, args: List[str], nonzero_is_finding: bool) -> None:
            self._run_command(Command(label, (lambda a=args: a), nonzero_is_finding))

        open_baseline_window(self, run_command=run_command)

    def _build_performance_launcher(self, parent: tk.Widget) -> None:
        box = tk.LabelFrame(
            parent, text="Diagnostics — Performance", padx=8, pady=8, font=self._fonts["body_bold"]
        )
        box.pack(fill=tk.X, pady=(0, 10))
        tk.Button(
            box,
            text="Open Performance Diagnostics…",
            width=26,
            anchor="w",
            command=self._open_performance_window,
        ).pack(fill=tk.X, pady=2)
        tk.Label(
            box,
            text="Hardware, system health, Secure's own resource\n"
            "use, per-module timing, and integration/tool\n"
            "status. Diagnostics only — never a security alert.",
            font=self._fonts["small"],
            fg="#666",
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

    def _open_performance_window(self) -> None:
        """Open the Diagnostics -> Performance window (Phase 30). Same
        read-only-display / CLI-subprocess-for-actions split as
        _open_baseline_window() above.
        """

        def run_command(label: str, args: List[str], nonzero_is_finding: bool) -> None:
            self._run_command(Command(label, (lambda a=args: a), nonzero_is_finding))

        open_performance_window(self, run_command=run_command)

    def _build_agent_launcher(self, parent: tk.Widget) -> None:
        box = tk.LabelFrame(parent, text="Agent — Repairs", padx=8, pady=8, font=self._fonts["body_bold"])
        box.pack(fill=tk.X, pady=(0, 10))
        tk.Button(
            box,
            text="Open Agent Repairs…",
            width=26,
            anchor="w",
            command=self._open_agent_window,
        ).pack(fill=tk.X, pady=2)
        tk.Button(
            box,
            text="Open Change Requests…",
            width=26,
            anchor="w",
            command=self._open_change_requests_window,
        ).pack(fill=tk.X, pady=2)
        tk.Label(
            box,
            text="Supervised, human-approved autonomous repair\n"
            "(Phase 31). A passing verification result is\n"
            "never authorization — you always approve.\n"
            "Change Requests (Phase 40) lists everything\n"
            "currently awaiting your decision.",
            font=self._fonts["small"],
            fg="#666",
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

    def _open_agent_window(self) -> None:
        """Open the Agent -> Repairs window (Phase 31). Same
        read-only-display / CLI-subprocess-for-actions split as
        _open_performance_window() above.
        """

        def run_command(label: str, args: List[str], nonzero_is_finding: bool) -> None:
            self._run_command(Command(label, (lambda a=args: a), nonzero_is_finding))

        open_agent_window(self, run_command=run_command)

    def _open_change_requests_window(self) -> None:
        """Open the Agent -> Change Requests window (Phase 40). Same
        read-only-display / CLI-subprocess-for-actions split as every
        other launcher here. This window cannot approve anything on its
        own — its Approve button runs the same
        `secure ai changes approve <cr_id> <hash>` a terminal user
        would, with the hash taken from the record rather than retyped.
        """

    def _build_remediation_launcher(self, parent: tk.Widget) -> None:
        """Build the remediation launcher frame."""
        box = tk.LabelFrame(parent, text="Remediation — Automated Response", padx=8, pady=8, font=self._fonts["body_bold"])
        box.pack(fill=tk.X, pady=(0, 10))
        tk.Button(
            box,
            text="Open Remediation Monitor…",
            width=26,
            anchor="w",
            command=self._open_remediation_window,
        ).pack(fill=tk.X, pady=2)
        tk.Label(
            box,
            text="Automated remediation execution monitor (Phase 52).\n"
            "Shows pending/successful/failed actions and recent\n"
            "execution history. All approvals route through CLI\n"
            "for audit trail preservation.",
            font=self._fonts["small"],
            fg="#666",
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

    def _open_remediation_window(self) -> None:
        """Open the Remediation monitor window (Phase 52). Same
        read-only-display / CLI-subprocess-for-actions split as every
        other launcher. Approvals and executions route through the CLI
        subprocess, preserving the audit trail.
        """

        def run_command(label: str, args: List[str], nonzero_is_finding: bool) -> None:
            self._run_command(Command(label, (lambda a=args: a), nonzero_is_finding))

        open_remediation_window(self, run_command=run_command)

        def run_command(label: str, args: List[str], nonzero_is_finding: bool) -> None:
            self._run_command(Command(label, (lambda a=args: a), nonzero_is_finding))

        open_change_requests_window(self, run_command=run_command)

    def _build_category(self, parent: tk.Widget, category: Category) -> None:
        box = tk.LabelFrame(
            parent, text=category.title, padx=8, pady=8, font=self._fonts["body_bold"]
        )
        box.pack(fill=tk.X, pady=(0, 10))
        for cmd in category.commands:
            tk.Button(
                box,
                text=cmd.label,
                width=26,
                anchor="w",
                command=lambda c=cmd: self._run_command(c),
            ).pack(fill=tk.X, pady=2)

    # ---------- command definitions ----------

    def _categories(self) -> List[Category]:
        py = _python_executable

        def init_server() -> List[str]:
            return [py(), "-m", "secure", "init", "--role", "server"]

        def init_workstation() -> List[str]:
            return [py(), "-m", "secure", "init", "--role", "workstation"]

        def status() -> List[str]:
            return [py(), "-m", "secure", "status"]

        def posture_check_full() -> List[str]:
            return [py(), "-m", "secure", "check"]

        def posture_check_quick() -> List[str]:
            return [py(), "-m", "secure", "check", "--quick"]

        def snapshot() -> List[str]:
            return [py(), "-m", "secure", "snapshot"]

        def inventory_scan() -> List[str]:
            return [py(), "-m", "secure", "inventory", "scan"]

        def inventory_list() -> List[str]:
            return [py(), "-m", "secure", "inventory", "list"]

        def inventory_name() -> Optional[List[str]]:
            identifier = simpledialog.askstring(
                "Name device", "Device IP or MAC address:", parent=self
            )
            if not identifier:
                return None
            name = simpledialog.askstring(
                "Name device", f"Friendly name for {identifier}:", parent=self
            )
            if not name:
                return None
            return [py(), "-m", "secure", "inventory", "name", identifier, name]

        def inventory_mark() -> Optional[List[str]]:
            result = mark_state_dialog(
                self, title="Mark device", id_prompt="Device IP or MAC address:"
            )
            if result is None:
                return None
            identifier, status = result
            return [py(), "-m", "secure", "inventory", "mark", identifier, status]

        def inventory_prune() -> Optional[List[str]]:
            return confirmed_args(
                lambda title, body: confirm_action(self, title=title, body=body, destructive=True),
                PRUNE_CONFIRM_TITLE,
                PRUNE_CONFIRM_BODY,
                [py(), "-m", "secure", "inventory", "prune"],
            )

        def connections_scan() -> List[str]:
            return [py(), "-m", "secure", "connections", "scan"]

        def connections_endpoints() -> List[str]:
            return [py(), "-m", "secure", "connections", "endpoints"]

        def connections_mark() -> Optional[List[str]]:
            result = mark_state_dialog(
                self,
                title="Mark remote destination",
                id_prompt="Destination id (see 'List Remote Destinations'):",
            )
            if result is None:
                return None
            endpoint_id, status = result
            return [py(), "-m", "secure", "connections", "mark", endpoint_id, status]

        def listening_scan() -> List[str]:
            return [py(), "-m", "secure", "listening", "scan"]

        def listening_list() -> List[str]:
            return [py(), "-m", "secure", "listening", "list"]

        def listening_mark() -> Optional[List[str]]:
            result = mark_state_dialog(
                self,
                title="Mark listening service",
                id_prompt="Service id (see 'List Listening Services'):",
            )
            if result is None:
                return None
            service_id, status = result
            return [py(), "-m", "secure", "listening", "mark", service_id, status]

        def arpwatch_scan() -> List[str]:
            return [py(), "-m", "secure", "arpwatch", "scan"]

        def arpwatch_list() -> List[str]:
            return [py(), "-m", "secure", "arpwatch", "list"]

        def arpwatch_mark() -> Optional[List[str]]:
            result = mark_state_dialog(
                self, title="Mark ARP alert", id_prompt="Alert id (see 'List ARP Alerts'):"
            )
            if result is None:
                return None
            alert_id, status = result
            return [py(), "-m", "secure", "arpwatch", "mark", alert_id, status]

        def wifi_scan() -> List[str]:
            return [py(), "-m", "secure", "wifi", "scan"]

        def wifi_list() -> List[str]:
            return [py(), "-m", "secure", "wifi", "list"]

        def wifi_mark() -> Optional[List[str]]:
            result = mark_state_dialog(
                self,
                title="Mark Wi-Fi network",
                id_prompt="Network id (see 'List Wi-Fi Networks'):",
            )
            if result is None:
                return None
            network_id, status = result
            return [py(), "-m", "secure", "wifi", "mark", network_id, status]

        def wifi_alerts() -> List[str]:
            return [py(), "-m", "secure", "wifi", "alerts"]

        def wifi_mark_alert() -> Optional[List[str]]:
            result = mark_state_dialog(
                self, title="Mark Wi-Fi alert", id_prompt="Alert id (see 'List Wi-Fi Alerts'):"
            )
            if result is None:
                return None
            alert_id, status = result
            return [py(), "-m", "secure", "wifi", "mark-alert", alert_id, status]

        def bluetooth_scan() -> List[str]:
            return [py(), "-m", "secure", "bluetooth", "scan"]

        def bluetooth_list() -> List[str]:
            return [py(), "-m", "secure", "bluetooth", "list"]

        def bluetooth_mark() -> Optional[List[str]]:
            result = mark_state_dialog(
                self,
                title="Mark Bluetooth device",
                id_prompt="Device id (see 'List Bluetooth Devices'):",
                states=("trusted", "untrusted"),
            )
            if result is None:
                return None
            device_id, status = result
            return [py(), "-m", "secure", "bluetooth", "mark", device_id, status]

        def bluetooth_alerts() -> List[str]:
            return [py(), "-m", "secure", "bluetooth", "alerts"]

        def bluetooth_mark_alert() -> Optional[List[str]]:
            result = mark_state_dialog(
                self,
                title="Mark Bluetooth alert",
                id_prompt="Alert id (see 'List Bluetooth Alerts'):",
            )
            if result is None:
                return None
            alert_id, status = result
            return [py(), "-m", "secure", "bluetooth", "mark-alert", alert_id, status]

        def bluetooth_state() -> List[str]:
            return [py(), "-m", "secure", "bluetooth", "state"]

        def bluetooth_ble_scan() -> List[str]:
            return [py(), "-m", "secure", "bluetooth", "ble", "scan"]

        def bluetooth_ble_list() -> List[str]:
            return [py(), "-m", "secure", "bluetooth", "ble", "list"]

        def bluetooth_ble_mark() -> Optional[List[str]]:
            result = mark_state_dialog(
                self,
                title="Mark BLE peripheral",
                id_prompt="Peripheral id (see 'List BLE Peripherals'):",
                states=("trusted", "untrusted"),
            )
            if result is None:
                return None
            peripheral_id, status = result
            return [py(), "-m", "secure", "bluetooth", "ble", "mark", peripheral_id, status]

        def bluetooth_ble_alerts() -> List[str]:
            return [py(), "-m", "secure", "bluetooth", "ble", "alerts"]

        def bluetooth_ble_mark_alert() -> Optional[List[str]]:
            result = mark_state_dialog(
                self, title="Mark BLE alert", id_prompt="Alert id (see 'List BLE Alerts'):"
            )
            if result is None:
                return None
            alert_id, status = result
            return [py(), "-m", "secure", "bluetooth", "ble", "mark-alert", alert_id, status]

        def persistence_scan() -> List[str]:
            return [py(), "-m", "secure", "persistence", "scan"]

        def persistence_processes() -> List[str]:
            return [py(), "-m", "secure", "persistence", "processes"]

        def persistence_mark_process() -> Optional[List[str]]:
            result = mark_state_dialog(
                self, title="Mark process entry", id_prompt="Entry id (see 'List Processes'):"
            )
            if result is None:
                return None
            entry_id, status = result
            return [py(), "-m", "secure", "persistence", "mark-process", entry_id, status]

        def persistence_items() -> List[str]:
            return [py(), "-m", "secure", "persistence", "items"]

        def persistence_mark_item() -> Optional[List[str]]:
            result = mark_state_dialog(
                self,
                title="Mark persistence entry",
                id_prompt="Entry id (see 'List Persistence Entries'):",
            )
            if result is None:
                return None
            entry_id, status = result
            return [py(), "-m", "secure", "persistence", "mark-item", entry_id, status]

        def persistence_alerts() -> List[str]:
            return [py(), "-m", "secure", "persistence", "alerts"]

        def persistence_mark_alert() -> Optional[List[str]]:
            result = mark_state_dialog(
                self,
                title="Mark persistence alert",
                id_prompt="Alert id (see 'List Persistence Alerts'):",
            )
            if result is None:
                return None
            alert_id, status = result
            return [py(), "-m", "secure", "persistence", "mark-alert", alert_id, status]

        def fileintegrity_scan() -> List[str]:
            return [py(), "-m", "secure", "fileintegrity", "scan"]

        def fileintegrity_watch_list() -> List[str]:
            return [py(), "-m", "secure", "fileintegrity", "watch-list"]

        def fileintegrity_watch_add() -> Optional[List[str]]:
            path = simpledialog.askstring(
                "Add watch path", "File or folder to monitor:", parent=self
            )
            if not path:
                return None
            return [py(), "-m", "secure", "fileintegrity", "watch-add", path]

        def fileintegrity_files() -> List[str]:
            return [py(), "-m", "secure", "fileintegrity", "files"]

        def fileintegrity_mark_file() -> Optional[List[str]]:
            result = mark_state_dialog(
                self,
                title="Mark file entry",
                id_prompt="Entry id (see 'List Monitored Files'):",
            )
            if result is None:
                return None
            entry_id, status = result
            return [py(), "-m", "secure", "fileintegrity", "mark-file", entry_id, status]

        def fileintegrity_events() -> List[str]:
            return [py(), "-m", "secure", "fileintegrity", "events"]

        def fileintegrity_alerts() -> List[str]:
            return [py(), "-m", "secure", "fileintegrity", "alerts"]

        def fileintegrity_mark_alert() -> Optional[List[str]]:
            result = mark_state_dialog(
                self,
                title="Mark file integrity alert",
                id_prompt="Alert id (see 'List File Integrity Alerts'):",
            )
            if result is None:
                return None
            alert_id, status = result
            return [py(), "-m", "secure", "fileintegrity", "mark-alert", alert_id, status]

        def run_everything() -> List[str]:
            return [py(), "-m", "secure", "run-all"]

        def correlate_run() -> List[str]:
            return [py(), "-m", "secure", "correlate", "run"]

        def correlate_list() -> List[str]:
            return [py(), "-m", "secure", "correlate", "list"]

        def correlate_mark_alert() -> Optional[List[str]]:
            result = mark_state_dialog(
                self,
                title="Mark correlation alert",
                id_prompt="Alert id (see 'List Correlation Alerts'):",
            )
            if result is None:
                return None
            alert_id, status = result
            return [py(), "-m", "secure", "correlate", "mark-alert", alert_id, status]

        def add_note() -> Optional[List[str]]:
            text = simpledialog.askstring(
                "Add note", "Event text to store:", parent=self
            )
            if not text:
                return None
            return [py(), "-m", "secure", "add-note", text]

        def investigate_show() -> Optional[List[str]]:
            # investigate_show_request() is the enforcement point: it
            # refuses an unknown type, an empty key, or a key starting with
            # "-". A refusal goes to the console and nothing runs.
            entity_type = simpledialog.askstring(
                "Investigate entity",
                "Entity type — one of:\n" + ", ".join(INVESTIGATE_ENTITY_TYPES),
                parent=self,
            )
            if entity_type is None:
                return None
            key = simpledialog.askstring(
                "Investigate entity", f"Key for {entity_type.strip()!r}:", parent=self
            )
            if key is None:
                return None
            args, refusal = investigate_show_request(entity_type.strip(), key)
            if refusal:
                self._log(f"  -> not run: {refusal}", "stderr")
                return None
            return [py(), "-m", "secure", *args]

        # Hand-built commands that join a catalog category (they need a
        # prompt, so they cannot be static catalog entries).
        catalog_extras = {INVESTIGATE: [Command("Investigate Entity…", investigate_show)]}

        return [
            Category(
                "Run Everything",
                [
                    Command(
                        "Run Everything (Scan + Correlate)",
                        run_everything,
                        nonzero_is_finding=True,
                    ),
                ],
            ),
            Category(
                "Identity & Setup",
                [
                    Command("Init as Server (always-on)", init_server),
                    Command("Init as Workstation", init_workstation),
                ],
            ),
            Category(
                "Status",
                [Command("Show Device Status", status)],
            ),
            Category(
                "Security Posture",
                [
                    Command("Run Full Check", posture_check_full, nonzero_is_finding=True),
                    Command(
                        "Run Quick Check (skip updates)",
                        posture_check_quick,
                        nonzero_is_finding=True,
                    ),
                ],
            ),
            Category(
                "Continuity",
                [Command("Snapshot", snapshot, nonzero_is_finding=True)],
            ),
            Category(
                "Device Inventory",
                [
                    Command("Scan Network", inventory_scan, nonzero_is_finding=True),
                    Command("List Devices", inventory_list),
                    Command("Name Device…", inventory_name),
                    Command("Mark Known/Unknown…", inventory_mark),
                    Command("Prune Junk Entries", inventory_prune),
                ],
            ),
            Category(
                "Active Connections",
                [
                    Command("Scan Connections", connections_scan, nonzero_is_finding=True),
                    Command("List Remote Destinations", connections_endpoints),
                    Command("Mark Known/Unknown…", connections_mark),
                ],
            ),
            Category(
                "Listening Services",
                [
                    Command("Scan Listening Services", listening_scan, nonzero_is_finding=True),
                    Command("List Listening Services", listening_list),
                    Command("Mark Known/Unknown…", listening_mark),
                ],
            ),
            Category(
                "ARP Watch",
                [
                    Command("Scan ARP Table", arpwatch_scan, nonzero_is_finding=True),
                    Command("List ARP Alerts", arpwatch_list),
                    Command("Mark Known/Unknown…", arpwatch_mark),
                ],
            ),
            Category(
                "Wi-Fi Security",
                [
                    Command("Scan Wi-Fi", wifi_scan, nonzero_is_finding=True),
                    Command("List Wi-Fi Networks", wifi_list),
                    Command("Mark Network Known/Unknown…", wifi_mark),
                    Command("List Wi-Fi Alerts", wifi_alerts),
                    Command("Mark Alert Known/Unknown…", wifi_mark_alert),
                ],
            ),
            Category(
                "Bluetooth",
                [
                    Command("Scan Bluetooth", bluetooth_scan, nonzero_is_finding=True),
                    Command("List Bluetooth Devices", bluetooth_list),
                    Command("Mark Trusted/Untrusted…", bluetooth_mark),
                    Command("List Bluetooth Alerts", bluetooth_alerts),
                    Command("Mark Alert Known/Unknown…", bluetooth_mark_alert),
                    Command("Check Bluetooth State", bluetooth_state, nonzero_is_finding=True),
                    Command(
                        "Scan Live BLE Peripherals", bluetooth_ble_scan, nonzero_is_finding=True
                    ),
                    Command("List BLE Peripherals", bluetooth_ble_list),
                    Command("Mark BLE Peripheral Trusted/Untrusted…", bluetooth_ble_mark),
                    Command("List BLE Alerts", bluetooth_ble_alerts),
                    Command("Mark BLE Alert Known/Unknown…", bluetooth_ble_mark_alert),
                ],
            ),
            Category(
                "Process & Persistence",
                [
                    Command("Scan Processes & Persistence", persistence_scan, nonzero_is_finding=True),
                    Command("List Processes", persistence_processes),
                    Command("Mark Process Known/Unknown…", persistence_mark_process),
                    Command("List Persistence Entries", persistence_items),
                    Command("Mark Entry Known/Unknown…", persistence_mark_item),
                    Command("List Persistence Alerts", persistence_alerts),
                    Command("Mark Alert Known/Unknown…", persistence_mark_alert),
                ],
            ),
            Category(
                "File Integrity",
                [
                    Command("Scan Watched Files", fileintegrity_scan, nonzero_is_finding=True),
                    Command("List Watch Paths", fileintegrity_watch_list),
                    Command("Add Watch Path…", fileintegrity_watch_add),
                    Command("List Monitored Files", fileintegrity_files),
                    Command("Mark File Known/Unknown…", fileintegrity_mark_file),
                    Command("Show Change History", fileintegrity_events),
                    Command("List File Integrity Alerts", fileintegrity_alerts),
                    Command("Mark Alert Known/Unknown…", fileintegrity_mark_alert),
                ],
            ),
            Category(
                "Correlation",
                [
                    Command("Correlate", correlate_run, nonzero_is_finding=True),
                    Command("List Correlation Alerts", correlate_list),
                    Command("Mark Alert Known/Unknown…", correlate_mark_alert),
                ],
            ),
            # One category per catalog category, in catalog order.
            *[
                Category(
                    title,
                    [
                        Command(
                            entry.label,
                            (lambda entry=entry: [py(), "-m", "secure", *entry.args]),
                            nonzero_is_finding=entry.nonzero_is_finding,
                            timeout_seconds=entry.timeout_seconds,
                        )
                        for entry in COMMAND_CATALOG
                        if entry.category == title
                    ]
                    + catalog_extras.get(title, []),
                )
                for title in dict.fromkeys(entry.category for entry in COMMAND_CATALOG)
            ],
            Category(
                "Event Log",
                [Command("Add Note…", add_note)],
            ),
        ]

    # ---------- running commands ----------

    def _run_command(self, cmd: Command) -> None:
        click_time = datetime.now().strftime("%H:%M:%S")
        self._log(f"[{click_time}] Clicked: {cmd.label}", "click")

        args = cmd.build_args()
        if not args:
            self._log("  -> not run (dialog cancelled).", "meta")
            return  # user cancelled a dialog, e.g. Add Note

        if self._busy:
            decision = self._prompt_busy_conflict(cmd.label)
            if decision == "cancel":
                self._log(f"  -> not run (you chose Cancel).", "meta")
                return
            if decision == "stop":
                self._log(
                    f"  -> stopping '{self._current_label}' now, "
                    f"then running '{cmd.label}'.",
                    "meta",
                )
                self._request_stop_current()
            else:  # "queue"
                ahead = self._job_queue.qsize() + 1  # +1 for the one currently running
                self._log(
                    f"  -> queued behind '{self._current_label}' "
                    f"({ahead} job(s) ahead).",
                    "meta",
                )

        # Enqueue rather than run immediately — see the module
        # docstring for why commands are serialized. If several
        # buttons get clicked in a row, they'll show up in the console
        # one after another, in the order they were clicked, exactly
        # like typing them into Terminal yourself.
        self._job_queue.put((cmd.label, args, cmd.nonzero_is_finding, cmd.timeout_seconds))

    def _prompt_busy_conflict(self, new_label: str) -> str:
        """Ask what to do when a command is clicked while another is running.

        Returns "stop" (terminate the running one, run this now),
        "queue" (run this after the current one finishes), or "cancel"
        (don't run this click at all).
        """
        running = self._current_label or "the current command"
        answer = messagebox.askyesnocancel(
            "A command is already running",
            f"'{running}' is still running.\n\n"
            f"Yes — stop it now and run '{new_label}' immediately\n"
            f"No — queue '{new_label}' to run right after it finishes\n"
            f"Cancel — don't run '{new_label}'",
            parent=self,
        )
        if answer is True:
            return "stop"
        if answer is False:
            return "queue"
        return "cancel"

    def _request_stop_current(self) -> None:
        """Ask the currently-running subprocess to terminate.

        A no-op if nothing is running, or if it already finished
        between the click and this call (a small, harmless race).
        """
        with self._process_lock:
            proc = self._current_process
            if proc is not None and proc.poll() is None:
                self._stop_requested = True
            else:
                proc = None
        if proc is not None:
            try:
                proc.terminate()
            except Exception as exc:
                self._queue.put(("stderr", f"Could not stop the running command: {exc}"))

    def _worker_loop(self) -> None:
        """Runs on a single background thread for the app's whole lifetime.

        Pulls one job at a time off `_job_queue` and executes it fully
        (including waiting for the subprocess to finish, or to be
        stopped) before picking up the next one — that's what
        guarantees in-order output. All GUI updates go through
        `_queue`/`_poll_queue` instead of touching widgets directly,
        since this thread is not the Tkinter main thread.
        """
        while True:
            label, args, nonzero_is_finding, timeout_seconds = self._job_queue.get()
            self._queue.put(("busy", label))
            self._execute(label, args, nonzero_is_finding, timeout_seconds)
            self._queue.put(("idle", ""))

    def _execute(
        self,
        label: str,
        args: List[str],
        nonzero_is_finding: bool = False,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        """Run one command's subprocess to completion and report how it
        went. The final line distinguishes three outcomes, not two:

            - exit code 0 -> ran fine, nothing worth flagging.
            - exit code 1 AND nonzero_is_finding -> ran fine; the
              nonzero exit is this command's normal way of saying "I
              found something worth reviewing" (new device, alert,
              posture FAIL, etc.) — see Command.nonzero_is_finding's
              docstring. Reported plainly, not as an error.
            - anything else (any exit code when nonzero_is_finding is
              False, or any exit code other than 0/1 regardless) -> a
              real failure, reported in the same red "stderr" style
              already used for crashes/timeouts.
        """
        printable = " ".join(args)
        start_time = datetime.now().strftime("%H:%M:%S")
        self._queue.put(("cmd", f"\n$ {printable}    (started {start_time})"))
        try:
            proc = subprocess.Popen(
                args,
                cwd=PROJECT_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as e:
            self._queue.put(("stderr", f"Could not run command: {e}"))
            return

        with self._process_lock:
            self._current_process = proc

        try:
            stdout, stderr = proc.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            finish_time = datetime.now().strftime("%H:%M:%S")
            self._queue.put(
                (
                    "stderr",
                    f"[{label}] {tokens.run_outcome_text('timeout')} "
                    f"after {timeout_seconds}s — {finish_time}",
                )
            )
            with self._process_lock:
                self._current_process = None
                self._stop_requested = False
            return

        with self._process_lock:
            self._current_process = None
            was_stopped = self._stop_requested
            self._stop_requested = False

        if stdout:
            self._queue.put(("stdout", stdout.rstrip("\n")))
        if stderr:
            self._queue.put(("stderr", stderr.rstrip("\n")))

        # Record the run in the Obsidian vault. Identical output does not
        # create a second note — it bumps that note's run_count instead;
        # only a changed result writes a new note, with a diff.
        if not was_stopped:
            try:
                from secure.vaultlog import record_run
                combined = (stdout or "") + (("\n" + stderr) if stderr else "")
                res = record_run(label, args, proc.returncode, combined)
                if res["status"] == "new" and res.get("changed_from"):
                    self._queue.put(("meta",
                        f"[vault] output CHANGED since last run — new note {res['digest']}"))
                elif res["status"] == "repeat":
                    self._queue.put(("meta",
                        f"[vault] same result as before (seen {res['count']}x)"))
                else:
                    self._queue.put(("meta", f"[vault] first recorded run — note {res['digest']}"))
            except Exception as exc:
                self._queue.put(("stderr", f"[vault] could not record run: {exc}"))

        # These three outcomes are reported with visibly distinct
        # glyphs/wording (see tokens.RUN_OUTCOME) precisely so a real
        # failure can never be mistaken for "ran fine, nothing found"
        # at a glance — the whole point of nonzero_is_finding is that
        # exit code 1 means something different depending on which
        # command ran, and that distinction has to survive into what
        # gets shown here.
        finish_time = datetime.now().strftime("%H:%M:%S")
        if was_stopped:
            self._queue.put(
                ("meta", f"[{label}] {tokens.run_outcome_text('stopped')} — {finish_time}")
            )
        elif proc.returncode == 0:
            self._queue.put(
                ("meta", f"[{label}] {tokens.run_outcome_text('success')} — {finish_time}")
            )
        elif nonzero_is_finding and proc.returncode == 1:
            self._queue.put(
                (
                    "meta",
                    f"[{label}] {tokens.run_outcome_text('findings')} "
                    f"(exit code 1, not a failure) — {finish_time}",
                )
            )
        else:
            self._queue.put(
                (
                    "stderr",
                    f"[{label}] {tokens.run_outcome_text('failed')} "
                    f"— exit code {proc.returncode} — {finish_time}",
                )
            )

    # ---------- console plumbing ----------

    def _poll_queue(self) -> None:
        try:
            while True:
                tag, text = self._queue.get_nowait()
                if tag == "busy":
                    self._set_busy(text)
                elif tag == "idle":
                    self._set_idle()
                else:
                    self._log(text, tag)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _set_busy(self, label: str) -> None:
        # Buttons stay clickable on purpose: clicking one while
        # something is running is exactly how you get the stop/queue/
        # cancel prompt in _run_command, rather than being unable to
        # act until the current command finishes.
        self._busy = True
        self._current_label = label
        self.status_var.set(f"Running: {label}…")

    def _set_idle(self) -> None:
        self._busy = False
        self.status_var.set("Idle")

    def _log(self, text: str, tag: str = "stdout") -> None:
        self.console.configure(state=tk.NORMAL)
        self.console.insert(tk.END, text + "\n", tag)
        self.console.see(tk.END)
        self.console.configure(state=tk.DISABLED)

    def _clear_console(self) -> None:
        self.console.configure(state=tk.NORMAL)
        self.console.delete("1.0", tk.END)
        self.console.configure(state=tk.DISABLED)

    def _copy_console(self) -> None:
        """Copy the full console transcript (every command + output so far) to the clipboard."""
        text = self.console.get("1.0", tk.END).rstrip("\n")
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()  # keeps the clipboard content available after the app loses focus

        original = self.copy_button.cget("text")
        self.copy_button.config(text="Copied!")
        self.after(1200, lambda: self.copy_button.config(text=original))

    def _update_and_restart(self) -> None:
        """Restart this GUI process in place, so it picks up whatever
        code is currently on disk in this project folder without you
        having to close and reopen the window yourself.

        This button does NOT fetch anything on its own. It's meant to
        pair with a folder-sync tool (Syncthing) keeping this whole
        project directory synced across your machines in the
        background (see "Multi-device model" and "Keeping the app
        itself up to date" in PROJECT_NOTES.md) — Syncthing does the
        actual syncing continuously; clicking Update just reloads
        whatever has already landed on disk, which is otherwise
        exactly what closing and reopening the app by hand would do
        (Python only reads each module's code once, at import time, so
        a long-running process keeps running old code in memory even
        after new files sync in — restarting the process is the only
        way to pick them up).
        """
        if self._busy:
            proceed = confirm_action(
                self,
                title="Update & Restart",
                body=f"'{self._current_label}' is still running.\n\n"
                "Restarting now will stop it immediately and its output "
                "will be lost. Restart anyway?",
                destructive=True,
            )
            if not proceed:
                return
            self._request_stop_current()

        self._log("\nRestarting to pick up the latest code on disk...", "meta")
        self.update_idletasks()

        # Mark this as a known update/reload context BEFORE relaunching
        # — see secure/self_update.py. File integrity monitoring checks
        # for a recent marker like this one so a legitimate multi-file
        # update to Secure's own source doesn't read as "unexplained
        # self-modification". Best-effort and quick (a few seconds max);
        # if it fails for any reason the relaunch still proceeds — an
        # unmarked update just means self-file changes stay at their
        # normal (unexplained) severity, not that anything breaks.
        try:
            subprocess.run(
                [_python_executable(), "-m", "secure", "self", "mark-update-context",
                 "--note", "GUI Update button"],
                cwd=str(PROJECT_ROOT),
                timeout=10,
                capture_output=True,
            )
        except Exception:
            pass

        # Give the log line a moment to actually render before the
        # process image gets replaced out from under this window.
        self.after(200, self._do_relaunch)

    def _do_relaunch(self) -> None:
        """Start a brand-new GUI process, then quit this one.

        An earlier version of this used os.execv() to replace this
        process's own image in place. That's the textbook Unix way to
        "restart in place," but on macOS it breaks Tk/Cocoa
        specifically: the OS has already bound this process's Mach
        task port and window-server connection to the outgoing
        NSApplication instance, and won't hand that over to whatever
        exec() loads next. In practice that meant clicking Update made
        the window disappear and never come back — no crash, no error
        dialog, just silence (macOS logs "Task policy set failed: 4
        ((os/kern) invalid argument)" to the terminal, easy to miss and
        easy to mistake for a harmless warning). A genuinely new,
        separate process doesn't have that problem — it gets its own
        fresh task port and window-server connection, exactly like
        double-clicking the app again would. So instead: spawn a new
        process running this same script, then exit this one — the
        same net effect (old window gone, new window up, latest code on
        disk in use) without the broken hand-off.
        """
        python = _python_executable()
        subprocess.Popen(
            [python, str(Path(__file__).resolve()), *sys.argv[1:]],
            cwd=str(PROJECT_ROOT),
            start_new_session=True,
        )
        # The worker thread is a daemon (see __init__), so there's
        # nothing else to wait on — exit immediately rather than
        # letting mainloop() unwind on its own, so there's no window
        # where both the old and new process are visible at once.
        os._exit(0)


def main() -> None:
    SecureGUI().mainloop()


if __name__ == "__main__":
    main()
