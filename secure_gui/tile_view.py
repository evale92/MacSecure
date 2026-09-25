"""Tile-based category view with hover dropdowns.

Alternative visual layout to the list-based button view. Displays each
category as a clickable tile; hovering shows a dropdown with all commands
in that category. Provides the same functionality as the list view with
improved visual hierarchy and space efficiency.
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable, Dict, List, Optional, Tuple

from secure_gui import tokens
from secure_gui.components import resolve_fonts

RunCommand = Callable[[str, List[str], bool], None]


BG = "#fafafa"
PAD = 10
SIDE_GUTTER = 20     # + outer padx 10 + tile padx 10 = 40px visible
HIDE_DELAY_MS = 600
TRACKPAD_THRESHOLD = 34      # higher = slower trackpad scrolling          # how long the dropdown lingers after the pointer leaves


def _round_pts(x1, y1, x2, y2, r):
    return [
        x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
        x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
        x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
    ]


def _round_rect(canvas, x1, y1, x2, y2, r, **kw):
    """Rounded rectangle as a smoothed polygon — Tk has no native one."""
    return canvas.create_polygon(_round_pts(x1, y1, x2, y2, r), smooth=True, **kw)


def _darken(hex_colour: str, factor: float = 0.82) -> str:
    """Darker shade of a #rrggbb colour, for the locked-tile state."""
    h = hex_colour.lstrip("#")
    if len(h) != 6:
        return hex_colour
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return "#%02x%02x%02x" % (int(r * factor), int(g * factor), int(b * factor))
TILE_W = 150
TILE_H = 84


class TileCategory:
    """Data holder for a category and its commands."""

    def __init__(self, name: str, commands: List[Tuple[str, List[str], bool]]):
        self.name = name
        self.commands = commands  # [(label, argv, nonzero_is_finding), ...]


class CategoryTileFrame(tk.Canvas):
    """A single category tile: rounded card with a soft shadow."""

    RADIUS = 10
    SHADOW = 3

    def __init__(
        self,
        parent: tk.Widget,
        category: TileCategory,
        run_command: RunCommand,
        fonts: Dict[str, Tuple],
        width: int = 150,
        height: int = 84,
        **kwargs
    ):
        super().__init__(
            parent, width=width, height=height,
            highlightthickness=0, bd=0, bg=tokens.ui("app_bg"), **kwargs
        )
        self.category = category
        self.run_command = run_command
        self.fonts = fonts
        self.dropdown_window: Optional[tk.Toplevel] = None
        self._locked = False
        self._hide_job = None
        self._dropdown_is_toplevel = False
        # NB: never assign self._w / self._h — Tkinter uses self._w as the
        # widget's Tcl path name.
        self._tile_w, self._tile_h = width, height

        sh, r = self.SHADOW, self.RADIUS
        # shadow first so the card sits on top of it
        self._shadow_id = _round_rect(
            self, sh, sh, width - 1, height - 1, r,
            fill=_darken(tokens.ui("app_bg"), 0.88), outline="",
        )
        self._card_id = _round_rect(
            self, 0, 0, width - sh - 1, height - sh - 1, r,
            fill=tokens.ui("tile_bg"), outline=tokens.ui("tile_border"), width=1,
        )
        self._text_id = self.create_text(
            (width - sh) / 2, (height - sh) / 2,
            text=category.name, font=fonts["body_bold"],
            fill=tokens.ui("text"), width=width - 28, justify="center",
        )

        for seq, handler in (("<Enter>", self._on_enter),
                             ("<Leave>", self._on_leave),
                             ("<Button-1>", self._on_click)):
            self.bind(seq, handler)
        self.bind("<Configure>", self._on_resize)

    def _on_resize(self, event):
        """Redraw the card at the widget's actual size — the grid stretches
        tiles to fill the row, and canvas items do not scale on their own."""
        w, h = event.width, event.height
        if w < 4 or h < 4:
            return
        sh, r = self.SHADOW, self.RADIUS
        self.coords(self._shadow_id, *_round_pts(sh, sh, w - 1, h - 1, r))
        self.coords(self._card_id, *_round_pts(0, 0, w - sh - 1, h - sh - 1, r))
        self.coords(self._text_id, (w - sh) / 2, (h - sh) / 2)
        self.itemconfigure(self._text_id, width=max(w - 28, 40))

    # ---- hover / lock ----------------------------------------------------

    def _paint(self) -> None:
        """Card colours follow lock state first, hover second."""
        if self._locked:
            fill = _darken(tokens.ui("tile_bg"))
            outline = tokens.ui("accent")
        elif self.dropdown_window is not None:
            fill = tokens.ui("tile_hover")
            outline = tokens.ui("accent")
        else:
            fill = tokens.ui("tile_bg")
            outline = tokens.ui("tile_border")
        self.configure(bg=tokens.ui("app_bg"))
        self.itemconfigure(self._card_id, fill=fill, outline=outline)
        self.itemconfigure(self._shadow_id, fill=_darken(tokens.ui("app_bg"), 0.88))
        self.itemconfigure(self._text_id, fill=tokens.ui("text"))

    def _on_enter(self, event=None):
        self._cancel_hide()
        self._show_dropdown()
        self._paint()

    def _on_leave(self, event=None):
        if self._locked:
            return                      # pinned open until clicked again
        self._schedule_hide()

    def _schedule_hide(self) -> None:
        """Let the dropdown linger so it can actually be moved onto."""
        self._cancel_hide()
        self._hide_job = self.after(HIDE_DELAY_MS, self._hide_if_pointer_away)

    def _cancel_hide(self) -> None:
        if self._hide_job is not None:
            try:
                self.after_cancel(self._hide_job)
            except tk.TclError:
                pass
            self._hide_job = None

    def _hide_if_pointer_away(self) -> None:
        self._hide_job = None
        if self._locked or self._pointer_inside():
            return
        self._hide_dropdown()
        self._paint()

    def _pointer_inside(self) -> bool:
        """True if the pointer is over the tile or its dropdown."""
        try:
            px, py = self.winfo_pointerx(), self.winfo_pointery()
        except tk.TclError:
            return False
        for w in (self, self.dropdown_window):
            if w is None:
                continue
            try:
                x1, y1 = w.winfo_rootx(), w.winfo_rooty()
                if x1 <= px <= x1 + w.winfo_width() and y1 <= py <= y1 + w.winfo_height():
                    return True
            except tk.TclError:
                continue
        return False

    def _on_click(self, event=None):
        """Click pins the options open; click again releases them.

        Only one tile can be pinned at a time — locking this one releases
        whichever was pinned before.
        """
        owner = getattr(self, "_owner", None)
        if not self._locked and owner is not None:
            # Collapse everything else — including dropdowns that are merely
            # hover-open, not locked. Two visible dropdowns overlap and read
            # as broken even when each tile is behaving correctly.
            for other in getattr(owner, "_tiles", []):
                if other is not self:
                    other.release_lock()

        self._locked = not self._locked
        if self._locked:
            self._cancel_hide()
            self._show_dropdown()
            if owner is not None:
                owner._locked_tile = self
        else:
            self._hide_dropdown()
            if owner is not None and getattr(owner, "_locked_tile", None) is self:
                owner._locked_tile = None
        self._paint()
        return "break"

    def release_lock(self) -> None:
        """Unpin this tile (used when another tile takes the lock)."""
        self._locked = False
        self._cancel_hide()
        self._hide_dropdown()
        self._paint()

    def _show_dropdown(self):
        """Show the command list.

        Two strategies, chosen by whether the panel fits:

        * fits inside the window -> a Frame placed in the same window. No
          focus handoff, so the first click on a tile always registers.
        * does not fit below the tile -> the same panel is flipped above
          it, and clamped inside the pane as a last resort. A borderless
          Toplevel was tried and rejected: macOS gives it rounded corners
          and a shadow, so it never matched the docked panel.
        """
        if self.dropdown_window is not None:
            return
        owner = getattr(self, "_owner", None)
        if owner is None:
            return
        root = self.winfo_toplevel()

        def build(parent):
            panel = tk.Frame(parent, bg=tokens.ui("panel_bg"),
                             highlightthickness=1,
                             highlightbackground=tokens.ui("accent"))
            for label, argv, nonzero in self.category.commands:
                btn = tk.Label(panel, text=label, font=self.fonts["body"],
                               bg=tokens.ui("panel_bg"), fg=tokens.ui("text"),
                               anchor="w", padx=12, pady=6, cursor="hand2")
                btn.pack(fill=tk.X)
                btn.bind("<Button-1>",
                         lambda e, l=label, a=argv, n=nonzero: self._execute_command(l, a, n))
                btn.bind("<Enter>", lambda e, b=btn: b.config(bg=tokens.ui("tile_hover")))
                btn.bind("<Leave>", lambda e, b=btn: b.config(bg=tokens.ui("panel_bg")))
            panel.bind("<Enter>", lambda e: self._cancel_hide())
            panel.bind("<Leave>", self._on_dropdown_leave)
            return panel

        # Measure the panel off-screen first so we know where to put it.
        probe = build(root)
        probe.update_idletasks()
        need_h = probe.winfo_reqheight()
        need_w = probe.winfo_reqwidth()
        probe.destroy()

        panel = build(owner)
        ow, oh = owner.winfo_width(), owner.winfo_height()
        x = self.winfo_rootx() - owner.winfo_rootx()
        below = (self.winfo_rooty() - owner.winfo_rooty()) + self.winfo_height() + 2

        if below + need_h <= oh:
            y = below                                   # room below: normal case
        else:
            above = (self.winfo_rooty() - owner.winfo_rooty()) - need_h - 2
            if above >= 0:
                y = above                               # flip above the tile
            else:
                y = max(0, oh - need_h)                 # clamp inside the pane

        x = max(0, min(x, ow - need_w)) if ow > need_w else 0
        # Hard clamp: a tile scrolled near the edge can compute a y outside
        # the pane, which would place the panel off-screen entirely.
        y = max(0, min(y, max(oh - need_h, 0)))

        panel.place(in_=owner, x=x, y=y)
        panel.lift()
        self._dropdown_is_toplevel = False

        self.dropdown_window = panel

    def _on_dropdown_leave(self, event=None):
        if self._locked:
            return
        self._schedule_hide()

    def _hide_dropdown(self):
        """Remove the panel, whichever kind it is."""
        if self.dropdown_window is not None:
            try:
                if not getattr(self, "_dropdown_is_toplevel", False):
                    self.dropdown_window.place_forget()
                self.dropdown_window.destroy()
            except tk.TclError:
                pass
            self.dropdown_window = None
            self._dropdown_is_toplevel = False

    def _execute_command(self, label: str, argv: List[str], nonzero_is_finding: bool):
        """Execute a command and hide dropdown."""
        owner = getattr(self, "_owner", None)
        if owner is not None and getattr(owner, "_locked_tile", None) is self:
            owner._locked_tile = None
        self._locked = False
        self._cancel_hide()
        self._hide_dropdown()
        self._paint()
        self.run_command(label, argv, nonzero_is_finding)


class TileView(tk.Frame):
    """Grid-based tile view for all categories."""

    def __init__(
        self,
        parent: tk.Widget,
        categories: List[TileCategory],
        run_command: RunCommand,
        fonts: Dict[str, Tuple],
        **kwargs
    ):
        super().__init__(parent, **kwargs)
        self.config(bg=tokens.ui("app_bg"))

        self._categories = categories
        self._run_command = run_command
        self._fonts = fonts
        self._tiles: List[tk.Widget] = []
        self._locked_tile = None
        self._columns = 0

        self.canvas = tk.Canvas(self, bg=tokens.ui("app_bg"), highlightthickness=0)
        self.scrollable_frame = tk.Frame(self.canvas, bg=tokens.ui("app_bg"))

        # anchor="n" keeps the grid horizontally centred; the x coordinate
        # is recomputed on every resize in _on_canvas_configure.
        self._window_id = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        self.scrollable_frame.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        self.canvas.pack(fill=tk.BOTH, expand=True)
        # Direct binding as well as the app-level one — see secure_gui.py.
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.canvas.bind(seq, self._on_mousewheel)
        # Tk 9 macOS trackpad — see secure_gui.py for the bitmask details.
        self.canvas.bind("<TouchpadScroll>", self._on_touchpad_scroll)

        for category in categories:
            tile = CategoryTileFrame(
                self.scrollable_frame, category, run_command, fonts,
                width=TILE_W, height=TILE_H,
            )
            # The tile's own children are packed, so pack_propagate is what
            # stops them collapsing it below the requested size.
            tile.pack_propagate(False)
            tile._owner = self
            self._tiles.append(tile)

        self._relayout(1)
        # <MouseWheel> only fires on the widget under the cursor, and each
        # tile is a real widget, so binding the canvas alone means the
        # trackpad does nothing while hovering a tile.

    # ---- layout ----------------------------------------------------------
    COLUMNS = 2   # fixed two-column grid; the view scrolls vertically

    def _columns_for(self, width: int) -> int:
        # One column only if the pane is too narrow for two.
        if width < 2 * (TILE_W + 2 * PAD) + 2 * PAD:
            return 1
        return self.COLUMNS

    def _relayout(self, columns: int) -> None:
        if columns == self._columns:
            return
        # Clear every column previously configured. grid_columnconfigure is
        # sticky: going 5 columns -> 2 leaves minsize set on columns 2-4, so
        # the frame stays 5 columns wide and the visible tiles end up left
        # of centre with lopsided padding.
        for c in range(max(self._columns, columns, len(self._tiles))):
            self.scrollable_frame.grid_columnconfigure(c, weight=0, minsize=0)

        self._columns = columns
        for i, tile in enumerate(self._tiles):
            tile.grid_forget()
        for i, tile in enumerate(self._tiles):
            tile.grid(row=i // columns, column=i % columns, padx=PAD, pady=PAD, sticky="nsew")
        # weight=1 so the columns share the full width between the gutters;
        # tiles stretch and redraw themselves via <Configure>.
        for c in range(columns):
            self.scrollable_frame.grid_columnconfigure(c, weight=1, uniform="tile", minsize=0)

    def _on_canvas_configure(self, event) -> None:
        self._relayout(self._columns_for(event.width))
        # Exactly SIDE_GUTTER px of background on each side — the grid is
        # pinned to that width rather than floating at its natural size.
        inner = max(event.width - 2 * SIDE_GUTTER, TILE_W)
        self.canvas.itemconfigure(self._window_id, width=inner)
        self.canvas.coords(self._window_id, SIDE_GUTTER, 0)

    def _on_frame_configure(self, event=None) -> None:
        # Anchor the scrollregion at x=0. Using bbox("all") directly makes
        # the region start at the left gutter, and Tk then treats that as
        # the canvas origin — which silently cancels the gutter offset.
        b = self.canvas.bbox("all")
        if b:
            self.canvas.configure(scrollregion=(0, 0, self.canvas.winfo_width(), b[3]))

    def _bind_wheel_recursive(self, widget=None) -> None:
        w = widget or self
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            w.bind(seq, self._on_mousewheel, add="+")
        for child in w.winfo_children():
            self._bind_wheel_recursive(child)

    def _on_mousewheel(self, event):
        """Scroll the tile grid. Mirrors the app-level logic: a 0 delta from
        a slow macOS trackpad drag must still scroll."""
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
            if abs(d) >= 120:
                step = int(-d / 120) or (-1 if d > 0 else 1)
            elif d:
                step = -1 if d > 0 else 1
            else:
                step = getattr(self, "_last_step", 0)
                if not step:
                    return
        self._last_step = step
        try:
            self.canvas.yview_scroll(step, "units")
        except tk.TclError:
            pass
        return "break"

    def _on_touchpad_scroll(self, event):
        """Tk 9 <TouchpadScroll>: delta packs deltaX (high 16 bits) and
        deltaY (low 16 bits), each signed 16-bit."""
        try:
            v = int(getattr(event, "delta", 0)) & 0xFFFFFFFF
        except (TypeError, ValueError):
            return "break"
        dy = v & 0xFFFF
        if dy >= 0x8000:
            dy -= 0x10000
        if dy == 0:
            return "break"
        self._tp_accum = getattr(self, "_tp_accum", 0) + dy
        if abs(self._tp_accum) < TRACKPAD_THRESHOLD:
            return "break"
        step = -1 if self._tp_accum > 0 else 1
        self._tp_accum = 0
        try:
            self.canvas.yview_scroll(step, "units")
        except tk.TclError:
            pass
        return "break"
