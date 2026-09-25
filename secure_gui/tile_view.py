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


class TileCategory:
    """Data holder for a category and its commands."""

    def __init__(self, name: str, commands: List[Tuple[str, List[str], bool]]):
        self.name = name
        self.commands = commands  # [(label, argv, nonzero_is_finding), ...]


class CategoryTileFrame(tk.Frame):
    """A single category tile with hover dropdown."""

    def __init__(
        self,
        parent: tk.Widget,
        category: TileCategory,
        run_command: RunCommand,
        fonts: Dict[str, Tuple],
        **kwargs
    ):
        super().__init__(parent, **kwargs)
        self.category = category
        self.run_command = run_command
        self.fonts = fonts
        self.dropdown_window: Optional[tk.Toplevel] = None

        self.config(
            bg="#f5f5f5",
            relief=tk.RAISED,
            bd=1,
            padx=12,
            pady=12,
            highlightthickness=1,
            highlightbackground="#ccc",
        )

        # Tile label
        self.label = tk.Label(
            self,
            text=category.name,
            font=fonts["body_bold"],
            bg="#f5f5f5",
            fg="#333",
        )
        self.label.pack(pady=4)

        # Command count
        count_label = tk.Label(
            self,
            text=f"{len(category.commands)} commands",
            font=fonts["small"],
            bg="#f5f5f5",
            fg="#666",
        )
        count_label.pack()

        # Hover indicator (shows on hover)
        self.hint = tk.Label(
            self,
            text="▼ Hover for commands",
            font=fonts["small"],
            bg="#f5f5f5",
            fg="#999",
        )
        self.hint.pack(pady=(4, 0))

        # Bindings for hover
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.label.bind("<Enter>", self._on_enter)
        self.label.bind("<Leave>", self._on_leave)
        count_label.bind("<Enter>", self._on_enter)
        count_label.bind("<Leave>", self._on_leave)
        self.hint.bind("<Enter>", self._on_enter)
        self.hint.bind("<Leave>", self._on_leave)

    def _on_enter(self, event=None):
        """Show dropdown on hover."""
        self.config(bg="#e8e8e8")
        self.label.config(bg="#e8e8e8")
        self._show_dropdown()

    def _on_leave(self, event=None):
        """Hide dropdown when mouse leaves."""
        self.config(bg="#f5f5f5")
        self.label.config(bg="#f5f5f5")
        self._hide_dropdown()

    def _show_dropdown(self):
        """Create and display the dropdown window."""
        if self.dropdown_window is not None:
            return

        # Position dropdown below the tile
        self.update_idletasks()
        x = self.winfo_rootx()
        y = self.winfo_rooty() + self.winfo_height() + 2

        self.dropdown_window = tk.Toplevel(self)
        self.dropdown_window.geometry(f"+{x}+{y}")
        self.dropdown_window.overrideredirect(True)
        self.dropdown_window.config(bg="#fff", relief=tk.RAISED, bd=1)

        # Add commands to dropdown
        for label, argv, nonzero_is_finding in self.category.commands:
            btn = tk.Button(
                self.dropdown_window,
                text=label,
                font=self.fonts["body"],
                bg="#fff",
                fg="#333",
                anchor="w",
                padx=12,
                pady=6,
                relief=tk.FLAT,
                command=lambda l=label, a=argv, n=nonzero_is_finding: self._execute_command(
                    l, a, n
                ),
            )
            btn.pack(fill=tk.X)
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg="#e8e8e8"))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg="#fff"))

        # Hide dropdown when mouse leaves it
        self.dropdown_window.bind("<Leave>", self._on_dropdown_leave)

    def _on_dropdown_leave(self, event=None):
        """Handle mouse leaving the dropdown."""
        if self.dropdown_window:
            # Check if mouse is still over the tile
            try:
                x, y = self.winfo_pointerx(), self.winfo_pointery()
                tile_x1 = self.winfo_rootx()
                tile_y1 = self.winfo_rooty()
                tile_x2 = tile_x1 + self.winfo_width()
                tile_y2 = tile_y1 + self.winfo_height()

                if not (tile_x1 <= x <= tile_x2 and tile_y1 <= y <= tile_y2):
                    self._hide_dropdown()
            except tk.TclError:
                pass

    def _hide_dropdown(self):
        """Destroy the dropdown window."""
        if self.dropdown_window is not None:
            self.dropdown_window.destroy()
            self.dropdown_window = None

    def _execute_command(self, label: str, argv: List[str], nonzero_is_finding: bool):
        """Execute a command and hide dropdown."""
        self._hide_dropdown()
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
        self.config(bg="#fff")

        # Create scrollable canvas
        self.canvas = tk.Canvas(self, bg="#fff", highlightthickness=0, height=400)
        self.scrollbar = tk.Scrollbar(self, orient=tk.VERTICAL, command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="#fff")

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")),
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Bind mousewheel
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<Button-4>", self._on_mousewheel)
        self.canvas.bind("<Button-5>", self._on_mousewheel)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create grid of tiles (3 columns)
        for i, category in enumerate(categories):
            row = i // 3
            col = i % 3

            tile = CategoryTileFrame(
                self.scrollable_frame,
                category,
                run_command,
                fonts,
                width=150,
                height=100,
            )
            tile.grid(row=row, column=col, padx=8, pady=8, sticky="nsew")

        # Configure grid weights for uniform sizing
        for i in range(3):
            self.scrollable_frame.grid_columnconfigure(i, weight=1)

    def _on_mousewheel(self, event):
        """Handle mousewheel scrolling."""
        if event.num == 5 or event.delta < 0:
            self.canvas.yview_scroll(3, "units")
        elif event.num == 4 or event.delta > 0:
            self.canvas.yview_scroll(-3, "units")
