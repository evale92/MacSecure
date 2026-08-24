"""Tkinter-dependent GUI helpers for the Secure control panel.

Unlike secure_gui/tokens.py, this module imports tkinter and cannot be
unit tested in an environment without it installed — it can only be
syntax-checked (`ast.parse`), the same limitation secure_gui.py itself
has always had. Keep this module's own logic thin: anything that can
be expressed as pure data/functions belongs in tokens.py or
data_access.py instead, where it's actually testable.

Stage 1 (this file's initial contents): font resolution only, backing
the typography correction in docs/DESIGN_SYSTEM.md — the normal
system UI font for prose/titles/buttons, Menlo/monospace reserved for
technical telemetry (IPs, MACs, hashes, paths, raw output).

Stage 2 adds: severity_badge(), status_badge(), mark_state_dialog(),
confirm_action() — the shared dialog/interaction helpers that replace
secure_gui.py's ~12 duplicated inline dialog chains.
"""

from __future__ import annotations

import tkinter as tk
import tkinter.font as tkfont
from tkinter import messagebox, simpledialog
from typing import Dict, Optional, Tuple

from secure_gui import tokens

# Cache is process-lifetime: named fonts don't change while the app is
# running, and tkfont.nametofont() requires a Tk root to already
# exist, so this is populated lazily on first use rather than at
# import time.
_TYPE_CACHE: "Dict[str, tuple] | None" = None


def resolve_fonts() -> Dict[str, Tuple]:
    """Resolve Tk's named system fonts into ready-to-use font tuples.

    Must only be called after a Tk root has been constructed (Tk's
    named fonts — TkDefaultFont, TkHeadingFont, TkFixedFont — don't
    exist until then). Returns a dict of role -> font tuple:

        title       Page/app titles.
        heading     Section headings, card titles.
        body        Ordinary prose: labels, buttons, dialogs,
                    explanations.
        body_bold   Emphasized prose.
        small       Secondary/caption text.
        mono        Technical telemetry: IPs, MACs, hashes, UUIDs,
                    ports, filesystem paths, raw command output.
        mono_bold   Emphasized technical telemetry.

    Deliberately never hardcodes a font family name (e.g. "Menlo") —
    it asks Tk for whatever the system's actual default UI font and
    fixed-width font are, so this keeps working correctly if that
    ever changes.
    """
    global _TYPE_CACHE
    if _TYPE_CACHE is not None:
        return _TYPE_CACHE

    default = tkfont.nametofont("TkDefaultFont").actual()
    try:
        heading = tkfont.nametofont("TkHeadingFont").actual()
    except Exception:
        # Not every Tk build ships TkHeadingFont; fall back to a
        # larger/bolder TkDefaultFont rather than failing.
        heading = default
    fixed = tkfont.nametofont("TkFixedFont").actual()

    default_family = default["family"]
    default_size = default["size"] or 13
    heading_family = heading["family"] or default_family
    heading_size = heading["size"] or (default_size + 2)
    fixed_family = fixed["family"]
    fixed_size = fixed["size"] or default_size

    _TYPE_CACHE = {
        "title": (default_family, default_size + 4, "bold"),
        "heading": (heading_family, heading_size, "bold"),
        "body": (default_family, default_size),
        "body_bold": (default_family, default_size, "bold"),
        "small": (default_family, max(default_size - 1, 9)),
        "mono": (fixed_family, fixed_size),
        "mono_bold": (fixed_family, fixed_size, "bold"),
    }
    return _TYPE_CACHE


# ---------- badges ----------
# Small read-only Label builders. Severity/status text always includes
# a glyph and a text label (from tokens.py) — color reinforces but is
# never the only signal, per docs/DESIGN_SYSTEM.md.


def severity_badge(parent: tk.Widget, severity: "str | None") -> tk.Label:
    """A small label showing a finding's severity (glyph + text + color).

    `severity` should be exactly the string the backend emitted (e.g.
    from an AlertRow) — this never invents a severity, it only looks
    up how to render whatever string it's given, falling back to an
    explicit "UNKNOWN SEVERITY" rendering for anything unrecognized.
    """
    fonts = resolve_fonts()
    return tk.Label(
        parent,
        text=tokens.severity_text(severity),
        fg=tokens.severity_color(severity),
        font=fonts["body_bold"],
    )


def status_badge(parent: tk.Widget, status: "str | None") -> tk.Label:
    """A small label showing sensor/scan health (glyph + text + color).

    See tokens.SENSOR_STATUS — this is deliberately a different
    vocabulary from severity_badge()'s. A sensor's health and what it
    found are independent facts and must never be visually conflated.
    """
    fonts = resolve_fonts()
    entry = tokens.SENSOR_STATUS.get((status or "").lower(), tokens.SENSOR_STATUS["unknown"])
    return tk.Label(
        parent,
        text=tokens.sensor_status_text(status),
        fg=entry["color"],
        font=fonts["body_bold"],
    )


# ---------- shared dialogs ----------


def mark_state_dialog(
    parent: tk.Widget,
    *,
    title: str,
    id_prompt: str,
    states: Tuple[str, str] = ("known", "unknown"),
    question: Optional[str] = None,
) -> Optional[Tuple[str, str]]:
    """Ask for an id, then ask which of two states to mark it as.

    Collapses the ~12 identical "askstring for an id, then askyesno
    for known/unknown (or trusted/untrusted)" dialog chains that used
    to be written out individually in secure_gui.py into one call.

    `states` is (state_if_yes, state_if_no) — e.g. ("known", "unknown")
    or ("trusted", "untrusted"). Returns (identifier, state), or None
    if either dialog was cancelled/left blank — callers should treat
    None exactly like a cancelled Command.build_args() (don't run
    anything).
    """
    identifier = simpledialog.askstring(title, id_prompt, parent=parent)
    if not identifier:
        return None

    state_yes, state_no = states
    if question is None:
        question = (
            f"Mark {identifier} as {state_yes.upper()}?\n\n"
            f"(Choose No to mark it {state_no}.)"
        )
    choose_yes = messagebox.askyesno(title, question, parent=parent)
    return identifier, (state_yes if choose_yes else state_no)


def confirm_action(parent: tk.Widget, *, title: str, body: str, destructive: bool = False) -> bool:
    """Standard yes/no confirmation.

    Per docs/DESIGN_SYSTEM.md: skip this entirely for harmless
    read-only actions (don't wrap every button in a confirmation).
    Use it for actions that change security state or can't be
    trivially undone. `destructive=True` adds a warning glyph to the
    dialog body — it does not change what buttons are offered
    (Tkinter's messagebox only offers Yes/No/Cancel wording, not
    custom button labels, without a much larger custom Toplevel that
    Product Phase 12 deliberately keeps out of scope).
    """
    prefix = "⚠ " if destructive else ""
    return messagebox.askyesno(title, f"{prefix}{body}", parent=parent)
