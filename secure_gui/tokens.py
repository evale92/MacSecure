"""Design tokens for the Secure control panel — pure data, no Tkinter.

This module deliberately imports nothing from `tkinter`. Everything in
it is a plain dict, tuple, or function, so it can be unit tested in
any environment (including one where Tkinter itself isn't installed —
see PROJECT_NOTES.md) and so `secure_gui/components.py` and
`secure_gui/alerts_view.py` (both Tkinter-dependent) have one shared,
testable source of truth instead of re-deriving glyphs/wording/colors
independently.

Four vocabularies live here, and they are kept deliberately separate
rather than merged into one generic "status" concept, because they
answer different questions and conflating them would misrepresent
what the backend actually knows:

    SEVERITY      "How bad is this finding, if it's real?"
                  Backend-owned. Must match secure/*/scanner.py and
                  secure/correlate's severity strings exactly — this
                  module never invents a severity the backend doesn't
                  emit.

    SENSOR_STATUS "Did the sensor/scan itself work?"
                  Independent of severity: a scan can succeed and find
                  nothing (clean), succeed and find something serious
                  (high severity), or the sensor itself can be
                  unavailable/degraded/permission-blocked regardless
                  of what it would have found. This module's status
                  vocabulary is deliberately allowed to be ahead of
                  what any given backend module currently reports —
                  see docs/DESIGN_SYSTEM.md for which of these 7
                  states each package can currently distinguish today.

    RUN_OUTCOME   "How did *this GUI button click's* subprocess exit?"
                  A GUI-owned concept, not a backend one. A command
                  can exit nonzero for reasons that have nothing to do
                  with sensor health (e.g. "no alert with that id") —
                  see Command.nonzero_is_finding in secure_gui.py.
                  Keeping this separate from SENSOR_STATUS avoids
                  implying the backend reported something it didn't.

    EMPTY_STATE   "Why is this list/table showing nothing right now?"
                  Five states that must never look the same, because
                  "no data yet" and "sensor unavailable" are very
                  different situations that both render as an empty
                  list unless the UI is explicit about which one this
                  is.

A fifth, Product-Phase-13 vocabulary lives here too:

    CONFIDENCE    "How strongly does the stored evidence support
                  Secure's interpretation of this finding?"
                  Presentation only — the MEANING of each confidence
                  level (CONFIRMED/LIKELY/UNCERTAIN/
                  INSUFFICIENT_EVIDENCE) is owned by
                  secure/explain/vocab.py, not here. This table only
                  maps those same backend-owned strings to a
                  glyph/color, exactly the way SEVERITY above maps
                  backend severity strings — it never redefines what a
                  confidence level means, and it's deliberately a
                  different glyph/color set than SEVERITY's, so a
                  confidence badge can never be mistaken for a
                  severity badge at a glance.

Every dict below has an "unknown"/fallback entry, so a lookup on an
unexpected key never raises and never silently renders as blank.
"""

from __future__ import annotations

# ---------- spacing ----------

SPACE = {
    "xs": 4,
    "sm": 8,
    "md": 12,
    "lg": 16,
    "xl": 24,
}

# ---------- color palette ----------
# The console pane's existing dark theme, plus severity/status colors
# chosen to stay legible on both the dark console background and the
# light-ish default background ttk.Treeview uses on macOS. Color is
# always paired with a glyph and a text label everywhere these are
# used — see SEVERITY/SENSOR_STATUS below — never the only signal.

COLORS = {
    "console_bg": "#0c0c0c",
    "console_fg": "#d0d0d0",
    "console_cmd": "#59d1ff",
    "console_stderr": "#ff6b6b",
    "console_meta": "#8a8a8a",
    "console_click": "#e0c341",
    "severity_critical": "#8c0f2a",
    "severity_high": "#c1382d",
    "severity_medium": "#b5750a",
    "severity_low": "#2f6f9f",
    "severity_informational": "#5a5a5a",
    "severity_unknown": "#8a8a8a",
    "status_success": "#2a9d3f",
    "status_degraded": "#b5750a",
    "status_unavailable": "#5a5a5a",
    "status_permission_required": "#8a5a1f",
    "status_timeout": "#a15a1f",
    "status_failed": "#c1382d",
    "status_not_yet_run": "#8a8a8a",
    "status_unknown": "#8a8a8a",
    # A distinct palette from severity_*/status_* above — blues/teals
    # rather than the red/amber/green severity uses — so a confidence
    # badge reads as visually different from a severity badge, never
    # as "another severity."
    "confidence_confirmed": "#1f6f5c",
    "confidence_likely": "#2f6f9f",
    "confidence_uncertain": "#6a5a1f",
    "confidence_insufficient_evidence": "#5a5a5a",
    "confidence_unknown": "#8a8a8a",
}

# ---------- severity (backend-owned vocabulary) ----------
# Keys must match the `severity` strings the backend actually emits:
# secure/fileintegrity emits low/medium/high; older modules emit
# medium/high only; secure/correlate emits all five. "informational"
# and "critical" are included because correlate can emit them, and so
# this table is complete even for modules that don't use the full
# range yet. "rank" is only for sorting (higher = more severe); it is
# never shown to the user.

SEVERITY = {
    "critical": {"glyph": "◆◆", "label": "CRITICAL", "color": COLORS["severity_critical"], "rank": 5},
    "high": {"glyph": "◆", "label": "HIGH", "color": COLORS["severity_high"], "rank": 4},
    "medium": {"glyph": "▲", "label": "MEDIUM", "color": COLORS["severity_medium"], "rank": 3},
    "low": {"glyph": "●", "label": "LOW", "color": COLORS["severity_low"], "rank": 2},
    "informational": {"glyph": "·", "label": "INFO", "color": COLORS["severity_informational"], "rank": 1},
    "unknown": {"glyph": "?", "label": "UNKNOWN SEVERITY", "color": COLORS["severity_unknown"], "rank": 0},
}


def severity_text(severity: "str | None") -> str:
    """Glyph + label for a severity string, e.g. '◆ HIGH'.

    Falls back to the "unknown" entry for None, empty, or any string
    the backend hasn't emitted before — this must never raise, since
    it's meant to be safe to call on raw data straight out of the
    database.
    """
    entry = SEVERITY.get((severity or "").lower(), SEVERITY["unknown"])
    return f"{entry['glyph']} {entry['label']}"


def severity_color(severity: "str | None") -> str:
    entry = SEVERITY.get((severity or "").lower(), SEVERITY["unknown"])
    return entry["color"]


# ---------- confidence (Product Phase 13 — presentation only) ----------
# Keys are exactly secure.explain.vocab's CONFIDENCE_* string
# constants (confirmed/likely/uncertain/insufficient_evidence) — this
# table never defines what they mean (see vocab.py for that), only how
# to draw them. A deliberately different glyph set from SEVERITY's
# (circles/rings rather than diamonds/triangles) so the two badge
# types are never visually interchangeable.

CONFIDENCE = {
    "confirmed": {"glyph": "●●", "label": "CONFIRMED", "color": COLORS["confidence_confirmed"]},
    "likely": {"glyph": "●", "label": "LIKELY", "color": COLORS["confidence_likely"]},
    "uncertain": {"glyph": "◐", "label": "UNCERTAIN", "color": COLORS["confidence_uncertain"]},
    "insufficient_evidence": {"glyph": "○", "label": "INSUFFICIENT EVIDENCE", "color": COLORS["confidence_insufficient_evidence"]},
    "unknown": {"glyph": "?", "label": "UNKNOWN CONFIDENCE", "color": COLORS["confidence_unknown"]},
}


def confidence_text(confidence: "str | None") -> str:
    """Glyph + label for a confidence string, e.g. '●● CONFIRMED'.

    Falls back to the "unknown" entry for None, empty, or any string
    secure/explain/vocab.py hasn't defined — must never raise, same
    discipline as severity_text() above.
    """
    entry = CONFIDENCE.get((confidence or "").lower(), CONFIDENCE["unknown"])
    return f"{entry['glyph']} {entry['label']}"


def confidence_color(confidence: "str | None") -> str:
    entry = CONFIDENCE.get((confidence or "").lower(), CONFIDENCE["unknown"])
    return entry["color"]


def severity_rank(severity: "str | None") -> int:
    entry = SEVERITY.get((severity or "").lower(), SEVERITY["unknown"])
    return entry["rank"]


# ---------- sensor / scan health ----------
# What a sensor or scan actually did, independent of what it found.
# Deliberately allowed to be ahead of backend support: most packages
# today only ever produce SUCCESS or FAILED (a plain exit code), and
# only persistence currently distinguishes UNAVAILABLE. The rest of
# this vocabulary exists so the GUI has somewhere correct to render
# these states once a given backend module grows the ability to report
# them — see docs/DESIGN_SYSTEM.md for the current per-module gap list.
# Until then, callers must not guess DEGRADED/UNAVAILABLE/etc. from
# incomplete information; use "not_yet_run" or "unknown" instead.

SENSOR_STATUS = {
    "success": {"glyph": "✓", "label": "SUCCESS", "color": COLORS["status_success"]},
    "degraded": {"glyph": "⚠", "label": "DEGRADED", "color": COLORS["status_degraded"]},
    "unavailable": {"glyph": "–", "label": "UNAVAILABLE", "color": COLORS["status_unavailable"]},
    "permission_required": {
        "glyph": "\U0001f512",
        "label": "PERMISSION REQUIRED",
        "color": COLORS["status_permission_required"],
    },
    "timeout": {"glyph": "⏱", "label": "TIMED OUT", "color": COLORS["status_timeout"]},
    "failed": {"glyph": "✕", "label": "FAILED", "color": COLORS["status_failed"]},
    "not_yet_run": {"glyph": "○", "label": "NOT YET RUN", "color": COLORS["status_not_yet_run"]},
    "unknown": {"glyph": "?", "label": "UNKNOWN STATUS", "color": COLORS["status_unknown"]},
}


def sensor_status_text(status: "str | None") -> str:
    entry = SENSOR_STATUS.get((status or "").lower(), SENSOR_STATUS["unknown"])
    return f"{entry['glyph']} {entry['label']}"


# ---------- GUI run outcome ----------
# How one button click's subprocess ended. This is a GUI-execution
# concept, not a sensor-health one — see the module docstring. Used
# only by secure_gui.py's _execute() for its own final console line.

RUN_OUTCOME = {
    "success": {"glyph": "✓", "label": "completed successfully"},
    "findings": {"glyph": "⚑", "label": "completed — findings above worth reviewing"},
    "stopped": {"glyph": "⏹", "label": "stopped by you"},
    "timeout": {"glyph": "⏱", "label": "timed out and was stopped"},
    "failed": {"glyph": "✕", "label": "command failed"},
}


def run_outcome_text(outcome: str) -> str:
    entry = RUN_OUTCOME.get(outcome, {"glyph": "?", "label": outcome})
    return f"{entry['glyph']} {entry['label']}"


# ---------- empty / result states ----------
# Five states a list/table can be in that must never render the same
# way. Each has example wording a screen can use directly or adapt.

EMPTY_STATE = {
    "no_data_yet": {
        "glyph": "○",
        "heading": "No data yet",
        "body": "Nothing has been scanned yet. Run a scan to populate this list.",
    },
    "clean_result": {
        "glyph": "✓",
        "heading": "Clean — nothing to review",
        "body": "The most recent scan completed and found nothing worth flagging.",
    },
    "filtered_empty": {
        "glyph": "–",
        "heading": "No matches for this filter",
        "body": "There is data, but nothing matches the current filter. Try clearing it.",
    },
    "unavailable": {
        "glyph": "⚠",
        "heading": "Unavailable",
        "body": "This sensor could not run. This is not the same as a clean result — see Diagnostics.",
    },
    "permission_required": {
        "glyph": "\U0001f512",
        "heading": "Permission required",
        "body": "macOS has not granted the permission this needs yet. This is not the same as a clean result.",
    },
}


# ---------- UI chrome themes ----------
#
# These recolour the app's *chrome* only — window background, tiles,
# buttons, headers. The severity_*/status_*/confidence_* palettes above
# are a backend-owned vocabulary and are deliberately NOT themed: a
# CRITICAL badge must stay red whatever skin the window is wearing.

THEMES = {
    # Warm coffee palette: Espresso / Roast Brown / Caramel / Latte / Foam
    "Espresso": {
        "accent":      "#5A3B2E",   # Roast Brown
        "accent_text": "#FFF8F0",   # Foam
        "app_bg":      "#F3E7D6",   # Latte Cream
        "panel_bg":    "#FFF8F0",   # Foam
        "tile_bg":     "#FFF8F0",
        "tile_hover":  "#C9B19C",   # Caramel / Crema
        "tile_border": "#C9B19C",
        "text":        "#2B1B14",   # Espresso
        "text_muted":  "#5A3B2E",
        "btn_bg":      "#FFF8F0",
        "btn_active":  "#C9B19C",
    },
    # Dark variant of the same palette
    "Espresso Dark": {
        "accent":      "#CBBBA0",
        "accent_text": "#2B1B14",
        "app_bg":      "#2B1B14",
        "panel_bg":    "#3B2B24",
        "tile_bg":     "#3B2B24",
        "tile_hover":  "#8A6F57",
        "tile_border": "#8A6F57",
        "text":        "#E8DCC8",
        "text_muted":  "#CBBBA0",
        "btn_bg":      "#3B2B24",
        "btn_active":  "#8A6F57",
    },
    "McAfee": {
        "accent":      "#C01818",
        "accent_text": "#ffffff",
        "app_bg":      "#f4f4f4",
        "panel_bg":    "#ffffff",
        "tile_bg":     "#ffffff",
        "tile_hover":  "#fdecec",
        "tile_border": "#d8d8d8",
        "text":        "#1f1f1f",
        "text_muted":  "#6b6b6b",
        "btn_bg":      "#ffffff",
        "btn_active":  "#f2d6d6",
    },
    "Facebook": {
        "accent":      "#1877F2",   # core Facebook blue
        "accent_text": "#FFFFFF",
        "app_bg":      "#F0F2F5",
        "panel_bg":    "#FFFFFF",
        "tile_bg":     "#FFFFFF",
        "tile_hover":  "#E7F5FF",   # soft blue
        "tile_border": "#898F9C",
        "text":        "#000000",
        "text_muted":  "#4B4C4F",
        "btn_bg":      "#FFFFFF",
        "btn_active":  "#E7F5FF",
    },
    "Discord": {
        "accent":      "#5865F2",   # Blurple
        "accent_text": "#FFFFFF",
        "app_bg":      "#23272A",   # Shark
        "panel_bg":    "#2C2F33",
        "tile_bg":     "#2C2F33",
        "tile_hover":  "#5865F2",
        "tile_border": "#23272A",
        "text":        "#FFFFFF",
        "text_muted":  "#B5BAC1",
        "btn_bg":      "#2C2F33",
        "btn_active":  "#5865F2",
    },
}

# Brand status colours, available to views that want them. Deliberately NOT
# wired into severity_*/status_* — those stay a backend vocabulary.
DISCORD_STATUS = {
    "green": "#57F287", "yellow": "#FEE75C",
    "fuchsia": "#EB459E", "red": "#ED4245",
}

DEFAULT_THEME = "Espresso"
_active = DEFAULT_THEME


def set_theme(name: str) -> None:
    global _active
    if name in THEMES:
        _active = name


def theme_name() -> str:
    return _active


def ui(key: str) -> str:
    """Current theme's value for a chrome colour."""
    return THEMES[_active][key]
