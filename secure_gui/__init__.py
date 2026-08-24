"""secure_gui — the desktop control panel's own package.

This package holds GUI-support code that used to live entirely inside
the single top-level `secure_gui.py` script. It's split out (rather
than grown in place) so that the pure-data/pure-logic pieces — design
tokens, and later the read-only display-data layer — can be unit
tested directly, without needing Tkinter itself to be importable. See
docs/DESIGN_SYSTEM.md for the design system this package implements,
and SOFTWARE_ENGINEERING_PLAN.md for why this line was drawn here.

Module map:
    tokens.py        Pure data + pure functions (no tkinter import).
                      Spacing, color, severity, sensor-health, and
                      empty-state vocabulary shared by the whole GUI.
    components.py     Tkinter-dependent. Small reusable widget
                      builders and dialog helpers (fonts, badges,
                      the shared "mark known/unknown" dialog, a
                      standard confirmation dialog).
    data_access.py    Pure data + pure functions (no tkinter import).
                      The thin, read-only display-data layer described
                      in docs/DESIGN_SYSTEM.md: reads alert records via
                      secure.storage.models for display only. All
                      state-changing actions still go through the CLI
                      subprocess path in secure_gui.py, unchanged.
    alerts_view.py    Tkinter-dependent. The Alerts DataTable +
                      EvidencePanel pilot screen.

Nothing in this package changes what any `secure` CLI command does —
it only changes how the existing GUI presents and triggers it.
"""

from __future__ import annotations
