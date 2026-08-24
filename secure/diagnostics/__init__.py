"""
secure/diagnostics/ — Phase 30: Performance & Diagnostics.

Answers "what hardware is this, how loaded is it, how much is Secure
itself using, which modules are expensive, and is anything worth a
plain factual warning" — deliberately NOT a security-detection layer
(see this package's own module docstrings and docs/PERFORMANCE.md).
Nothing here ever writes to a severity/anomaly/correlation/explanation
table, and nothing in those layers ever imports from this package —
enforced by the same lower-never-imports-higher rule every other layer
in docs/ARCHITECTURE.md follows, just applied in the other direction:
this package is only ever called FROM the interfaces layer
(secure/cli/, secure_gui.py), never from a sensor/integration/analysis
module.

Submodules:
    hardware.py    — static hardware/environment facts, never persisted
    system.py      — live system health, never persisted
    self_usage.py  — Secure's own current-process resource usage
    instrument.py  — per-operation timing wrapper (writes
                     perf_module_runs), used only at CLI call sites
    budgets.py      — plain factual threshold warnings, never security
                       alerts
    tools.py         — generic external-process (e.g. Claude) resource
                        aggregate
    milestones.py    — perf_milestones read/write
    report.py         — sanitized Markdown+JSON diagnostics report
"""

from __future__ import annotations
