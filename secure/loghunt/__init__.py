"""
secure.loghunt — bounded, fixed searches of the macOS unified log.

The unified log records decisions no other sensor sees: Gatekeeper
assessing an app, XProtect's behavioural rules firing, XProtect
Remediator reporting a scan, TCC denying an app a permission, the
"downloaded from the internet" prompt. `secure loghunt` runs a fixed set
of `log show` predicates over a bounded window, on request, and
summarises the matches by message template, so tens of thousands of
lines become a short table of what happened and how often.

Rules it keeps:
    - point-in-time and operator-requested, never a background watcher
    - fixed predicates only; nothing a user types becomes a predicate
    - `/usr/bin/log` through loghunt/_shell.py, fixed argv, timeout-bound
    - window capped at MAX_HOURS
    - a hunt that could not complete is ERROR/UNAVAILABLE, never a
      clean zero. `log show` ends ndjson output with a
      {"count": N, "finished": 1} line, and a hunt without that line
      (a timeout, a killed process) is marked incomplete

What a zero means: the predicate matched nothing in the window. The
predicates were measured on macOS 26 on 2026-09-16. Apple renames
subsystems between releases, so a zero on another version may mean the
predicate went stale, which the report says.

Source: rmusser01/Infosec_Reference @af8b68e Draft/L-SM-TH.md 1139-1175
(macOS Logging, Unified Log; hoakley's log series; "Logs Unite!").
"""

from __future__ import annotations

from secure.loghunt.hunts import HUNTS, MAX_HOURS, HuntResult, run_hunts

__all__ = ["HUNTS", "MAX_HOURS", "HuntResult", "run_hunts"]
