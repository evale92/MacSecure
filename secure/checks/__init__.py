"""
secure.checks — read-only macOS security posture checks (Phase 2).

See PROJECT_NOTES.md ("Phase 2 — macOS Security Posture Check") for
the full list of what's checked and the design rules every check in
this package follows:

    - Read-only. Nothing in this package changes any system setting.
    - No sudo, ever. If a check needs administrator privileges to get
      a definitive answer, it reports WARNING and explains how to
      check manually instead of escalating privileges on its own.
    - Short timeouts, so one slow/hung command can't hang the whole
      posture check.
    - Scoped to this Mac only — every check inspects local state
      (system commands, local preference files, or the loopback
      interface). Nothing here reaches out to another machine on your
      network.

Typical usage:

    from secure.checks import run_all_checks

    for result in run_all_checks():
        print(result.status.value, result.name, result.message)
"""

from __future__ import annotations

from secure.checks.models import CheckResult, CheckStatus
from secure.checks.runner import run_all_checks

__all__ = ["CheckResult", "CheckStatus", "run_all_checks"]
