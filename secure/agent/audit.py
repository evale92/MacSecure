"""
secure/agent/audit.py — Phase 31.5: Agent Action Audit.

Makes every externally visible action secure/agent/ (or its CLI)
performs — every subprocess, every git operation, every filesystem-
changing operation, and every proposed/actual system change —
independently reviewable, without adding any new autonomous behavior.
This module records; it never decides, gates, or authorizes anything.

Design, in one sentence: every subprocess-invoking function in
secure/agent/ (worktree.py, runner.py, verify.py) accepts an OPTIONAL
`audit_trail: Optional[list]` parameter. When it's `None` — the
default, and what every pre-existing call site and every pre-existing
test still passes — `record_action()` is a no-op and behavior is
byte-for-byte identical to before this phase. Only
secure/agent/orchestrator.py (which owns a real database connection
and a run_id) actually creates a real list, threads it through one
attempt/resume/revalidate call, and persists it in one batch via
`persist_audit_trail()`. This keeps every low-level module pure and
DB-connection-free (so every existing monkeypatch-based test in
tests/test_agent.py that patches `module.subprocess.run` still fully
intercepts the real call — nothing about *how* a subprocess is
invoked changed, only that its metadata can optionally be captured
alongside it), while still achieving one honest, queryable audit
trail per run.

Redaction (the "do not log secrets/env credentials/model prompts
containing secrets/sensitive file contents" requirement):

  - Environment variables are NEVER part of an audited action at all —
    no call site here ever passes `env` into an audit record; the only
    place `HOME` overrides are constructed is directly in
    worktree.py/runner.py/verify.py's own subprocess.run() calls,
    never logged.
  - Every argv token is passed through `redact_argv()`: a token
    matching a common secret-shaped pattern (api key/secret/password/
    token/bearer/authorization, case-insensitive) is replaced outright
    with `[REDACTED]`; any token longer than `_MAX_ARGV_TOKEN_CHARS`
    (covers mini-SWE-agent's own `-t "<task text>"` — effectively the
    model prompt) is truncated to a short prefix plus a length note,
    never stored verbatim, regardless of whether it happens to contain
    a secret.
  - `result_summary` is always a short, call-site-computed description
    ("exit 0", "3 changed files", "12 scenarios ok") — never raw
    subprocess stdout/stderr, which could otherwise carry file
    contents a test happened to print. Verbose pytest/validate output
    is not duplicated here; it already lives in
    `agent_repair_runs.pytest_summary`/`validate_summary` (Phase 31),
    which this module does not change.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from typing import Optional

_SECRET_TOKEN_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|secret|password|passwd|token|bearer|authorization)\b"
)
_MAX_ARGV_TOKEN_CHARS = 200
_MAX_SUMMARY_CHARS = 300


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact_token(token) -> str:
    text = token if isinstance(token, str) else str(token)
    if _SECRET_TOKEN_PATTERN.search(text):
        return "[REDACTED]"
    if len(text) > _MAX_ARGV_TOKEN_CHARS:
        return text[:80] + f"...[TRUNCATED, {len(text)} chars total]"
    return text


def redact_argv(argv: "Optional[list]") -> list:
    """Applied to every argv this module ever records — never the raw
    list. Safe to call with None (returns [])."""
    return [_redact_token(t) for t in (argv or [])]


def _redact_summary(summary: str) -> str:
    if not summary:
        return ""
    if _SECRET_TOKEN_PATTERN.search(summary):
        return "[summary withheld: contained a secret-shaped token]"
    if len(summary) > _MAX_SUMMARY_CHARS:
        return summary[:_MAX_SUMMARY_CHARS] + f"...[TRUNCATED, {len(summary)} chars total]"
    return summary


def record_action(
    audit_trail: "Optional[list]",
    *,
    component: str,
    action: str,
    argv: "Optional[list]" = None,
    cwd: "Optional[str]" = None,
    target: str = "",
    mutating: bool = False,
    approval_required: bool = False,
    started_at: "Optional[str]" = None,
    exit_code: "Optional[int]" = None,
    result_summary: str = "",
    duration_seconds: "Optional[float]" = None,
) -> None:
    """Appends one already-redacted entry to `audit_trail` — a plain
    list the CALLER owns and later hands to persist_audit_trail(). A
    no-op when `audit_trail` is None, which is the default at every
    subprocess call site in worktree.py/runner.py/verify.py — see this
    module's own docstring for why that matters."""
    if audit_trail is None:
        return
    audit_trail.append(
        {
            "timestamp": started_at or now_iso(),
            "component": component,
            "action": action,
            "argv": redact_argv(argv),
            "cwd": cwd,
            "target": target,
            "mutating": mutating,
            "approval_required": approval_required,
            "exit_code": exit_code,
            "result_summary": _redact_summary(result_summary),
            "duration_seconds": duration_seconds,
        }
    )


def persist_audit_trail(conn: sqlite3.Connection, *, run_id: "Optional[str]", audit_trail: "Optional[list]") -> None:
    """Bulk-persists everything record_action() collected during one
    attempt/resume/revalidate call, in one place, right before that
    call returns — see secure/agent/orchestrator.py. A no-op for an
    empty or None trail (nothing to write)."""
    if not audit_trail:
        return
    from secure.storage.models import add_agent_action

    for entry in audit_trail:
        add_agent_action(conn, run_id=run_id, **entry)


def record_and_persist_one(
    conn: sqlite3.Connection,
    *,
    run_id: "Optional[str]",
    component: str,
    action: str,
    argv: "Optional[list]" = None,
    cwd: "Optional[str]" = None,
    target: str = "",
    mutating: bool = False,
    approval_required: bool = False,
    started_at: "Optional[str]" = None,
    exit_code: "Optional[int]" = None,
    result_summary: str = "",
    duration_seconds: "Optional[float]" = None,
) -> None:
    """Convenience for callers that already have a live `conn` and
    just need to log ONE action immediately (secure/agent/changes.py's
    propose/supersede, secure/cli/agent.py's approve/remove-worktree) —
    equivalent to record_action() into a throwaway one-element list
    followed by persist_audit_trail(), without the caller needing to
    manage a list itself."""
    trail: list = []
    record_action(
        trail, component=component, action=action, argv=argv, cwd=cwd, target=target,
        mutating=mutating, approval_required=approval_required, started_at=started_at,
        exit_code=exit_code, result_summary=result_summary, duration_seconds=duration_seconds,
    )
    persist_audit_trail(conn, run_id=run_id, audit_trail=trail)
