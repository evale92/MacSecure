"""
secure/agent/context.py — Phase 33 (Part 2: Supervised Agentic
Development & Self-Healing — "mini-SWE-agent Repair Integration").

Builds the BOUNDED repair context Secure hands to mini-SWE-agent
alongside Phase 31's RepairCandidate (secure/agent/policy.py):
relevant/affected files, recent history for those files, and (once
Phase 37 exists) engineering-policy excerpts — never the entire
repository. Per the governing instruction ("Do not dump the entire
repository into model context by default. Prefer targeted retrieval
based on: traceback, failing tests, imports, affected module, recent
changes, relevant architecture documentation"), everything this module
builds is derived deterministically from `candidate` and the live
checkout, then size-bounded before it is ever rendered into a prompt.

This module owns NO reasoning about the failure and makes NO decision
about how to fix it — mini-SWE-agent's own reasoning loop (invoked by
secure/agent/runner.py, entirely unmodified by this phase) still owns
that completely. This module only assembles read-only, deterministic
retrieval results into a bounded text block that
secure/agent/runner.py's `_build_task_text()` appends to the existing
task prompt when a caller supplies one — the "context" argument is
optional and defaults to None everywhere it's threaded through, so
every pre-Phase-33 call site (and every existing test) behaves
identically without it.

Nothing here invokes git in a way that mutates anything: `git log` is
read-only, and it is safe to run against the LIVE checkout (not the
isolated worktree) because the worktree is itself a checkout of that
same history at the same base commit — reading the live repo's commit
log for a handful of already-known file paths reveals nothing the
worktree's own `git log` wouldn't also show, and avoids paying for a
second working copy just to read history.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from secure.agent.policy import TRIGGER_PYTEST_FAILURE, RepairCandidate
from secure.agent.worktree import project_root

# Bounds — deliberately small. This is "targeted retrieval," not a
# second copy of the repository; a handful of files and a handful of
# log lines per file is enough for a coding agent to orient itself
# without turning the prompt into an unbounded context dump.
_MAX_FILES = 5
_MAX_LOG_LINES_PER_FILE = 5
_GIT_LOG_TIMEOUT_SECONDS = 10.0

# Phase 37 ("Engineering Policy") is expected to add these files. Until
# it does, none of them exist and this module honestly includes
# nothing rather than fabricating policy text.
_POLICY_FILENAMES = ("AGENTS.md", "ARCHITECTURE_RULES.md", "SECURITY_INVARIANTS.md", "TESTING_POLICY.md")
_MAX_POLICY_CHARS_PER_FILE = 3000

# Matches pytest's own "--tb=short" traceback frame lines, e.g.
# "secure/widget.py:12: in do_thing" — the same textual shape
# secure/agent/policy.py's find_pytest_failures() already captures
# verbatim into RepairCandidate.trigger_detail.
_TRACEBACK_FILE_RE = re.compile(r"^(?P<path>[\w./\\-]+\.py):\d+: in ", re.MULTILINE)


@dataclass(frozen=True)
class RepairContext:
    """Everything this module retrieved for one RepairCandidate,
    already bounded. `affected_files` only ever contains paths that
    were verified to exist in the live checkout at build time — never a
    guessed or fabricated path. `recent_changes`/`policy_excerpts` map
    only to entries this module actually found; a file with no history
    or a policy file that doesn't exist yet is simply absent from the
    dict, not present with empty/placeholder text."""

    affected_files: "tuple[str, ...]"
    recent_changes: "dict[str, str]"
    policy_excerpts: "dict[str, str]"
    workspace_note: str


def _extract_affected_files(candidate: RepairCandidate, root: Path) -> "tuple[str, ...]":
    """Deterministic, regex/heuristic-based file discovery — no model
    call, no repository-wide search. For a pytest failure, the failing
    test's own file is always included first (derived straight from the
    node id pytest itself reported); any other file paths mentioned in
    the traceback text are added next, in the order they appear. A path
    that doesn't actually exist in `root` is silently skipped — this
    function never reports a guess as a fact."""
    files: "list[str]" = []
    seen: "set[str]" = set()

    def _add(rel: str) -> None:
        rel = rel.strip()
        if not rel or rel in seen or len(files) >= _MAX_FILES:
            return
        if not (root / rel).is_file():
            return
        seen.add(rel)
        files.append(rel)

    if candidate.trigger_kind == TRIGGER_PYTEST_FAILURE:
        _add(candidate.trigger_ref.split("::")[0])

    for match in _TRACEBACK_FILE_RE.finditer(candidate.trigger_detail):
        if len(files) >= _MAX_FILES:
            break
        _add(match.group("path"))

    return tuple(files)


def _git_log_for_file(root: Path, rel_path: str) -> str:
    """Up to `_MAX_LOG_LINES_PER_FILE` one-line commit summaries for a
    single file, read-only. Returns "" (never raises) when git is
    unavailable, the path has no history, or the command times out —
    honest absence, exactly like every other optional-signal function
    in this project."""
    try:
        proc = subprocess.run(
            ["git", "log", f"-{_MAX_LOG_LINES_PER_FILE}", "--oneline", "--", rel_path],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=_GIT_LOG_TIMEOUT_SECONDS,
            shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def _load_policy_excerpts(root: Path) -> "dict[str, str]":
    """Reads whichever of Phase 37's future engineering-policy files
    already exist at `root`. Returns {} today (none of them exist yet)
    — once Phase 37 adds AGENTS.md etc., every future repair task
    automatically includes them with zero change to this function."""
    excerpts: "dict[str, str]" = {}
    for name in _POLICY_FILENAMES:
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if len(text) > _MAX_POLICY_CHARS_PER_FILE:
            text = text[:_MAX_POLICY_CHARS_PER_FILE] + f"\n...[{len(text) - _MAX_POLICY_CHARS_PER_FILE} more characters truncated]"
        excerpts[name] = text
    return excerpts


def build_repair_context(candidate: RepairCandidate, *, root: "Optional[Path]" = None) -> RepairContext:
    """The one entry point callers (secure/agent/orchestrator.py) use.
    Pure with respect to its inputs modulo the live checkout's current
    state on disk — the same discipline build_mini_argv() already
    documents for itself, since this context text becomes part of the
    same task prompt that function renders."""
    root = root or project_root()
    affected_files = _extract_affected_files(candidate, root)
    recent_changes = {f: log for f in affected_files if (log := _git_log_for_file(root, f))}
    policy_excerpts = _load_policy_excerpts(root)
    workspace_note = (
        "You may only read and modify files inside your current working directory "
        "(an isolated git worktree). Nothing outside it is reachable or relevant to this task."
    )
    return RepairContext(
        affected_files=affected_files,
        recent_changes=recent_changes,
        policy_excerpts=policy_excerpts,
        workspace_note=workspace_note,
    )


def render_context_block(context: RepairContext) -> str:
    """Renders a RepairContext into the text block appended to the task
    prompt. Every section is OMITTED entirely (not shown with an empty
    body) when there is nothing real for it — never "no relevant files
    found" filler text that could itself mislead the model."""
    parts: "list[str]" = []

    if context.affected_files:
        parts.append("Relevant files:\n" + "\n".join(f"- {f}" for f in context.affected_files))
        history_lines = [
            f"{f}:\n{context.recent_changes[f]}" for f in context.affected_files if f in context.recent_changes
        ]
        if history_lines:
            parts.append("Recent relevant history (most recent commits touching these files):\n" + "\n\n".join(history_lines))

    if context.policy_excerpts:
        policy_lines = [f"--- {name} ---\n{text}" for name, text in context.policy_excerpts.items()]
        parts.append("Engineering policy (must be followed):\n" + "\n\n".join(policy_lines))

    parts.append(context.workspace_note)
    return "\n\n".join(parts)
