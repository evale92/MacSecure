"""
secure/agent/worktree.py — Phase 31: creates and tears down the one
thing every autonomous repair run is scoped to — an isolated `git
worktree` checked out from the live Secure repository, plus a
throwaway "agent home" directory used as HOME for every subprocess
this package ever spawns (the external tool AND Secure's own post-run
verification — see secure/agent/verify.py).

This is the concrete mechanism behind Phase 31's central trust
boundary: "the external agent may modify only the isolated worktree;
it must never directly modify the live Secure repository." A git
worktree is a full, separate working directory backed by the SAME
repository's object store (`git worktree add`) — files changed inside
it are never visible in the live checkout's own working tree unless a
human explicitly applies the diff later.

Unlike secure/validate/sandbox.py (a throwaway temp dir deleted the
instant its `with` block exits), a repair worktree must survive across
the tool run, verification, and a human's later review — so this
module deliberately does NOT use a context manager. Callers own the
worktree's lifetime explicitly via create_repair_worktree() /
remove_repair_worktree().

Both the worktree and its paired agent-home directory live under
`<app_dir>/agent_runs/<run_id>/` — self-contained per run, easy to
find, easy to audit, and never mixed with an OS temp directory some
other process could plausibly clean up while a change request is
still pending review. Phase 31 does not build automatic cleanup —
`<app_dir>/agent_runs/` accumulates until a human runs
`secure agent remove-worktree <run_id>` (Stage 7) or deletes it by
hand; see docs/AGENT_FOUNDATION.md.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from secure.agent.audit import now_iso, record_action

# secure/agent/worktree.py -> secure/agent -> secure -> project root
_PROJECT_ROOT = Path(__file__).resolve().parents[2]

AGENT_RUNS_DIRNAME = "agent_runs"


class WorktreeError(RuntimeError):
    """Raised when git itself fails to create/remove/inspect a worktree
    — never silently swallowed, since a caller that can't tell whether
    isolation actually happened must not proceed to invoke an external
    agent."""


@dataclass
class RepairWorktree:
    run_dir: Path
    worktree_path: Path
    agent_home_path: Path
    base_commit: str


def project_root() -> Path:
    return _PROJECT_ROOT


def _run_git(
    args: "list[str]",
    *,
    cwd: Path,
    timeout: float = 60.0,
    audit_trail: "Optional[list]" = None,
    action: str = "",
    mutating: bool = False,
    target: str = "",
) -> "subprocess.CompletedProcess":
    """The one seam every git subprocess call in this module goes
    through. `audit_trail`/`action`/`mutating`/`target` are all
    optional and purely additive (Phase 31.5) — when `audit_trail` is
    None (the default, and what every pre-existing caller/test still
    passes), this behaves EXACTLY as it did before that phase: same
    call, same return value, no extra work. Only when a caller supplies
    a real list (secure/agent/orchestrator.py) does this also time the
    call and append one redacted secure/agent/audit.py record to it."""
    argv = ["git", *args]
    if audit_trail is None:
        return subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=timeout, shell=False)

    started_at = now_iso()
    started_mono = time.monotonic()
    try:
        result = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True, timeout=timeout, shell=False)
        exit_code = result.returncode
        summary = f"exit {result.returncode}"
    except subprocess.TimeoutExpired:
        exit_code = None
        summary = f"timed out after {timeout}s"
        record_action(
            audit_trail, component="agent.worktree", action=action or " ".join(args), argv=argv,
            cwd=str(cwd), target=target, mutating=mutating, approval_required=False,
            started_at=started_at, exit_code=exit_code, result_summary=summary,
            duration_seconds=time.monotonic() - started_mono,
        )
        raise
    record_action(
        audit_trail, component="agent.worktree", action=action or " ".join(args), argv=argv,
        cwd=str(cwd), target=target, mutating=mutating, approval_required=False,
        started_at=started_at, exit_code=exit_code, result_summary=summary,
        duration_seconds=time.monotonic() - started_mono,
    )
    return result


def is_git_repository(repo_root: "Optional[Path]" = None, *, audit_trail: "Optional[list]" = None) -> bool:
    """Read-only, never raises — the honest-unavailable check every
    caller (secure/agent/policy.py, `secure agent status`) should run
    BEFORE attempting create_repair_worktree(), since `git worktree`
    has no meaning at all if the live Secure checkout isn't a git
    working copy in the first place. Phase 31's own testing showed
    this is a real, not merely hypothetical, precondition — see
    docs/AGENT_FOUNDATION.md."""
    repo_root = repo_root or _PROJECT_ROOT
    try:
        result = _run_git(
            ["rev-parse", "--is-inside-work-tree"], cwd=repo_root, timeout=10.0,
            audit_trail=audit_trail, action="git rev-parse --is-inside-work-tree", target=str(repo_root),
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"


def current_commit(repo_root: "Optional[Path]" = None, *, audit_trail: "Optional[list]" = None) -> str:
    repo_root = repo_root or _PROJECT_ROOT
    try:
        result = _run_git(
            ["rev-parse", "HEAD"], cwd=repo_root,
            audit_trail=audit_trail, action="git rev-parse HEAD", target=str(repo_root),
        )
    except FileNotFoundError as exc:
        raise WorktreeError(f"git is not available: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise WorktreeError(f"git rev-parse timed out in {repo_root}") from exc
    if result.returncode != 0:
        raise WorktreeError(f"could not resolve HEAD in {repo_root}: {result.stderr.strip()}")
    return result.stdout.strip()


def create_repair_worktree(
    run_id: str, *, app_dir: Path, repo_root: "Optional[Path]" = None, audit_trail: "Optional[list]" = None
) -> RepairWorktree:
    """Creates `git worktree add --detach <run_dir>/repo <base_commit>`
    plus an empty `<run_dir>/home` directory. Detached (not a new
    branch) on purpose — a repair attempt has no business creating a
    branch in the live repository's own ref namespace before a human
    has approved anything.
    """
    repo_root = repo_root or _PROJECT_ROOT
    base_commit = current_commit(repo_root, audit_trail=audit_trail)

    run_dir = Path(app_dir) / AGENT_RUNS_DIRNAME / run_id
    worktree_path = run_dir / "repo"
    agent_home_path = run_dir / "home"

    if run_dir.exists():
        raise WorktreeError(f"a run directory already exists at {run_dir} — refusing to overwrite it")

    run_dir.mkdir(parents=True, exist_ok=True)
    agent_home_path.mkdir(parents=True, exist_ok=True)

    result = _run_git(
        ["worktree", "add", "--detach", str(worktree_path), base_commit], cwd=repo_root,
        audit_trail=audit_trail, action="git worktree add --detach", mutating=True, target=str(worktree_path),
    )
    if result.returncode != 0:
        shutil.rmtree(run_dir, ignore_errors=True)
        raise WorktreeError(f"git worktree add failed: {result.stderr.strip()}")

    return RepairWorktree(
        run_dir=run_dir, worktree_path=worktree_path, agent_home_path=agent_home_path,
        base_commit=base_commit,
    )


def remove_repair_worktree(
    worktree: RepairWorktree, *, repo_root: "Optional[Path]" = None, audit_trail: "Optional[list]" = None
) -> None:
    """Removes the git worktree registration AND deletes the run
    directory from disk. Never called automatically by any run/verify
    step in this package — a human decides when a repair's worktree is
    no longer needed (after apply, after reject, or manual cleanup),
    never Secure on its own after a mere verification failure, since
    the worktree (and its transcript/diff) is exactly what a human
    needs to review to understand why it failed.
    """
    repo_root = repo_root or _PROJECT_ROOT
    if worktree.worktree_path.exists():
        _run_git(
            ["worktree", "remove", "--force", str(worktree.worktree_path)], cwd=repo_root,
            audit_trail=audit_trail, action="git worktree remove --force", mutating=True,
            target=str(worktree.worktree_path),
        )
    _run_git(
        ["worktree", "prune"], cwd=repo_root,
        audit_trail=audit_trail, action="git worktree prune", mutating=True, target=str(repo_root),
    )
    shutil.rmtree(worktree.run_dir, ignore_errors=True)
    record_action(
        audit_trail, component="agent.worktree", action="filesystem: rmtree run_dir",
        argv=[], cwd=str(repo_root), target=str(worktree.run_dir), mutating=True,
        started_at=now_iso(), result_summary="removed",
    )


def diff_and_changed_files(
    worktree: RepairWorktree, *, audit_trail: "Optional[list]" = None
) -> "tuple[str, list[str]]":
    """Secure's OWN, independent read of what the tool actually changed
    — never the tool's self-reported submission text (see
    secure/agent/runner.py). Returns (diff_text, changed_file_paths).
    An empty diff means the tool made no changes Secure can find,
    regardless of what it claims to have submitted.

    `git add -A -N .` (intent-to-add) is run first so newly created
    files show up in the diff too — plain `git diff` never shows
    untracked file content. Safe here only because this is always a
    throwaway worktree, never the live repository.
    """
    _run_git(
        ["add", "-A", "-N", "."], cwd=worktree.worktree_path,
        audit_trail=audit_trail, action="git add -A -N . (intent-to-add)", mutating=True,
        target=str(worktree.worktree_path),
    )
    status = _run_git(
        ["status", "--porcelain"], cwd=worktree.worktree_path,
        audit_trail=audit_trail, action="git status --porcelain", mutating=False,
        target=str(worktree.worktree_path),
    )
    changed_files = sorted({line[3:].strip() for line in status.stdout.splitlines() if line.strip()})

    diff = _run_git(
        ["diff", "--no-color"], cwd=worktree.worktree_path,
        audit_trail=audit_trail, action="git diff --no-color", mutating=False,
        target=str(worktree.worktree_path),
    )
    return diff.stdout, changed_files


def worktree_exists(worktree: RepairWorktree) -> bool:
    return worktree.worktree_path.is_dir() and (worktree.worktree_path / ".git").exists()
