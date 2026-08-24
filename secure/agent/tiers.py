"""
secure/agent/tiers.py — Phase 36 (Part 2: Supervised Agentic
Development & Self-Healing — "Tiered Test Orchestration").

Defines a lean, four-tier verification escalation policy — FAST,
TARGETED, FULL, SECURITY VALIDATION — reusing Phase 27's `secure
validate` suite and Phase 31's own pytest-in-worktree machinery
unchanged wherever possible. Per the governing instruction ("Create a
lean test-orchestration policy using existing pytest and validation
infrastructure... do not run the entire suite unnecessarily"), this
module adds only the two tiers that didn't already exist (FAST,
TARGETED) and an escalation function that decides how far to go — it
does not reimplement FULL or SECURITY VALIDATION, which are already
exactly `secure/agent/verify.py`'s `run_pytest_in_worktree()` and
`run_validate_in_worktree()`, called here unchanged.

FAST is deliberately pytest-free (syntax check via `compileall` plus
an import check) so it has no dependency on pytest being installed at
all — the cheapest possible signal, always available. TARGETED reuses
the exact "map a changed file to its module, then to
`tests/test_<module>*.py`" idea Phase 33's own
`secure/agent/context.py` already established for a different purpose
(finding relevant history for a repair prompt) — here applied to
finding relevant tests instead of relevant history.

This phase deliberately does NOT rewire
`secure/agent/orchestrator.py`'s existing `_finish_repair_run()`, which
today always runs the FULL tier (pytest) and SECURITY tier (`secure
validate run`) unconditionally after every repair attempt. That is a
conservative, already-verified, already-tested default, and changing
it would be an unreviewed behavior change to the live repair flow, not
merely an additive one. Phase 44 ("Verified Self-Healing") explicitly
requires "FAST verification passes, TARGETED tests pass, FULL
regression passes when required, Phase 27 validation passes when
security behavior is affected" as part of its own VERIFIED criteria —
the exact vocabulary this module defines — so this module is
groundwork for that phase to consume, not a replacement for Phase 31's
existing, safer-by-default verification call today.
"""

from __future__ import annotations

import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from secure.agent.audit import now_iso, record_action
from secure.agent.verify import VerifyResult, _isolated_env, run_pytest_in_worktree, run_validate_in_worktree
from secure.agent.worktree import RepairWorktree
from secure.config import AppConfig

TIER_FAST = "fast"
TIER_TARGETED = "targeted"
TIER_FULL = "full"
TIER_SECURITY = "security_validation"

ALL_TIERS = (TIER_FAST, TIER_TARGETED, TIER_FULL, TIER_SECURITY)

_FAST_TIMEOUT_SECONDS = 60.0
_MAX_SUMMARY_CHARS = 4000

# Heuristic only — deliberately separate from AppConfig.agent_path_denylist
# (which BLOCKS an agent edit outright). This list only decides whether
# to escalate VERIFICATION depth; it is intentionally conservative
# ("when uncertain, escalate" — the same spirit Phase 39 will later
# apply to change classification) rather than an attempt at a complete
# security-relevance classifier.
SECURITY_SENSITIVE_PREFIXES = (
    "secure/validate/",
    "secure/detect/",
    "secure/integrations/",
    "secure/evidence/",
    "secure/correlate/",
    "secure/ai/",
    "secure/agent/",
    "secure/fileintegrity/",
    "secure/persistence/",
)


@dataclass(frozen=True)
class TierResult:
    tier: str
    status: str  # "ok" | "fail" | "unavailable" | "timeout" | "error"
    passed: "Optional[bool]"
    summary: str
    duration_seconds: float
    commands: "tuple[str, ...]" = field(default_factory=tuple)


@dataclass(frozen=True)
class EscalationOutcome:
    """Everything one call to choose_and_run_verification() did —
    "store exact commands, results, duration, and relevant
    revision/diff identity" (the phase's own words): `revision` and
    `diff_hash` carry the identity, each TierResult's own `commands`
    carries the exact argv, `duration_seconds` is on every TierResult,
    and `audit_trail` (when the caller supplied one) carries the same
    per-command timestamp/exit-code detail Phase 31.5 already
    established for every subprocess this package runs."""

    fast: TierResult
    targeted: "Optional[TierResult]"
    full: "Optional[TierResult]"
    security: "Optional[TierResult]"
    stopped_at: str
    revision: str
    changed_files: "tuple[str, ...]"
    diff_hash: "Optional[str]" = None

    @property
    def overall_passed(self) -> "Optional[bool]":
        """None when any tier that actually ran didn't cleanly resolve
        to a definite pass/fail (same "inconclusive is not a pass"
        rule VerificationOutcome.overall_passed already establishes) —
        never silently treated as success."""
        ran = [r for r in (self.fast, self.targeted, self.full, self.security) if r is not None]
        if any(r.status != "ok" for r in ran):
            return None
        if any(r.passed is None for r in ran):
            return None
        return all(r.passed for r in ran)


def _truncate(text: str, limit: int = _MAX_SUMMARY_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[{len(text) - limit} more characters truncated]"


def _run_one(
    tier: str,
    argv: "list[str]",
    *,
    cwd: Path,
    env: dict,
    timeout: float,
    audit_trail: "Optional[list]" = None,
    target: str = "",
) -> "tuple[Optional[subprocess.CompletedProcess], float, Optional[TierResult]]":
    """The one seam every tier's subprocess call goes through — mirrors
    secure/agent/verify.py's own fixed-argv/no-shell/hard-timeout shape
    rather than importing it, for the same reason verify.py's own
    docstring gives for not importing secure/ai/verify/operations.py: a
    narrow safety boundary shouldn't be loosened just to add one more
    caller.

    Returns (proc, duration_seconds, early_result). `early_result` is
    non-None only for the FileNotFoundError/TimeoutExpired paths, where
    there is no proc to interpret and the caller should return it
    directly. On success, `proc` is set and `early_result` is None —
    the caller interprets `proc.returncode`/output for that tier's own
    pass/fail rule and builds its own TierResult using the returned
    duration."""
    started_at = now_iso()
    started_mono = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=str(cwd), env=env, capture_output=True, text=True, timeout=timeout, shell=False)
    except FileNotFoundError as exc:
        duration = time.monotonic() - started_mono
        record_action(
            audit_trail, component="agent.tiers", action=f"{tier} tier", argv=argv, cwd=str(cwd),
            target=target, mutating=False, started_at=started_at, exit_code=None,
            result_summary="could not launch", duration_seconds=duration,
        )
        return None, duration, TierResult(tier, "unavailable", None, f"could not launch: {exc}", duration, (" ".join(argv),))
    except subprocess.TimeoutExpired:
        duration = time.monotonic() - started_mono
        record_action(
            audit_trail, component="agent.tiers", action=f"{tier} tier", argv=argv, cwd=str(cwd),
            target=target, mutating=False, started_at=started_at, exit_code=None,
            result_summary=f"timed out after {timeout}s", duration_seconds=duration,
        )
        return None, duration, TierResult(tier, "timeout", None, f"timed out after {timeout}s", duration, (" ".join(argv),))

    duration = time.monotonic() - started_mono
    record_action(
        audit_trail, component="agent.tiers", action=f"{tier} tier", argv=argv, cwd=str(cwd),
        target=target, mutating=False, started_at=started_at, exit_code=proc.returncode,
        result_summary=f"exit {proc.returncode}", duration_seconds=duration,
    )
    return proc, duration, None


# ---------- FAST ----------


def run_fast_tier(worktree: RepairWorktree, cfg: AppConfig, *, audit_trail: "Optional[list]" = None) -> TierResult:
    """Syntax check (`python -m compileall`) plus an import check
    (`python -c "import secure"`), both pytest-free so this tier has no
    dependency on pytest being installed — always the cheapest possible
    signal. Neither check ever mutates anything in the worktree, but
    both still run with HOME isolated to the throwaway agent-home
    directory (same discipline as every other subprocess this package
    spawns), since an import can execute arbitrary module-level code."""
    env = _isolated_env(worktree)
    commands: "list[str]" = []

    targets = [p for p in ("secure", "secure_gui", "tests") if (worktree.worktree_path / p).exists()]
    if not targets:
        return TierResult(TIER_FAST, "unavailable", None, "no secure/secure_gui/tests directory found in worktree", 0.0, ())

    compile_argv = [sys.executable, "-m", "compileall", "-q", *targets]
    commands.append(" ".join(compile_argv))
    proc, d1, early = _run_one(
        TIER_FAST, compile_argv, cwd=worktree.worktree_path, env=env, timeout=_FAST_TIMEOUT_SECONDS,
        audit_trail=audit_trail, target=str(worktree.worktree_path),
    )
    if early is not None:
        return early
    if proc.returncode != 0:
        return TierResult(TIER_FAST, "ok", False, _truncate(proc.stdout + "\n" + proc.stderr), d1, tuple(commands))

    import_argv = [sys.executable, "-c", "import secure"]
    commands.append(" ".join(import_argv))
    proc2, d2, early2 = _run_one(
        TIER_FAST, import_argv, cwd=worktree.worktree_path, env=env, timeout=_FAST_TIMEOUT_SECONDS,
        audit_trail=audit_trail, target=str(worktree.worktree_path),
    )
    if early2 is not None:
        return early2

    passed = proc2.returncode == 0
    summary = "syntax and import checks passed" if passed else _truncate(proc2.stdout + "\n" + proc2.stderr)
    return TierResult(TIER_FAST, "ok", passed, summary, d1 + d2, tuple(commands))


# ---------- TARGETED ----------


def _module_segment(changed_file: str) -> "Optional[str]":
    """secure/agent/context.py -> 'agent' (a subpackage); secure/widget.py
    -> 'widget' (a leaf module directly under secure/, so the segment
    is its own stem, not a directory name); secure_gui/agent_view.py ->
    'gui'; a bare top-level file or anything outside secure/secure_gui
    -> None (nothing to target)."""
    parts = Path(changed_file).parts
    if not parts:
        return None
    if parts[0] == "secure":
        if len(parts) == 2:
            return Path(parts[1]).stem
        if len(parts) >= 3:
            return parts[1]
        return None
    if parts[0] == "secure_gui":
        return "gui"
    return None


def targeted_test_files(changed_files: "list[str]", root: Path) -> "list[str]":
    """Deterministic, bounded, no model call: any changed file already
    under tests/ is targeted directly; every other changed file under
    secure/<module>/... or secure_gui/... contributes
    tests/test_<module>*.py (and tests/test_gui*.py for secure_gui) if
    such a file exists. Returns [] — never a guess — when nothing
    matches, which callers must treat as "nothing targeted," not "an
    empty tests directory passed.\""""
    matched: "set[str]" = {f for f in changed_files if f.startswith("tests/") and f.endswith(".py")}
    tests_dir = root / "tests"
    if tests_dir.is_dir():
        segments = {s for s in (_module_segment(f) for f in changed_files) if s}
        for segment in segments:
            for p in sorted(tests_dir.glob(f"test_{segment}*.py")):
                matched.add(str(p.relative_to(root)))
    return sorted(matched)


def run_pytest_targeted(
    worktree: RepairWorktree, cfg: AppConfig, test_files: "list[str]", *, audit_trail: "Optional[list]" = None
) -> TierResult:
    if not test_files:
        return TierResult(TIER_TARGETED, "unavailable", None, "no test files targeted by the changed files", 0.0, ())

    argv = [sys.executable, "-m", "pytest", *test_files, "-q", "--tb=short"]
    env = _isolated_env(worktree)
    proc, duration, early = _run_one(
        TIER_TARGETED, argv, cwd=worktree.worktree_path, env=env, timeout=cfg.agent_verify_timeout_seconds,
        audit_trail=audit_trail, target=str(worktree.worktree_path),
    )
    if early is not None:
        return early

    output = proc.stdout + "\n" + proc.stderr
    if "No module named pytest" in output:
        return TierResult(TIER_TARGETED, "unavailable", None, "pytest is not installed", duration, (" ".join(argv),))

    passed = proc.returncode == 0
    return TierResult(TIER_TARGETED, "ok", passed, _truncate(output), duration, (" ".join(argv),))


# ---------- escalation ----------


def _touches_security_sensitive_paths(changed_files: "list[str]") -> bool:
    return any(f.startswith(prefix) for f in changed_files for prefix in SECURITY_SENSITIVE_PREFIXES)


def _to_tier_result(verify_result: "VerifyResult", tier: str) -> TierResult:
    return TierResult(tier, verify_result.status, verify_result.passed, verify_result.summary, 0.0, ())


def choose_and_run_verification(
    worktree: RepairWorktree,
    cfg: AppConfig,
    changed_files: "list[str]",
    *,
    diff_hash: "Optional[str]" = None,
    force_full: bool = False,
    audit_trail: "Optional[list]" = None,
) -> EscalationOutcome:
    """The escalation policy itself: FAST always runs first and stops
    everything on a definite failure (no point running slower tiers
    against code that doesn't even import). Otherwise TARGETED runs
    against whatever tests map to `changed_files`. FULL escalates when
    TARGETED found nothing to target, TARGETED itself didn't pass
    cleanly, the caller forced it, or `changed_files` is empty (unknown
    scope is treated conservatively, the same "when uncertain, choose
    the more restrictive option" spirit Phase 39 will later formalize
    for change classification). SECURITY VALIDATION runs whenever any
    changed file touches a security-sensitive path, or scope is
    unknown."""
    fast = run_fast_tier(worktree, cfg, audit_trail=audit_trail)
    if fast.passed is False:
        return EscalationOutcome(
            fast=fast, targeted=None, full=None, security=None, stopped_at=TIER_FAST,
            revision=worktree.base_commit, changed_files=tuple(changed_files), diff_hash=diff_hash,
        )

    unknown_scope = not changed_files
    test_files = targeted_test_files(changed_files, worktree.worktree_path) if changed_files else []
    targeted = run_pytest_targeted(worktree, cfg, test_files, audit_trail=audit_trail) if test_files else None

    needs_full = force_full or unknown_scope or targeted is None or targeted.passed is not True
    full = _to_tier_result(run_pytest_in_worktree(worktree, cfg, audit_trail=audit_trail), TIER_FULL) if needs_full else None

    security_relevant = unknown_scope or _touches_security_sensitive_paths(changed_files)
    security = _to_tier_result(run_validate_in_worktree(worktree, cfg, audit_trail=audit_trail), TIER_SECURITY) if security_relevant else None

    if security is not None:
        stopped_at = TIER_SECURITY
    elif full is not None:
        stopped_at = TIER_FULL
    elif targeted is not None:
        stopped_at = TIER_TARGETED
    else:
        stopped_at = TIER_FAST

    return EscalationOutcome(
        fast=fast, targeted=targeted, full=full, security=security, stopped_at=stopped_at,
        revision=worktree.base_commit, changed_files=tuple(changed_files), diff_hash=diff_hash,
    )
