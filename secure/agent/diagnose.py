"""
secure/agent/diagnose.py — Phase 43 (Part 2: Supervised Agentic
Development & Self-Healing — "Automated Failure Diagnosis").

Connects failure detection to the repair workflow, in the fixed order
the governing text requires
(docs/ROADMAP_PART2_PHASES_38_47.md):

    DETECT FAILURE -> REPRODUCE -> COLLECT MINIMAL RELEVANT CONTEXT ->
    PRIMARY AGENT DIAGNOSIS -> SANDBOX REPAIR -> TARGETED TESTS ->
    BROADER TESTS AS REQUIRED -> INDEPENDENT REVIEW

    "If the failure cannot be reproduced, record that explicitly. Do
    not fabricate a repair for a non-reproducible failure."

WHAT THIS PHASE ACTUALLY ADDS: THE REPRODUCE STEP

Every other box in that sequence already existed. Detection is Phase
31's `secure/agent/policy.py`. Bounded context is Phase 33's
`secure/agent/context.py` (built from traceback, failing test, affected
module, and recent history — never the whole repository). Diagnosis and
sandbox repair are Phase 31's orchestrator plus mini-SWE-agent.
Targeted and broader tests are Phase 36's tiers. Independent review is
Phase 38.

The missing box was REPRODUCE, and its absence mattered: without it,
Secure would spend a full repair cycle — a worktree, a model
invocation, a verification pass — on a test that no longer fails.
Worse, a coding agent handed a failure that does not actually occur has
nothing real to fix, and the most likely thing it produces is a
plausible-looking change that "fixes" nothing. That is the exact
fabrication the governing text forbids, and the cheapest way to prevent
it is to check first.

REPRODUCTION IS A GATE, NOT A HINT

`diagnose_failure()` refuses to proceed unless reproduction returned a
definite True. Not-reproduced stops. Inconclusive stops — the same
"inconclusive is never a pass" rule Phase 31's verification,
Phase 36's escalation, and Phase 38's review gate all already follow.
An honest "I could not confirm this still fails" is a useful result;
a repair built on it is not.

READ-ONLY, AND ISOLATED

Reproduction runs the failing test only, with HOME pinned to a
throwaway directory so a test that writes to `~/.secure` cannot touch
the operator's real one — the same discipline
`secure/agent/verify.py`'s `_isolated_env()` applies to verification.
It runs against the live checkout because that is what "does this
still fail RIGHT NOW" means, and it never writes there.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from secure.agent.audit import now_iso, record_action
from secure.agent.policy import (
    TRIGGER_DETECT_RULE_TEST_FAILURE,
    TRIGGER_PYTEST_FAILURE,
    TRIGGER_VALIDATE_SCENARIO_FAILURE,
    RepairCandidate,
)
from secure.agent.worktree import project_root
from secure.config import AppConfig

# Reproduction outcomes.
REPRO_REPRODUCED = "reproduced"          # the failure happens right now
REPRO_NOT_REPRODUCED = "not_reproduced"  # it passes now — nothing to repair
REPRO_UNAVAILABLE = "unavailable"        # the mechanism could not run
REPRO_TIMEOUT = "timeout"
REPRO_ERROR = "error"
REPRO_UNSUPPORTED = "unsupported"        # this trigger kind cannot be reproduced in isolation

# Only a definite REPRO_REPRODUCED permits a repair.
_PROCEED_STATUSES = (REPRO_REPRODUCED,)

_DEFAULT_TIMEOUT_SECONDS = 300.0
_MAX_DETAIL_CHARS = 4000


@dataclass(frozen=True)
class ReproductionResult:
    """`reproduced` is a THREE-state answer: True (it still fails),
    False (it passes now), or None (could not tell). None is never
    collapsed into either certainty."""

    status: str
    reproduced: "Optional[bool]"
    detail: str
    command: str
    duration_seconds: float

    @property
    def may_proceed_to_repair(self) -> bool:
        return self.status in _PROCEED_STATUSES and self.reproduced is True


def _truncate(text: str, limit: int = _MAX_DETAIL_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[{len(text) - limit} more characters truncated]"


def _isolated_home_env(home: Path) -> dict:
    """Same intent as secure/agent/verify.py's `_isolated_env()`, built
    here for a bare directory rather than a RepairWorktree. Not
    imported from there for the reason that module's own docstring
    gives about narrow safety boundaries: the two callers need
    different inputs, and widening one function's contract to serve
    both would loosen it."""
    import os

    env = dict(os.environ)
    env["HOME"] = str(home)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def reproduce_failure(
    candidate: RepairCandidate,
    cfg: AppConfig,
    *,
    root: "Optional[Path]" = None,
    timeout: "Optional[float]" = None,
    audit_trail: "Optional[list]" = None,
) -> ReproductionResult:
    """Re-runs ONLY the failing thing, right now, and reports whether it
    still fails. Never raises; every failure mode is a status.

    Deliberately narrow: for a pytest trigger this runs exactly the one
    node id, not the suite. Re-running the whole suite would be slower,
    would conflate this failure with unrelated ones, and would make a
    'reproduced' answer mean something weaker than it should.
    """
    root = root or project_root()
    timeout = timeout if timeout is not None else _DEFAULT_TIMEOUT_SECONDS

    if candidate.trigger_kind == TRIGGER_PYTEST_FAILURE:
        argv = [sys.executable, "-m", "pytest", candidate.trigger_ref, "-q", "--tb=short"]
    elif candidate.trigger_kind == TRIGGER_VALIDATE_SCENARIO_FAILURE:
        argv = [sys.executable, "-m", "secure", "validate", "run"]
    elif candidate.trigger_kind == TRIGGER_DETECT_RULE_TEST_FAILURE:
        argv = [sys.executable, "-m", "secure", "detect", "validate"]
    else:
        return ReproductionResult(
            status=REPRO_UNSUPPORTED, reproduced=None,
            detail=f"trigger kind {candidate.trigger_kind!r} has no defined reproduction command",
            command="", duration_seconds=0.0,
        )

    command = " ".join(argv)
    started_at = now_iso()
    started = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="secure-repro-home-") as home:
        env = _isolated_home_env(Path(home))
        try:
            proc = subprocess.run(
                argv, cwd=str(root), capture_output=True, text=True,
                timeout=timeout, shell=False, env=env,
            )
        except FileNotFoundError as exc:
            duration = time.monotonic() - started
            _audit(audit_trail, argv, root, started_at, None, "could not launch", duration)
            return ReproductionResult(
                status=REPRO_UNAVAILABLE, reproduced=None,
                detail=f"could not launch the reproduction command: {exc}",
                command=command, duration_seconds=duration,
            )
        except subprocess.TimeoutExpired:
            duration = time.monotonic() - started
            _audit(audit_trail, argv, root, started_at, None, f"timed out after {timeout}s", duration)
            return ReproductionResult(
                status=REPRO_TIMEOUT, reproduced=None,
                detail=f"the reproduction command timed out after {timeout}s — cannot tell whether "
                "the failure still occurs",
                command=command, duration_seconds=duration,
            )

    duration = time.monotonic() - started
    output = _truncate((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""))
    _audit(audit_trail, argv, root, started_at, proc.returncode, f"exit {proc.returncode}", duration)

    # A missing pytest is an unavailable MECHANISM, not a passing test.
    # Collapsing it into "not reproduced" would silently discard real
    # failures on a machine without pytest installed.
    if "No module named pytest" in output:
        return ReproductionResult(
            status=REPRO_UNAVAILABLE, reproduced=None,
            detail="pytest is not installed — cannot tell whether the failure still occurs",
            command=command, duration_seconds=duration,
        )

    if proc.returncode == 0:
        return ReproductionResult(
            status=REPRO_NOT_REPRODUCED, reproduced=False,
            detail="the failure did NOT recur — it passes now. Nothing was repaired. This may have "
            "been fixed already, or it may be flaky; either way there is nothing here to fix.\n\n"
            + output,
            command=command, duration_seconds=duration,
        )

    return ReproductionResult(
        status=REPRO_REPRODUCED, reproduced=True,
        detail=output, command=command, duration_seconds=duration,
    )


def _audit(audit_trail, argv, root, started_at, exit_code, summary, duration) -> None:
    record_action(
        audit_trail, component="agent.diagnose", action="reproduce", argv=argv, cwd=str(root),
        target=" ".join(argv[-2:]), mutating=False, started_at=started_at, exit_code=exit_code,
        result_summary=summary, duration_seconds=duration,
    )


# ---------------------------------------------------------------------
# The full sequence
# ---------------------------------------------------------------------

DIAGNOSIS_STOPPED_NOT_REPRODUCED = "stopped_not_reproduced"
DIAGNOSIS_STOPPED_INCONCLUSIVE = "stopped_inconclusive_reproduction"
DIAGNOSIS_REPAIRED = "repair_attempted"


@dataclass(frozen=True)
class DiagnosisResult:
    """What one full diagnosis pass did. `run` is the
    AgentRepairRunRecord when a repair was actually attempted, and None
    whenever reproduction stopped the sequence — there is no run
    because nothing ran, which is the honest representation of "we did
    not fabricate a repair"."""

    status: str
    candidate: RepairCandidate
    reproduction: ReproductionResult
    run: "Optional[object]" = None

    @property
    def repair_attempted(self) -> bool:
        return self.status == DIAGNOSIS_REPAIRED


def diagnose_failure(
    conn,
    cfg: AppConfig,
    candidate: RepairCandidate,
    *,
    root: "Optional[Path]" = None,
    providers: "Optional[dict]" = None,
    reproduce_timeout: "Optional[float]" = None,
) -> DiagnosisResult:
    """DETECT (already done — `candidate` came from
    secure/agent/policy.py) -> REPRODUCE -> everything Phase 31/33/36/38
    already do, in that order, and only if reproduction said yes.

    The bounded-context collection, the primary agent's diagnosis, the
    sandboxed repair, the targeted and broader tests, and the
    independent review are all `attempt_repair()`'s existing job. This
    function's contribution is the gate in front of them, and the
    honest record when that gate closes.
    """
    from secure.agent.audit import persist_audit_trail
    from secure.agent.orchestrator import attempt_repair

    audit_trail: list = []
    reproduction = reproduce_failure(
        candidate, cfg, root=root, timeout=reproduce_timeout, audit_trail=audit_trail
    )
    persist_audit_trail(conn, run_id=None, audit_trail=audit_trail)

    if reproduction.reproduced is False:
        return DiagnosisResult(
            status=DIAGNOSIS_STOPPED_NOT_REPRODUCED, candidate=candidate, reproduction=reproduction
        )
    if not reproduction.may_proceed_to_repair:
        # Inconclusive: the mechanism did not run cleanly. Treated
        # exactly like a failure to reproduce for the purpose of
        # proceeding — never as permission.
        return DiagnosisResult(
            status=DIAGNOSIS_STOPPED_INCONCLUSIVE, candidate=candidate, reproduction=reproduction
        )

    run = attempt_repair(conn, cfg, candidate, repo_root=root, providers=providers, reproduction=reproduction)
    return DiagnosisResult(
        status=DIAGNOSIS_REPAIRED, candidate=candidate, reproduction=reproduction, run=run
    )


def describe(result: DiagnosisResult) -> str:
    """Human-readable summary — used by the CLI and safe to log."""
    lines = [
        f"Trigger:       {result.candidate.trigger_kind}  {result.candidate.trigger_ref}",
        f"Reproduction:  {result.reproduction.status} (reproduced={result.reproduction.reproduced})",
        f"  command:     {result.reproduction.command or '(none)'}",
        f"  duration:    {result.reproduction.duration_seconds:.2f}s",
    ]
    if result.status == DIAGNOSIS_STOPPED_NOT_REPRODUCED:
        lines.append("Outcome:       STOPPED — the failure did not recur. No repair was attempted,")
        lines.append("               and none was fabricated.")
    elif result.status == DIAGNOSIS_STOPPED_INCONCLUSIVE:
        lines.append("Outcome:       STOPPED — reproduction was inconclusive. An inconclusive check")
        lines.append("               is not permission to repair.")
    else:
        run = result.run
        lines.append(f"Outcome:       repair attempted — run {getattr(run, 'run_id', '(unknown)')} "
                     f"status={getattr(run, 'status', '(unknown)')}")
    return "\n".join(lines)
