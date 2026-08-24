"""
secure/agent/policy.py — Phase 31: deterministic repair-trigger policy.

No model is ever called from this module. It decides two independent,
purely mechanical things:

1. Discovery — what test/validation failures currently exist to repair
   at all (find_pytest_failures(), find_validate_scenario_failures(),
   find_detect_rule_failures()). Each one reuses the exact existing
   authority for that failure kind — pytest's own exit code and
   ``FAILED`` lines, secure.validate.runner.run_validation_suite()'s
   own OUTCOME_MISS verdict, secure.detect.validate.validate_and_record()'s
   own VALIDATION_FAILED verdict — and adds no new pass/fail judgment
   of its own. "The deterministic test framework decides PASS or FAIL"
   (the same rule secure/ai/verify/__init__.py's rule 4 already lives
   by) applies here unchanged.

2. Eligibility — given ONE specific candidate, whether Secure is
   currently willing to start a repair attempt for it at all
   (evaluate_policy()): is this trigger kind in
   AppConfig.agent_allowed_trigger_kinds, has
   AppConfig.agent_max_attempts already been reached for this exact
   trigger, and is the live checkout even a usable git repository.

Per the governing instruction, Phase 31 restricts triggers to
deterministic test/validation failures ONLY — never a security
finding (an anomaly, a correlation alert, a raw detection match). If a
later phase ever wants to widen this, that is a new, explicit trigger
kind added here, never a loosening of an existing one.
"""

from __future__ import annotations

import subprocess
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from secure.agent.worktree import is_git_repository, project_root
from secure.config import AppConfig
from secure.storage.models import list_agent_repair_runs_for_trigger

TRIGGER_PYTEST_FAILURE = "pytest_failure"
TRIGGER_VALIDATE_SCENARIO_FAILURE = "validate_scenario_failure"
TRIGGER_DETECT_RULE_TEST_FAILURE = "detect_rule_test_failure"

ALL_TRIGGER_KINDS = (
    TRIGGER_PYTEST_FAILURE,
    TRIGGER_VALIDATE_SCENARIO_FAILURE,
    TRIGGER_DETECT_RULE_TEST_FAILURE,
)

_MAX_DETAIL_CHARS = 4000
_DEFAULT_PYTEST_TIMEOUT = 180.0


@dataclass(frozen=True)
class RepairCandidate:
    trigger_kind: str
    trigger_ref: str
    trigger_detail: str


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    attempts_so_far: int


def _truncate(text: str, limit: int = _MAX_DETAIL_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[{len(text) - limit} more characters truncated]"


def find_pytest_failures(
    *, root: "Optional[Path]" = None, timeout: float = _DEFAULT_PYTEST_TIMEOUT
) -> "list[RepairCandidate]":
    """Runs the project's own pytest suite once — fixed argv, no shell,
    the same subprocess-safety shape as secure/ai/verify/operations.py's
    op_run_pytest — and reports one candidate per failing test node id.
    Purely read-only: nothing here ever writes to the live repo."""
    root = root or project_root()
    tests_dir = root / "tests"
    if not tests_dir.is_dir():
        return []

    argv = [sys.executable, "-m", "pytest", str(tests_dir), "-q", "--tb=short"]
    try:
        proc = subprocess.run(
            argv, cwd=str(root), capture_output=True, text=True, timeout=timeout, shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if proc.returncode == 0:
        return []

    output = proc.stdout + "\n" + proc.stderr
    detail = _truncate(output)
    candidates: "list[RepairCandidate]" = []
    seen: "set[str]" = set()
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("FAILED "):
            continue
        node_id = line[len("FAILED "):].split(" - ")[0].split(" ")[0].strip()
        if node_id and node_id not in seen:
            seen.add(node_id)
            candidates.append(
                RepairCandidate(trigger_kind=TRIGGER_PYTEST_FAILURE, trigger_ref=node_id, trigger_detail=detail)
            )
    return candidates


def find_validate_scenario_failures(conn: sqlite3.Connection) -> "list[RepairCandidate]":
    """Runs secure/validate/'s own registered scenario suite once (the
    exact run_validation_suite() every `secure validate run` already
    calls) and reports one candidate per scenario whose outcome is
    OUTCOME_MISS — the unambiguous "this is broken" verdict. PARTIAL,
    NOT_EVALUABLE, and SENSOR_UNAVAILABLE are deliberately not treated
    as repair triggers: they are honest absence/partial states, not a
    clean deterministic failure."""
    from secure.validate import OUTCOME_MISS
    from secure.validate.runner import run_validation_suite

    summary = run_validation_suite(conn)
    candidates = []
    for result in summary.results:
        if result.outcome != OUTCOME_MISS:
            continue
        detail = _truncate(
            f"technique={result.technique_id} category={result.category} "
            f"expected={result.expected_result} outcome={result.outcome} notes={result.notes}"
        )
        candidates.append(
            RepairCandidate(
                trigger_kind=TRIGGER_VALIDATE_SCENARIO_FAILURE, trigger_ref=result.scenario_id, trigger_detail=detail
            )
        )
    return candidates


def find_detect_rule_failures(conn: sqlite3.Connection, cfg: AppConfig) -> "list[RepairCandidate]":
    """Runs secure/detect/'s own fixture validation (the exact
    validate_and_record() every `secure detect test` already calls)
    against every cataloged rule and reports one candidate per rule
    whose overall verdict is VALIDATION_FAILED."""
    from secure.detect.validate import VALIDATION_FAILED, validate_and_record
    from secure.storage.models import list_detection_rules

    candidates = []
    for record in list_detection_rules(conn):
        updated, outcomes = validate_and_record(conn, cfg, record)
        if updated.validation_status != VALIDATION_FAILED:
            continue
        failing = [o for o in outcomes if not o.passed]
        detail = _truncate(
            "\n".join(
                f"fixture={o.fixture_name} expected={o.expected} actual={o.actual} detail={o.detail}"
                for o in failing
            )
        )
        candidates.append(
            RepairCandidate(
                trigger_kind=TRIGGER_DETECT_RULE_TEST_FAILURE,
                trigger_ref=f"{updated.family}:{updated.rule_key}",
                trigger_detail=detail,
            )
        )
    return candidates


def find_repair_candidates(
    conn: sqlite3.Connection, cfg: AppConfig, *, root: "Optional[Path]" = None
) -> "list[RepairCandidate]":
    """Discovery across every trigger kind Phase 31 supports, restricted
    to whatever AppConfig.agent_allowed_trigger_kinds currently permits.
    Order matters only for presentation — pytest first (cheapest,
    fastest signal), then validate, then detect."""
    candidates: "list[RepairCandidate]" = []
    if TRIGGER_PYTEST_FAILURE in cfg.agent_allowed_trigger_kinds:
        candidates.extend(find_pytest_failures(root=root))
    if TRIGGER_VALIDATE_SCENARIO_FAILURE in cfg.agent_allowed_trigger_kinds:
        candidates.extend(find_validate_scenario_failures(conn))
    if TRIGGER_DETECT_RULE_TEST_FAILURE in cfg.agent_allowed_trigger_kinds:
        candidates.extend(find_detect_rule_failures(conn, cfg))
    return candidates


def evaluate_policy(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    candidate: RepairCandidate,
    *,
    repo_root: "Optional[Path]" = None,
) -> PolicyDecision:
    """Whether Secure is currently willing to start a NEW repair attempt
    for this exact candidate. Every check here is deterministic and
    config-driven — nothing about "does this look fixable" is judged;
    that question belongs entirely to the external tool once (and only
    if) a run actually starts."""
    if candidate.trigger_kind not in ALL_TRIGGER_KINDS:
        return PolicyDecision(allowed=False, reason=f"unknown trigger kind {candidate.trigger_kind!r}", attempts_so_far=0)

    if candidate.trigger_kind not in cfg.agent_allowed_trigger_kinds:
        return PolicyDecision(
            allowed=False,
            reason=f"trigger kind {candidate.trigger_kind!r} is not in agent_allowed_trigger_kinds",
            attempts_so_far=0,
        )

    if not is_git_repository(repo_root):
        return PolicyDecision(
            allowed=False,
            reason="the Secure checkout is not a git repository — `git worktree` isolation is not possible here",
            attempts_so_far=0,
        )

    prior = list_agent_repair_runs_for_trigger(
        conn, trigger_kind=candidate.trigger_kind, trigger_ref=candidate.trigger_ref
    )
    attempts_so_far = len(prior)
    if attempts_so_far >= cfg.agent_max_attempts:
        return PolicyDecision(
            allowed=False,
            reason=f"agent_max_attempts ({cfg.agent_max_attempts}) already reached for this trigger "
            f"({attempts_so_far} prior attempt(s)) — stopping rather than retrying indefinitely",
            attempts_so_far=attempts_so_far,
        )

    already_verified = any(r.status == "verified" for r in prior)
    if already_verified:
        return PolicyDecision(
            allowed=False,
            reason="a prior attempt against this exact trigger already produced a verified repair "
            "(see its change request) — not starting another one",
            attempts_so_far=attempts_so_far,
        )

    return PolicyDecision(allowed=True, reason="eligible", attempts_so_far=attempts_so_far)
