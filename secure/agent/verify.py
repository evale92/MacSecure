"""
secure/agent/verify.py — Phase 31: deterministic acceptance criteria
for a repair attempt. Two checks, both run as fresh subprocesses
against the worktree, never in-process:

    1. `python3 -m pytest <worktree>/tests -q` — does the worktree's
       OWN test suite pass. Because Python's `-m` prepends the process
       working directory to sys.path[0], running this with
       cwd=<worktree> naturally imports the WORKTREE's own `secure/`
       package (Secure has no setup.py install — it's always imported
       from whatever directory is first on sys.path), not whatever
       version happens to be already imported in this process. This is
       what makes "verification exercises the repaired code" true
       without needing a second Python interpreter or a reinstall step.

    2. `python3 -m secure validate run` — does Secure's own synthetic
       ATT&CK validation suite still pass, run the exact same way, for
       the exact same reason: cwd=<worktree> means this invocation
       imports and exercises the worktree's own secure/validate/ code.

Both subprocess calls set HOME to the run's own throwaway agent-home
directory (secure/agent/worktree.py's RepairWorktree.agent_home_path)
— this is the one deliberate difference from
secure/ai/verify/operations.py's op_run_pytest, which intentionally
inherits the calling process's real HOME because IT is meant to verify
the live, real installation. Phase 31 verification must never let a
misbehaving test in a repaired worktree write to the operator's actual
`~/.secure/secure.db`, so `secure validate run`'s own database (and
anything pytest touches via the real HOME) lands in the throwaway
directory instead, exactly like secure/validate/sandbox.py's own
"never the operator's real database" rule one level up.

This module does not import or call secure/ai/verify/operations.py's
functions directly — not because that package's discipline is wrong,
but because its fixed subprocess calls don't accept an environment
override, and rule 1 of that package ("FIXED OPERATION ENUM ONLY") is
exactly the kind of narrow safety boundary that shouldn't be loosened
just to add one more parameter for a different caller. This module
mirrors its exact safety shape (fixed argv, no shell, hard timeout,
status vs. verdict kept separate) as a small, independent
implementation instead.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional

from secure.agent.audit import now_iso, record_action
from secure.agent.worktree import RepairWorktree
from secure.config import AppConfig

_MAX_SUMMARY_CHARS = 4000


@dataclass
class VerifyResult:
    status: str  # "ok" | "fail" | "unavailable" | "timeout" | "error"
    passed: "Optional[bool]"
    summary: str


def _truncate(text: str, limit: int = _MAX_SUMMARY_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[{len(text) - limit} more characters truncated]"


def _isolated_env(worktree: RepairWorktree) -> dict:
    env = dict(os.environ)
    env["HOME"] = str(worktree.agent_home_path)
    return env


def run_pytest_in_worktree(
    worktree: RepairWorktree, cfg: AppConfig, *, audit_trail: "Optional[list]" = None
) -> VerifyResult:
    tests_dir = worktree.worktree_path / "tests"
    if not tests_dir.is_dir():
        return VerifyResult(status="unavailable", passed=None, summary="no tests/ directory in the worktree")

    argv = [sys.executable, "-m", "pytest", str(tests_dir), "-q", "--tb=short"]
    started_at = now_iso()
    started_mono = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=str(worktree.worktree_path),
            env=_isolated_env(worktree),
            capture_output=True,
            text=True,
            timeout=cfg.agent_verify_timeout_seconds,
            shell=False,
        )
    except FileNotFoundError as exc:
        record_action(
            audit_trail, component="agent.verify", action="pytest run (worktree)", argv=argv,
            cwd=str(worktree.worktree_path), target=str(tests_dir), mutating=False,
            started_at=started_at, exit_code=None, result_summary="could not launch pytest",
            duration_seconds=time.monotonic() - started_mono,
        )
        return VerifyResult(status="unavailable", passed=None, summary=f"could not launch pytest: {exc}")
    except subprocess.TimeoutExpired:
        record_action(
            audit_trail, component="agent.verify", action="pytest run (worktree)", argv=argv,
            cwd=str(worktree.worktree_path), target=str(tests_dir), mutating=False,
            started_at=started_at, exit_code=None,
            result_summary=f"timed out after {cfg.agent_verify_timeout_seconds}s",
            duration_seconds=time.monotonic() - started_mono,
        )
        return VerifyResult(
            status="timeout", passed=None,
            summary=f"pytest did not finish within {cfg.agent_verify_timeout_seconds}s",
        )

    output = proc.stdout + "\n" + proc.stderr
    if "No module named pytest" in output:
        record_action(
            audit_trail, component="agent.verify", action="pytest run (worktree)", argv=argv,
            cwd=str(worktree.worktree_path), target=str(tests_dir), mutating=False,
            started_at=started_at, exit_code=proc.returncode, result_summary="pytest not installed",
            duration_seconds=time.monotonic() - started_mono,
        )
        return VerifyResult(status="unavailable", passed=None, summary="pytest is not installed in this environment")

    passed = proc.returncode == 0
    record_action(
        audit_trail, component="agent.verify", action="pytest run (worktree)", argv=argv,
        cwd=str(worktree.worktree_path), target=str(tests_dir), mutating=False,
        started_at=started_at, exit_code=proc.returncode,
        result_summary=f"exit {proc.returncode} ({'passed' if passed else 'failed'})",
        duration_seconds=time.monotonic() - started_mono,
    )
    return VerifyResult(status="ok", passed=passed, summary=_truncate(output))


def run_validate_in_worktree(
    worktree: RepairWorktree, cfg: AppConfig, *, audit_trail: "Optional[list]" = None
) -> VerifyResult:
    argv = [sys.executable, "-m", "secure", "validate", "run"]
    env = _isolated_env(worktree)
    started_at = now_iso()
    started_mono = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=str(worktree.worktree_path),
            env=env,
            capture_output=True,
            text=True,
            timeout=cfg.agent_verify_timeout_seconds,
            shell=False,
        )
    except FileNotFoundError as exc:
        record_action(
            audit_trail, component="agent.verify", action="secure validate run (worktree)", argv=argv,
            cwd=str(worktree.worktree_path), target=str(worktree.worktree_path), mutating=False,
            started_at=started_at, exit_code=None, result_summary="could not launch secure validate",
            duration_seconds=time.monotonic() - started_mono,
        )
        return VerifyResult(status="unavailable", passed=None, summary=f"could not launch secure validate: {exc}")
    except subprocess.TimeoutExpired:
        record_action(
            audit_trail, component="agent.verify", action="secure validate run (worktree)", argv=argv,
            cwd=str(worktree.worktree_path), target=str(worktree.worktree_path), mutating=False,
            started_at=started_at, exit_code=None,
            result_summary=f"timed out after {cfg.agent_verify_timeout_seconds}s",
            duration_seconds=time.monotonic() - started_mono,
        )
        return VerifyResult(
            status="timeout", passed=None,
            summary=f"secure validate run did not finish within {cfg.agent_verify_timeout_seconds}s",
        )

    output = proc.stdout + "\n" + proc.stderr
    # `secure validate run` itself exits non-zero only on a hard crash;
    # a MISS outcome still exits 0 (it's a finding, not a tool failure)
    # — see secure/cli/validate.py's own cmd_validate_run. So "did the
    # tool run" (this status) and "did every scenario pass" (passed,
    # below) are two different questions, same status-vs-verdict split
    # secure/ai/verify/__init__.py's rule 4 already establishes.
    if proc.returncode != 0:
        record_action(
            audit_trail, component="agent.verify", action="secure validate run (worktree)", argv=argv,
            cwd=str(worktree.worktree_path), target=str(worktree.worktree_path), mutating=False,
            started_at=started_at, exit_code=proc.returncode, result_summary=f"exit {proc.returncode} (error)",
            duration_seconds=time.monotonic() - started_mono,
        )
        return VerifyResult(status="error", passed=None, summary=_truncate(output))

    passed = _read_latest_validation_verdict(worktree, env)
    record_action(
        audit_trail, component="agent.verify", action="secure validate run (worktree)", argv=argv,
        cwd=str(worktree.worktree_path), target=str(worktree.worktree_path), mutating=False,
        started_at=started_at, exit_code=proc.returncode,
        result_summary=f"exit {proc.returncode} ({'passed' if passed else 'failed' if passed is False else 'inconclusive'})",
        duration_seconds=time.monotonic() - started_mono,
    )
    return VerifyResult(status="ok", passed=passed, summary=_truncate(output))


def _read_latest_validation_verdict(worktree: RepairWorktree, env: dict) -> "Optional[bool]":
    """Reads the structured per-scenario outcomes the subprocess above
    just wrote to the throwaway agent-home database directly — never by
    re-parsing the subprocess's own printed text (that text contains
    the literal substring "MISS" even in its own column HEADER when the
    count is zero, which made a naive text search unreliable). Opens
    the database read-only and briefly; never the operator's real one,
    since `env["HOME"]` here is always the isolated agent-home
    directory, the same one the subprocess itself just wrote to.
    """
    import sqlite3 as _sqlite3
    from pathlib import Path as _Path

    from secure.storage.models import list_validation_runs, list_validation_scenario_results
    from secure.validate import OUTCOME_MISS

    db_path = _Path(env["HOME"]) / ".secure" / "secure.db"
    if not db_path.is_file():
        return None
    conn = _sqlite3.connect(str(db_path))
    conn.row_factory = _sqlite3.Row
    try:
        runs = list_validation_runs(conn, limit=1)
        if not runs:
            return None
        results = list_validation_scenario_results(conn, runs[0].run_id)
        if not results:
            return None
        return not any(r.outcome == OUTCOME_MISS for r in results)
    finally:
        conn.close()


@dataclass
class VerificationOutcome:
    pytest_result: VerifyResult
    validate_result: VerifyResult

    @property
    def overall_passed(self) -> "Optional[bool]":
        """None (not "false") when either check's own MECHANISM didn't
        run cleanly (unavailable/timeout/error) — an inconclusive
        verification must never be reported as a clean pass, but it
        must also never be silently reported as a definite fail; see
        secure/agent/changes.py's own handling of this None case."""
        if self.pytest_result.status != "ok" or self.validate_result.status != "ok":
            return None
        if self.pytest_result.passed is None or self.validate_result.passed is None:
            return None
        return bool(self.pytest_result.passed and self.validate_result.passed)


def verify_worktree(
    worktree: RepairWorktree, cfg: AppConfig, *, audit_trail: "Optional[list]" = None
) -> VerificationOutcome:
    return VerificationOutcome(
        pytest_result=run_pytest_in_worktree(worktree, cfg, audit_trail=audit_trail),
        validate_result=run_validate_in_worktree(worktree, cfg, audit_trail=audit_trail),
    )
