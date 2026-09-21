"""
secure/ai/verify/runner.py — executes a list of allowlisted
VerificationOperations, one at a time, catching every exception so one
bad request can never abort the rest of a run, and persists the whole
run to `ai_verification_runs` (secure/storage/models/ai.py).

`execute_operation()` is the single choke point every operation must
pass through — it is the only place in this package that maps an
operation NAME to the function that actually runs it, and it rejects
anything not in `operations.VALID_OPERATIONS` before touching the
filesystem, the database, or a subprocess.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from secure.ai.verify.operations import (
    OP_CHECK_TOOL_HEALTH,
    OP_INSPECT_TEST_PRESENCE,
    OP_LIST_TESTS,
    OP_READ_FILE,
    OP_RUN_PYTEST,
    OP_RUN_SCENARIO,
    OP_RUN_VALIDATION_SUITE,
    VALID_OPERATIONS,
    OperationResult,
    VerificationOperation,
    op_check_tool_health,
    op_inspect_test_presence,
    op_list_tests,
    op_read_file,
    op_run_pytest,
    op_run_scenario,
    op_run_validation_suite,
    project_root as default_project_root,
)
from secure.config import AppConfig
from secure.storage.models import add_ai_verification_run, complete_ai_verification_run

# Both run the whole tests/ suite, which takes ~200-310s on the target
# Mac (2540 tests, 2026-09-21). Below that, the step always ends as
# "timeout" instead of a verdict. Keep ~2x headroom over a full run.
DEFAULT_PYTEST_TIMEOUT = 600.0

# Statuses where the OPERATION ran to completion and returned real
# information, whether or not the thing it verified turned out to be
# healthy. Only these count toward a "clean" run — see this module's
# own docstring and secure/ai/verify/__init__.py's rule 4 for why that
# split matters.
_MECHANISM_OK_STATUSES = ("ok",)


def execute_operation(
    op: VerificationOperation, *, conn: sqlite3.Connection, cfg: AppConfig, root: "Optional[Path]" = None
) -> OperationResult:
    root = root or default_project_root()
    started_at = datetime.now(timezone.utc).isoformat()
    t0 = time.monotonic()

    if op.op not in VALID_OPERATIONS:
        return OperationResult(
            op=op.op, args=op.args, status="error", output=None,
            error=f"{op.op!r} is not an allowed verification operation. Allowed: {sorted(VALID_OPERATIONS)}",
            started_at=started_at, duration_ms=(time.monotonic() - t0) * 1000.0,
        )

    try:
        if op.op == OP_LIST_TESTS:
            output = op_list_tests(root)
            status = "ok"
        elif op.op == OP_READ_FILE:
            output = op_read_file(op.args.get("path", ""), root=root)
            status = "ok"
        elif op.op == OP_RUN_PYTEST:
            timeout = float(op.args.get("timeout") or DEFAULT_PYTEST_TIMEOUT)
            output = op_run_pytest(op.args.get("test_path"), root=root, timeout=timeout)
            status = output.get("status", "error")
        elif op.op == OP_RUN_VALIDATION_SUITE:
            output = op_run_validation_suite(conn)
            status = "ok"
        elif op.op == OP_RUN_SCENARIO:
            output = op_run_scenario(conn, op.args.get("scenario_id", ""))
            status = "ok" if output.get("found") else "error"
        elif op.op == OP_CHECK_TOOL_HEALTH:
            output = op_check_tool_health(cfg)
            status = "ok"
        elif op.op == OP_INSPECT_TEST_PRESENCE:
            output = op_inspect_test_presence(root)
            status = "ok"
        else:  # pragma: no cover — guarded by the VALID_OPERATIONS check above
            output, status = None, "error"
        error = output.get("error") if status == "error" and isinstance(output, dict) else None
    except Exception as exc:
        output, status, error = None, "error", f"{type(exc).__name__}: {exc}"

    duration_ms = (time.monotonic() - t0) * 1000.0
    return OperationResult(
        op=op.op, args=op.args, status=status, output=output, error=error,
        started_at=started_at, duration_ms=duration_ms,
    )


@dataclass
class VerificationRunSummary:
    run_id: int
    query_id: "Optional[int]"
    started_at: str
    completed_at: str
    results: "list[OperationResult]"
    overall_status: str


def run_operations(
    conn: sqlite3.Connection,
    cfg: AppConfig,
    operations: "list[VerificationOperation]",
    *,
    query_id: "Optional[int]" = None,
    root: "Optional[Path]" = None,
) -> VerificationRunSummary:
    started_at = datetime.now(timezone.utc).isoformat()
    run_id = add_ai_verification_run(conn, query_id=query_id, started_at=started_at)

    results = [execute_operation(op, conn=conn, cfg=cfg, root=root) for op in operations]

    ok_count = sum(1 for r in results if r.status in _MECHANISM_OK_STATUSES)
    if not results:
        overall_status = "error"
    elif ok_count == len(results):
        overall_status = "ok"
    elif ok_count == 0:
        overall_status = "error"
    else:
        overall_status = "partial"

    completed_at = datetime.now(timezone.utc).isoformat()
    complete_ai_verification_run(
        conn, run_id=run_id, completed_at=completed_at,
        operations=[op.to_dict() for op in operations],
        results=[r.to_dict() for r in results],
        overall_status=overall_status,
    )

    return VerificationRunSummary(
        run_id=run_id, query_id=query_id, started_at=started_at, completed_at=completed_at,
        results=results, overall_status=overall_status,
    )


def default_operations() -> "list[VerificationOperation]":
    """The fixed bundle `secure ai verify suite` (and, in Stage 7, the
    change-request workflow's own "deterministic tests run" step) runs
    by default: what tests exist, whether they pass, whether the
    security validation suite's synthetic scenarios still behave, and
    whether every integration is reachable. Deliberately ordered
    cheapest/most-informative first, in case a caller wants to bail
    early after inspecting partial results."""
    return [
        VerificationOperation(OP_LIST_TESTS),
        VerificationOperation(OP_INSPECT_TEST_PRESENCE),
        VerificationOperation(OP_CHECK_TOOL_HEALTH),
        VerificationOperation(OP_RUN_VALIDATION_SUITE),
        VerificationOperation(OP_RUN_PYTEST),
    ]


def run_default_verification_suite(
    conn: sqlite3.Connection, cfg: AppConfig, *, query_id: "Optional[int]" = None, root: "Optional[Path]" = None
) -> VerificationRunSummary:
    return run_operations(conn, cfg, default_operations(), query_id=query_id, root=root)
