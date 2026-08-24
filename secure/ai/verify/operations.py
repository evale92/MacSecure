"""
secure/ai/verify/operations.py — the fixed, allowlisted operation enum
and its implementations. See secure/ai/verify/__init__.py for the four
hard rules this module exists to enforce.

Every `op_*` function here is a plain, narrow, individually-auditable
Python function — never a generic command executor. A caller (the
runner in secure/ai/verify/runner.py, and through it, ultimately an
LLM's structured request) can only ever reach one of these by name,
with a small validated argument set. There is deliberately no
"op_run_shell_command" and there never will be.
"""

from __future__ import annotations

import ast
import json
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from secure.config import AppConfig

# secure/ai/verify/operations.py -> secure/ai/verify -> secure/ai -> secure -> project root
_PROJECT_ROOT = Path(__file__).resolve().parents[3]

OP_LIST_TESTS = "list_tests"
OP_READ_FILE = "read_file"
OP_RUN_PYTEST = "run_pytest"
OP_RUN_VALIDATION_SUITE = "run_validation_suite"
OP_RUN_SCENARIO = "run_scenario"
OP_CHECK_TOOL_HEALTH = "check_tool_health"
OP_INSPECT_TEST_PRESENCE = "inspect_test_presence"

VALID_OPERATIONS = (
    OP_LIST_TESTS,
    OP_READ_FILE,
    OP_RUN_PYTEST,
    OP_RUN_VALIDATION_SUITE,
    OP_RUN_SCENARIO,
    OP_CHECK_TOOL_HEALTH,
    OP_INSPECT_TEST_PRESENCE,
)

# Extensions read_file will never return the contents of, regardless of
# where they live under the project root — databases, keys, certs, and
# env files are the categories most likely to hold live secrets or the
# operator's actual security data.
_DENIED_READ_SUFFIXES = (
    ".db", ".sqlite", ".sqlite3", ".pem", ".key", ".p12", ".pfx", ".keychain",
    ".env",
)
_MAX_READ_BYTES = 50_000


def project_root() -> Path:
    return _PROJECT_ROOT


@dataclass
class VerificationOperation:
    op: str
    args: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"op": self.op, "args": self.args}


@dataclass
class OperationResult:
    op: str
    args: dict
    status: str  # "ok" / "unavailable" / "timeout" / "error"
    output: "Optional[dict]"
    error: "Optional[str]"
    started_at: str
    duration_ms: float

    def to_dict(self) -> dict:
        return {
            "op": self.op, "args": self.args, "status": self.status, "output": self.output,
            "error": self.error, "started_at": self.started_at, "duration_ms": self.duration_ms,
        }


class UnsafePathError(ValueError):
    pass


def _safe_relative_path(root: Path, rel_path: str) -> Path:
    """Resolves `rel_path` against `root` and raises UnsafePathError for
    anything that isn't a plain, in-tree relative path — absolute
    paths, `..` escapes, and (via the final resolve()/relative_to()
    check) symlink escapes are all rejected the same way.
    """
    if not rel_path or rel_path.strip() == "":
        raise UnsafePathError("empty path")
    if Path(rel_path).is_absolute():
        raise UnsafePathError(f"absolute paths are not allowed: {rel_path!r}")
    if ".." in Path(rel_path).parts:
        raise UnsafePathError(f"'..' path segments are not allowed: {rel_path!r}")

    candidate = (root / rel_path).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        raise UnsafePathError(f"path escapes the project root: {rel_path!r}") from None
    return candidate


def _discover_test_files(root: Path) -> "list[Path]":
    tests_dir = root / "tests"
    if not tests_dir.is_dir():
        return []
    return sorted(tests_dir.glob("test_*.py"))


def _test_function_names(path: Path) -> "list[str]":
    """AST-only — never imports the test file, so this is safe to call
    on every discovered test file with zero side effects."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return []
    return sorted(
        node.name for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    )


def op_list_tests(root: "Optional[Path]" = None) -> dict:
    root = root or _PROJECT_ROOT
    files = _discover_test_files(root)
    return {
        "test_file_count": len(files),
        "files": [
            {"name": f.name, "function_count": len(_test_function_names(f)), "functions": _test_function_names(f)}
            for f in files
        ],
    }


def op_read_file(rel_path: str, *, root: "Optional[Path]" = None, max_bytes: int = _MAX_READ_BYTES) -> dict:
    root = root or _PROJECT_ROOT
    path = _safe_relative_path(root, rel_path)

    if path.suffix.lower() in _DENIED_READ_SUFFIXES:
        raise UnsafePathError(f"reading files with extension {path.suffix!r} is not permitted: {rel_path!r}")
    if not path.exists():
        raise FileNotFoundError(f"no such file under the project root: {rel_path!r}")
    if not path.is_file():
        raise UnsafePathError(f"not a regular file: {rel_path!r}")

    size = path.stat().st_size
    raw = path.read_bytes()[: max_bytes + 1]
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"path": rel_path, "binary": True, "size_bytes": size, "content": None, "truncated": False}

    return {"path": rel_path, "binary": False, "size_bytes": size, "content": text, "truncated": truncated}


def op_run_pytest(
    test_path: "Optional[str]" = None, *, root: "Optional[Path]" = None, timeout: float = 120.0
) -> dict:
    """Runs pytest via `subprocess.run([sys.executable, "-m", "pytest", ...])`
    — a fixed argv, never a shell string. `test_path`, if given, must
    name one of the files `op_list_tests()` already discovered; this
    prevents an arbitrary path (or a path outside tests/) from ever
    reaching the subprocess argv.
    """
    root = root or _PROJECT_ROOT
    tests_dir = root / "tests"

    if test_path is not None:
        discovered_names = {f.name for f in _discover_test_files(root)}
        if test_path not in discovered_names:
            return {
                "status": "error",
                "error": f"{test_path!r} is not a known test file (see list_tests).",
                "returncode": None, "stdout": "", "stderr": "",
            }
        target = str(tests_dir / test_path)
    else:
        target = str(tests_dir)

    argv = [sys.executable, "-m", "pytest", target, "-q"]
    try:
        proc = subprocess.run(
            argv, cwd=str(root), capture_output=True, text=True, timeout=timeout, shell=False,
        )
    except FileNotFoundError as exc:
        return {"status": "unavailable", "error": f"could not launch pytest: {exc}", "returncode": None,
                "stdout": "", "stderr": ""}
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": f"pytest did not finish within {timeout}s", "returncode": None,
                "stdout": "", "stderr": ""}

    stdout = proc.stdout[-20_000:]
    stderr = proc.stderr[-20_000:]
    if proc.returncode != 0 and ("No module named pytest" in stderr or "No module named pytest" in stdout):
        return {"status": "unavailable", "error": "pytest is not installed in this environment",
                "returncode": proc.returncode, "stdout": stdout, "stderr": stderr}

    return {
        "status": "ok", "error": None, "returncode": proc.returncode,
        "tests_passed": proc.returncode == 0, "stdout": stdout, "stderr": stderr,
    }


def op_run_validation_suite(conn: sqlite3.Connection) -> dict:
    """Delegates entirely to the already-deterministic Phase 27
    validation suite — this operation adds no scoring or scenario logic
    of its own, it only exposes that existing suite to the constrained
    verification layer."""
    from secure.validate.runner import run_validation_suite

    summary = run_validation_suite(conn)
    return {
        "run_id": summary.run_id, "total_count": summary.total_count,
        "counts_by_outcome": summary.counts_by_outcome,
        "scenario_ids": [r.scenario_id for r in summary.results],
    }


def op_run_scenario(conn: sqlite3.Connection, scenario_id: str) -> dict:
    """Runs every registered scenario in its own throwaway sandbox
    (same as the full suite does) until it finds the one matching
    `scenario_id`, and reports just that one. Deliberately does not
    maintain a second, hand-kept id->function registry that could drift
    from `all_scenario_functions()`'s own real order."""
    from secure.validate.runner import all_scenario_functions
    from secure.validate.sandbox import sandbox

    if not scenario_id:
        return {"status": "error", "found": False, "error": "scenario_id is required"}

    for scenario_fn in all_scenario_functions():
        with sandbox() as sb:
            result = scenario_fn(sb)
        if result.scenario_id == scenario_id:
            return {
                "status": "ok", "found": True, "scenario_id": result.scenario_id,
                "technique_id": result.technique_id, "category": result.category,
                "expected_result": result.expected_result, "outcome": result.outcome,
                "sensors_observed": result.sensors_observed, "findings": result.findings,
                "correlation_result": result.correlation_result, "notes": result.notes,
            }

    return {"status": "error", "found": False, "error": f"no scenario with id {scenario_id!r} is registered"}


def op_check_tool_health(cfg: AppConfig) -> dict:
    from secure.ai.context import _collect_tool_health

    return {"tools": _collect_tool_health(cfg)}


# A package "has tests" if any tests/test_*.py file's own text mentions
# its dotted module path. This is a structural presence check, NOT
# statement or branch coverage — the `coverage` package isn't available
# in every environment Secure runs in, and reporting a fabricated
# coverage percentage would be exactly the kind of dishonest aggregate
# secure/validate/report.py already refuses to produce (Phase 27). Say
# what this actually measures, nothing more.
def op_inspect_test_presence(root: "Optional[Path]" = None) -> dict:
    root = root or _PROJECT_ROOT
    secure_dir = root / "secure"
    test_files = _discover_test_files(root)
    test_sources = {f.name: f.read_text(encoding="utf-8", errors="ignore") for f in test_files}

    modules = []
    for path in sorted(secure_dir.rglob("*.py")):
        if path.name in ("__init__.py",) or "__pycache__" in path.parts:
            continue
        rel = path.relative_to(root)
        dotted = ".".join(rel.with_suffix("").parts)
        matched = sorted(name for name, text in test_sources.items() if dotted in text or path.stem in text)
        modules.append({"module": dotted, "has_test_reference": bool(matched), "referenced_by": matched})

    referenced = sum(1 for m in modules if m["has_test_reference"])
    return {
        "note": "Structural test-file cross-reference only, not statement/branch coverage.",
        "module_count": len(modules), "modules_referenced_by_a_test_file": referenced,
        "modules": modules,
    }
