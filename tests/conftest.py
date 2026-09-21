"""
Shared test guards.

Some app code runs the project's own test suite as a verification step
(secure/ai/verify/operations.py's op_run_pytest, secure/agent/*). If a
test reaches that code unstubbed, it launches `python -m pytest tests`
on this repo, which reaches the same test again: a recursive suite run
that stalls for DEFAULT_PYTEST_TIMEOUT per level and can orphan
processes. This guard blocks the run and fails the test by name.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_REAL_TESTS_DIR = Path(__file__).resolve().parent


def _targets_real_suite(argv) -> bool:
    args = [str(a) for a in argv]
    if "pytest" not in args:
        return False
    for arg in args:
        try:
            p = Path(arg).resolve()
        except (OSError, ValueError):
            continue
        # Only the whole suite recurses. Targeted runs of one file or
        # node id (secure/agent/diagnose.py, promote.py, tiers.py) are
        # legitimate and must stay allowed.
        if p == _REAL_TESTS_DIR:
            return True
    return False


@pytest.fixture(autouse=True)
def _forbid_nested_real_suite(monkeypatch):
    # Recorded and failed at teardown, not raised: the verification
    # runner catches every exception by design (secure/ai/verify/runner.py),
    # so a raise here would be swallowed and the test would still pass.
    attempts = []
    real_run = subprocess.run

    def guarded_run(argv, *args, **kwargs):
        if not isinstance(argv, str) and _targets_real_suite(argv):
            attempts.append(list(map(str, argv)))
            raise RuntimeError("blocked recursive pytest run on the real suite")
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", guarded_run)
    yield
    if attempts:
        pytest.fail(
            "test tried to run pytest on the real project suite (recursive run); "
            f"stub it with the stub_verification_pytest fixture. argv: {attempts[0]}",
            pytrace=False,
        )


@pytest.fixture
def stub_verification_pytest(monkeypatch):
    """Replace the verification runner's pytest step with a passing stub."""
    monkeypatch.setattr(
        "secure.ai.verify.runner.op_run_pytest",
        lambda *a, **k: {"status": "ok", "error": None, "returncode": 0,
                         "tests_passed": True, "stdout": "", "stderr": ""},
    )
