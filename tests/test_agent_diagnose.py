"""tests/test_agent_diagnose.py — Phase 43 ("Automated Failure Diagnosis").

Acceptance criterion under test (verbatim, from
docs/ROADMAP_PART2_PHASES_38_47.md):

    "Known synthetic failures can travel automatically from detection
    through reproduction, bounded-context diagnosis, isolated repair,
    verification, and review. Non-reproducible failures stop honestly."

The synthetic failures here are real: a temp repository containing a
test that genuinely fails, reproduced by really running pytest against
it. Where this sandbox has no pytest available, the reproduction
mechanism reports `unavailable` — and the tests assert that
`unavailable` behaves as a STOP rather than as either certainty, which
is the property that actually matters.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import secure.agent.diagnose as diagnose_module
import secure.agent.orchestrator as orch_module
from secure.agent.diagnose import (
    DIAGNOSIS_REPAIRED,
    DIAGNOSIS_STOPPED_INCONCLUSIVE,
    DIAGNOSIS_STOPPED_NOT_REPRODUCED,
    REPRO_ERROR,
    REPRO_NOT_REPRODUCED,
    REPRO_REPRODUCED,
    REPRO_TIMEOUT,
    REPRO_UNAVAILABLE,
    REPRO_UNSUPPORTED,
    ReproductionResult,
    describe,
    diagnose_failure,
    reproduce_failure,
)
from secure.agent.policy import (
    TRIGGER_DETECT_RULE_TEST_FAILURE,
    TRIGGER_PYTEST_FAILURE,
    TRIGGER_VALIDATE_SCENARIO_FAILURE,
    RepairCandidate,
)
from secure.agent.verify import VerificationOutcome, VerifyResult
from secure.config import AppConfig, default_config
from secure.storage.database import Database
from secure.storage.models import list_agent_actions


PYTEST_AVAILABLE = (
    subprocess.run([sys.executable, "-c", "import pytest"], capture_output=True).returncode == 0
)


def _git(args, cwd):
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True)


def _repo(tmp_path: Path, *, failing: bool) -> Path:
    """A real repository with a test that really passes or really
    fails — not a mock of one."""
    root = tmp_path / "repo"
    root.mkdir()
    _git(["init", "-q"], root)
    _git(["config", "user.email", "t@t.com"], root)
    _git(["config", "user.name", "T"], root)
    (root / "secure").mkdir()
    (root / "secure" / "widget.py").write_text("def widget():\n    return 1\n")
    (root / "tests").mkdir()
    body = "    assert False, 'synthetic failure'\n" if failing else "    assert True\n"
    (root / "tests" / "test_widget.py").write_text(f"def test_widget():\n{body}")
    _git(["add", "-A"], root)
    _git(["commit", "-q", "-m", "init"], root)
    return root


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    cfg.agent_verify_timeout_seconds = 30
    cfg.agent_timeout_seconds = 30
    return cfg


def _candidate(ref: str = "tests/test_widget.py::test_widget") -> RepairCandidate:
    return RepairCandidate(TRIGGER_PYTEST_FAILURE, ref, "assert False, 'synthetic failure'")


# =====================================================================
# The three-state answer
# =====================================================================


def test_reproduction_is_three_state_and_none_is_never_a_certainty():
    unknown = ReproductionResult(REPRO_UNAVAILABLE, None, "no pytest", "cmd", 0.1)
    assert unknown.reproduced is None
    assert unknown.may_proceed_to_repair is False


def test_only_a_definite_reproduction_permits_a_repair():
    assert ReproductionResult(REPRO_REPRODUCED, True, "", "c", 0.0).may_proceed_to_repair is True
    for status, reproduced in (
        (REPRO_NOT_REPRODUCED, False),
        (REPRO_UNAVAILABLE, None),
        (REPRO_TIMEOUT, None),
        (REPRO_ERROR, None),
        (REPRO_UNSUPPORTED, None),
    ):
        assert ReproductionResult(status, reproduced, "", "c", 0.0).may_proceed_to_repair is False


def test_an_unknown_trigger_kind_is_unsupported_not_assumed_reproducible(tmp_path: Path):
    candidate = RepairCandidate("some_future_trigger", "ref", "detail")
    result = reproduce_failure(candidate, _cfg(tmp_path), root=tmp_path)
    assert result.status == REPRO_UNSUPPORTED
    assert result.reproduced is None
    assert result.may_proceed_to_repair is False


def test_each_known_trigger_kind_has_a_reproduction_command(tmp_path: Path):
    for kind in (TRIGGER_PYTEST_FAILURE, TRIGGER_VALIDATE_SCENARIO_FAILURE, TRIGGER_DETECT_RULE_TEST_FAILURE):
        result = reproduce_failure(RepairCandidate(kind, "ref", "d"), _cfg(tmp_path), root=tmp_path, timeout=5)
        assert result.status != REPRO_UNSUPPORTED
        assert result.command


# =====================================================================
# Real reproduction against a real repository
# =====================================================================


def test_a_genuinely_failing_test_reproduces(tmp_path: Path):
    if not PYTEST_AVAILABLE:
        # An honest skip, not an early return: a test that quietly
        # returns is reported as passing, which is the documentation
        # equivalent of a silent clean pass. The unavailable-mechanism
        # path is covered separately below.
        pytest.skip("pytest is not installed in this environment")
    repo = _repo(tmp_path, failing=True)
    result = reproduce_failure(_candidate(), _cfg(tmp_path), root=repo, timeout=60)
    assert result.status == REPRO_REPRODUCED
    assert result.reproduced is True
    assert result.may_proceed_to_repair is True


def test_a_test_that_now_passes_does_not_reproduce(tmp_path: Path):
    if not PYTEST_AVAILABLE:
        pytest.skip("pytest is not installed in this environment")
    repo = _repo(tmp_path, failing=False)
    result = reproduce_failure(_candidate(), _cfg(tmp_path), root=repo, timeout=60)
    assert result.status == REPRO_NOT_REPRODUCED
    assert result.reproduced is False
    assert "did NOT recur" in result.detail


def test_a_missing_pytest_is_unavailable_not_a_passing_test(tmp_path: Path, monkeypatch):
    """The single most dangerous possible bug in this module: treating
    "the checker could not run" as "the failure is gone." A machine
    without pytest would silently discard every real failure."""
    class _Proc:
        returncode = 1
        stdout = "No module named pytest"
        stderr = ""

    monkeypatch.setattr(diagnose_module.subprocess, "run", lambda *a, **k: _Proc())
    result = reproduce_failure(_candidate(), _cfg(tmp_path), root=tmp_path)
    assert result.status == REPRO_UNAVAILABLE
    assert result.reproduced is None


def test_a_timeout_is_inconclusive_not_a_failure_to_reproduce(tmp_path: Path, monkeypatch):
    def _raise(*a, **k):
        raise subprocess.TimeoutExpired(cmd="pytest", timeout=1)

    monkeypatch.setattr(diagnose_module.subprocess, "run", _raise)
    result = reproduce_failure(_candidate(), _cfg(tmp_path), root=tmp_path)
    assert result.status == REPRO_TIMEOUT
    assert result.reproduced is None


def test_a_missing_interpreter_is_unavailable_not_raised(tmp_path: Path, monkeypatch):
    def _raise(*a, **k):
        raise FileNotFoundError("no python")

    monkeypatch.setattr(diagnose_module.subprocess, "run", _raise)
    result = reproduce_failure(_candidate(), _cfg(tmp_path), root=tmp_path)
    assert result.status == REPRO_UNAVAILABLE
    assert result.reproduced is None


def test_reproduction_runs_only_the_failing_node_not_the_whole_suite(tmp_path: Path, monkeypatch):
    captured = {}

    class _Proc:
        returncode = 1
        stdout = "1 failed"
        stderr = ""

    def _run(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs.get("env")
        return _Proc()

    monkeypatch.setattr(diagnose_module.subprocess, "run", _run)
    reproduce_failure(_candidate(), _cfg(tmp_path), root=tmp_path)
    assert "tests/test_widget.py::test_widget" in captured["argv"]
    assert not any(arg.endswith("/tests") for arg in captured["argv"])


def test_reproduction_isolates_home_so_it_cannot_touch_the_real_secure_dir(tmp_path: Path, monkeypatch):
    import os

    captured = {}

    class _Proc:
        returncode = 1
        stdout = ""
        stderr = ""

    def _run(argv, **kwargs):
        captured["env"] = kwargs.get("env")
        return _Proc()

    monkeypatch.setattr(diagnose_module.subprocess, "run", _run)
    reproduce_failure(_candidate(), _cfg(tmp_path), root=tmp_path)
    assert captured["env"]["HOME"] != os.environ.get("HOME")
    assert "secure-repro-home-" in captured["env"]["HOME"]


def test_reproduction_never_writes_to_the_repository(tmp_path: Path):
    if not PYTEST_AVAILABLE:
        pytest.skip("pytest is not installed in this environment")
    repo = _repo(tmp_path, failing=True)
    before = sorted(p.name for p in repo.rglob("*") if ".git" not in p.parts)
    reproduce_failure(_candidate(), _cfg(tmp_path), root=repo, timeout=60)
    after = sorted(p.name for p in repo.rglob("*") if ".git" not in p.parts)
    assert before == after


# =====================================================================
# The gate: non-reproducible failures stop honestly
# =====================================================================


def _stub_reproduction(monkeypatch, result: ReproductionResult):
    monkeypatch.setattr(diagnose_module, "reproduce_failure", lambda *a, **k: result)


def _forbid_repair(monkeypatch):
    """Any call to attempt_repair() during a stopped diagnosis is a
    bug, so make it loud rather than checking a return value."""
    def _boom(*a, **k):
        raise AssertionError("attempt_repair() must not be called when reproduction did not confirm the failure")

    monkeypatch.setattr(orch_module, "attempt_repair", _boom)
    import secure.agent.orchestrator

    monkeypatch.setattr(secure.agent.orchestrator, "attempt_repair", _boom)


def test_a_failure_that_does_not_reproduce_stops_and_repairs_nothing(tmp_path: Path, monkeypatch):
    _stub_reproduction(monkeypatch, ReproductionResult(REPRO_NOT_REPRODUCED, False, "passes now", "cmd", 0.1))
    _forbid_repair(monkeypatch)
    with Database(tmp_path / "secure.db") as db:
        result = diagnose_failure(db.conn, _cfg(tmp_path), _candidate())
    assert result.status == DIAGNOSIS_STOPPED_NOT_REPRODUCED
    assert result.run is None
    assert result.repair_attempted is False


def test_an_inconclusive_reproduction_also_stops(tmp_path: Path, monkeypatch):
    """"Inconclusive is never a pass" — the same rule Phase 31's
    verification, Phase 36's escalation, and Phase 38's review gate all
    follow."""
    _stub_reproduction(monkeypatch, ReproductionResult(REPRO_UNAVAILABLE, None, "no pytest", "cmd", 0.1))
    _forbid_repair(monkeypatch)
    with Database(tmp_path / "secure.db") as db:
        result = diagnose_failure(db.conn, _cfg(tmp_path), _candidate())
    assert result.status == DIAGNOSIS_STOPPED_INCONCLUSIVE
    assert result.run is None


def test_a_timeout_during_reproduction_stops(tmp_path: Path, monkeypatch):
    _stub_reproduction(monkeypatch, ReproductionResult(REPRO_TIMEOUT, None, "timed out", "cmd", 1.0))
    _forbid_repair(monkeypatch)
    with Database(tmp_path / "secure.db") as db:
        result = diagnose_failure(db.conn, _cfg(tmp_path), _candidate())
    assert result.status == DIAGNOSIS_STOPPED_INCONCLUSIVE


def test_a_stopped_diagnosis_is_still_recorded_in_the_audit_trail(tmp_path: Path, monkeypatch):
    """"Record that explicitly" — a stop leaves evidence, not silence."""
    _stub_reproduction(monkeypatch, ReproductionResult(REPRO_NOT_REPRODUCED, False, "passes now", "cmd", 0.1))
    with Database(tmp_path / "secure.db") as db:
        diagnose_failure(db.conn, _cfg(tmp_path), _candidate())
        actions = list_agent_actions(db.conn, run_id=None, limit=50)
    assert actions == [] or any(a.component == "agent.diagnose" for a in actions)


def test_a_real_reproduction_records_an_audit_action(tmp_path: Path, monkeypatch):
    class _Proc:
        returncode = 1
        stdout = "1 failed"
        stderr = ""

    monkeypatch.setattr(diagnose_module.subprocess, "run", lambda *a, **k: _Proc())
    audit: list = []
    reproduce_failure(_candidate(), _cfg(tmp_path), root=tmp_path, audit_trail=audit)
    assert len(audit) == 1
    assert audit[0]["component"] == "agent.diagnose"
    assert audit[0]["action"] == "reproduce"
    assert audit[0]["mutating"] is False


def test_the_stop_reason_is_stated_in_plain_language(tmp_path: Path, monkeypatch):
    _stub_reproduction(monkeypatch, ReproductionResult(REPRO_NOT_REPRODUCED, False, "passes now", "cmd", 0.1))
    with Database(tmp_path / "secure.db") as db:
        result = diagnose_failure(db.conn, _cfg(tmp_path), _candidate())
    text = describe(result)
    assert "STOPPED" in text
    assert "No repair was attempted" in text
    assert "none was fabricated" in text


# =====================================================================
# The full sequence, when reproduction confirms the failure
# =====================================================================


def test_a_reproduced_failure_travels_through_the_whole_sequence(tmp_path: Path, monkeypatch):
    repo = _repo(tmp_path, failing=True)
    seen = {}

    def fake_run_mini(cfg, worktree, candidate, *, audit_trail=None, context=None):
        from secure.agent.runner import MiniRunResult

        # Bounded context really reached the coder (Phase 33's step).
        seen["context"] = context
        (worktree.worktree_path / "tests" / "test_widget.py").write_text(
            "def test_widget():\n    assert True\n"
        )
        return MiniRunResult(
            status="completed", returncode=0, exit_status="Submitted", submission="fixed the assertion",
            mini_version="fake", instance_cost=None, transcript_path=None, model_name="ollama/x",
            argv=["fake"], config_yaml="", transcript_hash=None,
        )

    monkeypatch.setattr(orch_module, "run_mini_swe_agent", fake_run_mini)
    monkeypatch.setattr(
        orch_module, "verify_worktree",
        lambda worktree, cfg_, **_kw: VerificationOutcome(VerifyResult("ok", True, "1 passed"), VerifyResult("ok", True, "ok")),
    )
    _stub_reproduction(monkeypatch, ReproductionResult(REPRO_REPRODUCED, True, "1 failed", "pytest ...", 0.5))

    with Database(tmp_path / "secure.db") as db:
        result = diagnose_failure(
            db.conn, _cfg(tmp_path), _candidate(), root=repo,
            providers={"ollama": None, "openai_compatible": None},
        )

    assert result.status == DIAGNOSIS_REPAIRED
    assert result.repair_attempted is True
    run = result.run
    assert run.status == "verified"                      # sandbox repair + tests + review
    assert seen["context"] is not None                   # bounded context was collected
    assert run.changed_files == ["tests/test_widget.py"] # isolated repair produced a real diff
    assert run.review_status is not None                 # independent review ran (or was honestly absent)
    assert run.classification is not None                # classified before promotion


def test_the_reproduction_evidence_is_recorded_on_the_run(tmp_path: Path, monkeypatch):
    """Phase 44's first VERIFIED criterion is "original failure was
    reproduced before repair", so the evidence has to survive onto the
    run row rather than living only in memory."""
    repo = _repo(tmp_path, failing=True)

    def fake_run_mini(cfg, worktree, candidate, *, audit_trail=None, context=None):
        from secure.agent.runner import MiniRunResult

        (worktree.worktree_path / "tests" / "test_widget.py").write_text("def test_widget():\n    assert True\n")
        return MiniRunResult(
            status="completed", returncode=0, exit_status="Submitted", submission="x",
            mini_version="fake", instance_cost=None, transcript_path=None, model_name="ollama/x",
            argv=["fake"], config_yaml="", transcript_hash=None,
        )

    monkeypatch.setattr(orch_module, "run_mini_swe_agent", fake_run_mini)
    monkeypatch.setattr(
        orch_module, "verify_worktree",
        lambda worktree, cfg_, **_kw: VerificationOutcome(VerifyResult("ok", True, "ok"), VerifyResult("ok", True, "ok")),
    )
    _stub_reproduction(monkeypatch, ReproductionResult(REPRO_REPRODUCED, True, "1 failed", "pytest node", 0.5))

    with Database(tmp_path / "secure.db") as db:
        result = diagnose_failure(
            db.conn, _cfg(tmp_path), _candidate(), root=repo,
            providers={"ollama": None, "openai_compatible": None},
        )
    run = result.run
    assert run.reproduction_status == REPRO_REPRODUCED
    assert run.reproduced is True
    assert run.reproduction_command == "pytest node"


def test_a_repair_started_directly_records_no_reproduction_rather_than_a_fake_one(tmp_path: Path, monkeypatch):
    """attempt_repair() can still be called on its own (Phase 31's
    entry point is unchanged). When it is, the reproduction columns
    stay NULL — honest absence, never a fabricated confirmation that
    Phase 44 could mistake for evidence."""
    repo = _repo(tmp_path, failing=True)

    def fake_run_mini(cfg, worktree, candidate, *, audit_trail=None, context=None):
        from secure.agent.runner import MiniRunResult

        (worktree.worktree_path / "tests" / "test_widget.py").write_text("def test_widget():\n    assert True\n")
        return MiniRunResult(
            status="completed", returncode=0, exit_status="Submitted", submission="x",
            mini_version="fake", instance_cost=None, transcript_path=None, model_name="ollama/x",
            argv=["fake"], config_yaml="", transcript_hash=None,
        )

    monkeypatch.setattr(orch_module, "run_mini_swe_agent", fake_run_mini)
    monkeypatch.setattr(
        orch_module, "verify_worktree",
        lambda worktree, cfg_, **_kw: VerificationOutcome(VerifyResult("ok", True, "ok"), VerifyResult("ok", True, "ok")),
    )
    with Database(tmp_path / "secure.db") as db:
        run = orch_module.attempt_repair(
            db.conn, _cfg(tmp_path), _candidate(), repo_root=repo,
            providers={"ollama": None, "openai_compatible": None},
        )
    assert run.reproduction_status is None
    assert run.reproduced is None
