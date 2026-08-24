"""
Tests for Phase 28 Stage 6: the constrained verification mode
(secure/ai/verify/operations.py, secure/ai/verify/runner.py). Covers
path-safety enforcement, the fixed operation allowlist, subprocess
mechanics for run_pytest (mocked via monkeypatched subprocess.run —
no real pytest needed), and persistence via ai_verification_runs.

Run with:  pytest
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from secure.ai.verify import operations as ops_module
from secure.ai.verify import runner as runner_module
from secure.ai.verify.operations import (
    OP_CHECK_TOOL_HEALTH,
    OP_INSPECT_TEST_PRESENCE,
    OP_LIST_TESTS,
    OP_READ_FILE,
    OP_RUN_PYTEST,
    OP_RUN_SCENARIO,
    OP_RUN_VALIDATION_SUITE,
    VALID_OPERATIONS,
    UnsafePathError,
    VerificationOperation,
    op_read_file,
)
from secure.ai.verify.runner import execute_operation, run_default_verification_suite, run_operations
from secure.config import AppConfig
from secure.storage.database import Database
from secure.storage.models import find_ai_verification_run


def _tiny_project(tmp_path: Path) -> Path:
    """A minimal, isolated fake project root — never the real
    secure/ project — so read_file/list_tests tests are self-contained
    and don't depend on this repo's own current file layout.
    """
    root = tmp_path / "fakeproject"
    (root / "secure").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "secure" / "widget.py").write_text("def widget():\n    return 1\n")
    (root / "tests" / "test_widget.py").write_text(
        "def test_widget_returns_one():\n    from secure.widget import widget\n    assert widget() == 1\n"
    )
    (root / "secret.key").write_text("do-not-read-me")
    return root


# ---------- path safety ----------


def test_read_file_rejects_dotdot_escape(tmp_path: Path):
    root = _tiny_project(tmp_path)
    try:
        op_read_file("../../etc/passwd", root=root)
        assert False, "should have raised"
    except UnsafePathError:
        pass


def test_read_file_rejects_absolute_path(tmp_path: Path):
    root = _tiny_project(tmp_path)
    try:
        op_read_file("/etc/passwd", root=root)
        assert False, "should have raised"
    except UnsafePathError:
        pass


def test_read_file_rejects_denylisted_extension(tmp_path: Path):
    root = _tiny_project(tmp_path)
    try:
        op_read_file("secret.key", root=root)
        assert False, "should have raised"
    except UnsafePathError:
        pass


def test_read_file_rejects_missing_file(tmp_path: Path):
    root = _tiny_project(tmp_path)
    try:
        op_read_file("does/not/exist.py", root=root)
        assert False, "should have raised"
    except FileNotFoundError:
        pass


def test_read_file_success_returns_content(tmp_path: Path):
    root = _tiny_project(tmp_path)
    result = op_read_file("secure/widget.py", root=root)
    assert result["binary"] is False
    assert "def widget" in result["content"]
    assert result["truncated"] is False


def test_read_file_truncates_beyond_max_bytes(tmp_path: Path):
    root = _tiny_project(tmp_path)
    (root / "secure" / "big.py").write_text("x = 1\n" * 10000)
    result = op_read_file("secure/big.py", root=root, max_bytes=100)
    assert result["truncated"] is True
    assert len(result["content"]) == 100


# ---------- list_tests / inspect_test_presence ----------


def test_list_tests_finds_the_fixture_project_test(tmp_path: Path):
    root = _tiny_project(tmp_path)
    result = ops_module.op_list_tests(root)
    assert result["test_file_count"] == 1
    assert result["files"][0]["name"] == "test_widget.py"
    assert "test_widget_returns_one" in result["files"][0]["functions"]


def test_inspect_test_presence_is_honest_about_what_it_measures(tmp_path: Path):
    root = _tiny_project(tmp_path)
    result = ops_module.op_inspect_test_presence(root)
    assert "not statement/branch coverage" in result["note"]
    widget_entry = next(m for m in result["modules"] if m["module"] == "secure.widget")
    assert widget_entry["has_test_reference"] is True


# ---------- run_pytest (mocked subprocess) ----------


def test_run_pytest_success(tmp_path: Path, monkeypatch):
    root = _tiny_project(tmp_path)

    def fake_run(argv, cwd, capture_output, text, timeout, shell):
        assert shell is False
        assert cwd == str(root)
        return subprocess.CompletedProcess(argv, returncode=0, stdout="1 passed", stderr="")

    monkeypatch.setattr(ops_module.subprocess, "run", fake_run)
    result = ops_module.op_run_pytest(root=root)
    assert result["status"] == "ok"
    assert result["tests_passed"] is True


def test_run_pytest_failure_is_still_a_clean_mechanism_result(tmp_path: Path, monkeypatch):
    root = _tiny_project(tmp_path)

    def fake_run(argv, cwd, capture_output, text, timeout, shell):
        return subprocess.CompletedProcess(argv, returncode=1, stdout="1 failed", stderr="")

    monkeypatch.setattr(ops_module.subprocess, "run", fake_run)
    result = ops_module.op_run_pytest(root=root)
    assert result["status"] == "ok"  # ran fine mechanically
    assert result["tests_passed"] is False  # but the tests themselves failed


def test_run_pytest_not_installed_is_unavailable(tmp_path: Path, monkeypatch):
    root = _tiny_project(tmp_path)

    def fake_run(argv, cwd, capture_output, text, timeout, shell):
        raise FileNotFoundError("no pytest")

    monkeypatch.setattr(ops_module.subprocess, "run", fake_run)
    result = ops_module.op_run_pytest(root=root)
    assert result["status"] == "unavailable"


def test_run_pytest_timeout(tmp_path: Path, monkeypatch):
    root = _tiny_project(tmp_path)

    def fake_run(argv, cwd, capture_output, text, timeout, shell):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=timeout)

    monkeypatch.setattr(ops_module.subprocess, "run", fake_run)
    result = ops_module.op_run_pytest(root=root, timeout=1.0)
    assert result["status"] == "timeout"


def test_run_pytest_rejects_test_path_not_in_discovered_list(tmp_path: Path):
    root = _tiny_project(tmp_path)
    result = ops_module.op_run_pytest("../../etc/passwd", root=root)
    assert result["status"] == "error"


def test_run_pytest_never_uses_shell_true(tmp_path: Path, monkeypatch):
    root = _tiny_project(tmp_path)
    captured = {}

    def fake_run(argv, cwd, capture_output, text, timeout, shell):
        captured["shell"] = shell
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ops_module.subprocess, "run", fake_run)
    ops_module.op_run_pytest(root=root)
    assert captured["shell"] is False
    assert isinstance(captured["argv"], list)


# ---------- runner.py: execute_operation / run_operations ----------


def test_execute_operation_rejects_unknown_op(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        result = execute_operation(
            VerificationOperation("op_delete_everything"), conn=db.conn, cfg=AppConfig(app_dir=str(tmp_path))
        )
    assert result.status == "error"
    assert "not an allowed" in result.error


def test_execute_operation_check_tool_health(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        result = execute_operation(
            VerificationOperation(OP_CHECK_TOOL_HEALTH), conn=db.conn, cfg=AppConfig(app_dir=str(tmp_path))
        )
    assert result.status == "ok"
    names = {t["name"] for t in result.output["tools"]}
    assert names == {"osquery", "yarax", "sigma", "suricata", "zeek", "velociraptor"}


def test_execute_operation_run_validation_suite_persists_to_caller_db(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        result = execute_operation(
            VerificationOperation(OP_RUN_VALIDATION_SUITE), conn=db.conn, cfg=AppConfig(app_dir=str(tmp_path))
        )
        assert result.status == "ok"
        assert result.output["total_count"] > 0
        from secure.storage.models import find_validation_run

        assert find_validation_run(db.conn, result.output["run_id"]) is not None


def test_execute_operation_run_scenario_not_found(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        result = execute_operation(
            VerificationOperation(OP_RUN_SCENARIO, {"scenario_id": "nonexistent_xyz"}),
            conn=db.conn, cfg=AppConfig(app_dir=str(tmp_path)),
        )
    assert result.status == "error"
    assert result.output["found"] is False


def test_execute_operation_run_scenario_found(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        suite = execute_operation(
            VerificationOperation(OP_RUN_VALIDATION_SUITE), conn=db.conn, cfg=AppConfig(app_dir=str(tmp_path))
        )
        first_id = suite.output["scenario_ids"][0]
        result = execute_operation(
            VerificationOperation(OP_RUN_SCENARIO, {"scenario_id": first_id}),
            conn=db.conn, cfg=AppConfig(app_dir=str(tmp_path)),
        )
    assert result.status == "ok"
    assert result.output["found"] is True
    assert result.output["scenario_id"] == first_id


def test_run_operations_overall_status_partial_when_some_ops_fail(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        ops = [
            VerificationOperation(OP_CHECK_TOOL_HEALTH),
            VerificationOperation("not_a_real_op"),
        ]
        summary = run_operations(db.conn, AppConfig(app_dir=str(tmp_path)), ops)
    assert summary.overall_status == "partial"
    assert len(summary.results) == 2


def test_run_operations_overall_status_error_when_all_ops_fail(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        ops = [VerificationOperation("not_a_real_op"), VerificationOperation("also_fake")]
        summary = run_operations(db.conn, AppConfig(app_dir=str(tmp_path)), ops)
    assert summary.overall_status == "error"


def test_run_operations_persists_a_findable_run(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        summary = run_operations(db.conn, AppConfig(app_dir=str(tmp_path)), [VerificationOperation(OP_LIST_TESTS)])
        record = find_ai_verification_run(db.conn, summary.run_id)
    assert record is not None
    assert record.overall_status == "ok"
    assert len(record.operations) == 1
    assert len(record.results) == 1


def test_run_default_verification_suite_covers_the_documented_bundle(tmp_path: Path, monkeypatch):
    root = _tiny_project(tmp_path)
    monkeypatch.setattr(
        ops_module.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess([], returncode=0, stdout="", stderr=""),
    )
    with Database(tmp_path / "t.db") as db:
        summary = run_default_verification_suite(db.conn, AppConfig(app_dir=str(tmp_path)), root=root)

    ops_run = {r.op for r in summary.results}
    assert ops_run == {OP_LIST_TESTS, OP_INSPECT_TEST_PRESENCE, OP_CHECK_TOOL_HEALTH, OP_RUN_VALIDATION_SUITE, OP_RUN_PYTEST}
    assert summary.overall_status == "ok"


def test_valid_operations_is_exactly_the_documented_seven():
    assert set(VALID_OPERATIONS) == {
        OP_LIST_TESTS, OP_READ_FILE, OP_RUN_PYTEST, OP_RUN_VALIDATION_SUITE,
        OP_RUN_SCENARIO, OP_CHECK_TOOL_HEALTH, OP_INSPECT_TEST_PRESENCE,
    }
