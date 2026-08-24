"""
Tests for secure/dfir/velociraptor/ (Phase 24 Stage 2: availability,
shell wrapper, collect, parser). No real `velociraptor` binary is ever
present in this sandbox — every ok/degraded/error path is exercised by
monkeypatching `_shell.run`, the same fake-shell-call convention
tests/test_integrations_suricata.py already established for its own
_shell.py.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.config import AppConfig
from secure.dfir.velociraptor import _shell as shell_module
from secure.dfir.velociraptor import availability as availability_module
from secure.dfir.velociraptor import collect as collect_module
from secure.dfir.velociraptor.parser import parse_jsonl
from secure.integrations.base import STATUS_DEGRADED, STATUS_ERROR, STATUS_OK, STATUS_UNAVAILABLE


def _cfg(tmp_path: Path) -> AppConfig:
    return AppConfig(app_dir=str(tmp_path))


# ---------- parser.py ----------


def test_parse_jsonl_parses_every_valid_object_line():
    raw = '{"pid": 1, "name": "launchd"}\n{"pid": 2, "name": "curl"}\n'
    parsed = parse_jsonl(raw)
    assert parsed.rows == [{"pid": 1, "name": "launchd"}, {"pid": 2, "name": "curl"}]
    assert parsed.malformed_count == 0


def test_parse_jsonl_skips_blank_lines():
    raw = '{"pid": 1}\n\n   \n{"pid": 2}\n'
    parsed = parse_jsonl(raw)
    assert len(parsed.rows) == 2


def test_parse_jsonl_counts_malformed_lines_without_dropping_the_rest():
    raw = '{"pid": 1}\nnot json at all\n{"pid": 2}\n'
    parsed = parse_jsonl(raw)
    assert parsed.rows == [{"pid": 1}, {"pid": 2}]
    assert parsed.malformed_count == 1


def test_parse_jsonl_non_object_json_counts_as_malformed():
    raw = '{"pid": 1}\n[1, 2, 3]\n"just a string"\n'
    parsed = parse_jsonl(raw)
    assert parsed.rows == [{"pid": 1}]
    assert parsed.malformed_count == 2


def test_parse_jsonl_empty_output_is_zero_rows_zero_malformed():
    parsed = parse_jsonl("")
    assert parsed.rows == []
    assert parsed.malformed_count == 0


# ---------- _shell.py ----------


def test_try_get_version_returns_none_when_binary_missing(monkeypatch):
    monkeypatch.setattr(
        shell_module, "run", lambda binary, args, timeout=30.0: shell_module.ShellResult(
            ok=False, stdout="", stderr="command not found", returncode=None
        )
    )
    assert shell_module.try_get_version("velociraptor") is None


def test_try_get_version_extracts_semver(monkeypatch):
    monkeypatch.setattr(
        shell_module, "run", lambda binary, args, timeout=30.0: shell_module.ShellResult(
            ok=True, stdout="Velociraptor 0.7.1 (Cannon)", stderr="", returncode=0
        )
    )
    assert shell_module.try_get_version("velociraptor") == "0.7.1"


# ---------- availability.py ----------


def test_check_availability_missing_binary_is_unavailable(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        availability_module, "run", lambda binary, args, timeout=10.0: shell_module.ShellResult(
            ok=False, stdout="", stderr=f"{binary}: command not found", returncode=None
        )
    )
    health = availability_module.check_availability(_cfg(tmp_path))
    assert health.status == STATUS_UNAVAILABLE


def test_check_availability_present_but_broken_is_error(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        availability_module, "run", lambda binary, args, timeout=10.0: shell_module.ShellResult(
            ok=False, stdout="", stderr="permission denied", returncode=126
        )
    )
    health = availability_module.check_availability(_cfg(tmp_path))
    assert health.status == STATUS_ERROR


def test_check_availability_ok_extracts_version(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        availability_module, "run", lambda binary, args, timeout=10.0: shell_module.ShellResult(
            ok=True, stdout="Velociraptor 0.7.1", stderr="", returncode=0
        )
    )
    health = availability_module.check_availability(_cfg(tmp_path))
    assert health.status == STATUS_OK
    assert health.tool_version == "0.7.1"


# ---------- collect.py ----------


def test_run_collection_missing_binary_is_unavailable_never_exculpatory(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        collect_module, "run", lambda binary, args, timeout=120.0: shell_module.ShellResult(
            ok=False, stdout="", stderr=f"{binary}: command not found", returncode=None
        )
    )
    monkeypatch.setattr(collect_module, "try_get_version", lambda binary: None)
    outcome = collect_module.run_collection(_cfg(tmp_path), "MacOS.System.Pslist")
    assert outcome.status == STATUS_UNAVAILABLE
    assert outcome.rows == []


def test_run_collection_nonzero_exit_is_error_not_empty_success(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        collect_module, "run", lambda binary, args, timeout=120.0: shell_module.ShellResult(
            ok=False, stdout="", stderr="artifact not found on this system", returncode=1
        )
    )
    monkeypatch.setattr(collect_module, "try_get_version", lambda binary: "0.7.1")
    outcome = collect_module.run_collection(_cfg(tmp_path), "Nonexistent.Artifact")
    assert outcome.status == STATUS_ERROR
    assert outcome.rows == []
    assert outcome.tool_version == "0.7.1"


def test_run_collection_timeout_is_error(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        collect_module, "run", lambda binary, args, timeout=120.0: shell_module.ShellResult(
            ok=False, stdout="", stderr="command timed out after 120s", returncode=None
        )
    )
    monkeypatch.setattr(collect_module, "try_get_version", lambda binary: None)
    outcome = collect_module.run_collection(_cfg(tmp_path), "MacOS.System.Pslist")
    assert outcome.status == STATUS_ERROR
    assert "timed out" in outcome.detail


def test_run_collection_zero_rows_is_degraded_not_ok(tmp_path: Path, monkeypatch):
    # Zero rows must never look identical to "collected N rows, found
    # nothing concerning" — it's DEGRADED, not OK, so a caller never
    # mistakes "collection produced nothing" for a clean scan result.
    monkeypatch.setattr(
        collect_module, "run", lambda binary, args, timeout=120.0: shell_module.ShellResult(
            ok=True, stdout="", stderr="", returncode=0
        )
    )
    monkeypatch.setattr(collect_module, "try_get_version", lambda binary: "0.7.1")
    outcome = collect_module.run_collection(_cfg(tmp_path), "MacOS.System.Pslist")
    assert outcome.status == STATUS_DEGRADED
    assert outcome.rows == []


def test_run_collection_ok_parses_rows(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        collect_module, "run", lambda binary, args, timeout=120.0: shell_module.ShellResult(
            ok=True, stdout='{"pid": 1, "name": "launchd"}\n{"pid": 2, "name": "curl"}\n', stderr="", returncode=0
        )
    )
    monkeypatch.setattr(collect_module, "try_get_version", lambda binary: "0.7.1")
    outcome = collect_module.run_collection(_cfg(tmp_path), "MacOS.System.Pslist", {"pid": "2"})
    assert outcome.status == STATUS_OK
    assert len(outcome.rows) == 2
    assert outcome.tool_version == "0.7.1"
    assert outcome.started_at is not None
    assert outcome.completed_at is not None


def test_run_collection_partial_malformed_output_is_degraded(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        collect_module, "run", lambda binary, args, timeout=120.0: shell_module.ShellResult(
            ok=True, stdout='{"pid": 1}\nnot json\n', stderr="", returncode=0
        )
    )
    monkeypatch.setattr(collect_module, "try_get_version", lambda binary: None)
    outcome = collect_module.run_collection(_cfg(tmp_path), "MacOS.System.Pslist")
    assert outcome.status == STATUS_DEGRADED
    assert len(outcome.rows) == 1
    assert outcome.malformed_row_count == 1


def test_run_collection_fully_malformed_output_is_error(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        collect_module, "run", lambda binary, args, timeout=120.0: shell_module.ShellResult(
            ok=True, stdout='not json at all\n', stderr="", returncode=0
        )
    )
    monkeypatch.setattr(collect_module, "try_get_version", lambda binary: None)
    outcome = collect_module.run_collection(_cfg(tmp_path), "MacOS.System.Pslist")
    assert outcome.status == STATUS_ERROR
    assert outcome.rows == []


def test_build_args_includes_artifact_and_parameters():
    args = collect_module._build_args("MacOS.System.Pslist", {"pid": "123"})
    assert args == ["artifacts", "collect", "MacOS.System.Pslist", "--format", "jsonl", "--args", "pid=123"]
