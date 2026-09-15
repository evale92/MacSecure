"""tests/test_agent_promote_verify.py — the REAL post-promotion check.

`verify_after_promotion()` is what decides, after a patch has already
been written to the live checkout, whether it stays. Every test in
tests/test_agent_promote.py replaces it with a stub so it can drive
promote()'s own branches, which left its body executed by no test at
all: rebinding it to a function that raises left all 112 tests that
reach promote() green (measured 2026-09-15 at 1975dd5, J-0409).

These tests run it unstubbed — real FAST tier, real TARGETED tier, real
`python -m pytest` re-check of the original failure — against a
disposable git repository in `tmp_path`, never the real checkout. Each
refusal test holds every other check passing, so `ok is False` can only
come from the branch the test is named for.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import secure.agent.promote as promote_module
from secure.agent.policy import TRIGGER_PYTEST_FAILURE, TRIGGER_VALIDATE_SCENARIO_FAILURE
from secure.agent.promote import verify_after_promotion
from secure.config import AppConfig, default_config


def _live_repo(tmp_path: Path, extra_files: "dict[str, str] | None" = None) -> Path:
    """A throwaway stand-in for the live checkout after the patch has
    been applied: widget() already returns 2. tests/test_widget.py is
    what TARGETED selects for secure/widget.py; tests/test_original.py
    is the original failure, deliberately outside that glob so the
    re-check and the TARGETED tier can be failed independently."""
    root = tmp_path / "live"
    root.mkdir()
    files = {
        "secure/widget.py": "def widget():\n    return 2\n",
        "tests/test_widget.py": "from secure.widget import widget\n\n\ndef test_widget():\n    assert callable(widget)\n",
        "tests/test_original.py": "from secure.widget import widget\n\n\ndef test_original():\n    assert widget() == 2\n",
    }
    files.update(extra_files or {})
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    subprocess.run(["git", "init", "-q"], cwd=str(root), capture_output=True, check=True)
    return root


@dataclass
class _Run:
    trigger_kind: str = TRIGGER_PYTEST_FAILURE
    trigger_ref: str = "tests/test_original.py::test_original"
    changed_files: list = field(default_factory=lambda: ["secure/widget.py"])


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    cfg.agent_verify_timeout_seconds = 60
    return cfg


def _note(notes, prefix: str) -> str:
    matches = [n for n in notes if n.startswith(prefix)]
    assert len(matches) == 1, notes
    return matches[0]


def test_every_check_passing_and_the_original_failure_gone_is_ok(tmp_path: Path):
    live = _live_repo(tmp_path)

    ok, notes = verify_after_promotion(_Run(), _cfg(tmp_path), root=live)

    assert ok is True, notes
    assert _note(notes, "FAST:") == "FAST: status=ok passed=True"
    assert _note(notes, "TARGETED:") == "TARGETED: status=ok passed=True (1 file(s))"
    assert _note(notes, "ORIGINAL FAILURE") == (
        "ORIGINAL FAILURE re-check: tests/test_original.py::test_original now passes"
    )


def test_an_original_failure_that_still_fails_is_not_ok(tmp_path: Path):
    live = _live_repo(tmp_path, {"secure/widget.py": "def widget():\n    return 1\n"})

    ok, notes = verify_after_promotion(_Run(), _cfg(tmp_path), root=live)

    assert ok is False, notes
    assert _note(notes, "FAST:") == "FAST: status=ok passed=True"
    assert _note(notes, "TARGETED:").startswith("TARGETED: status=ok passed=True")
    assert _note(notes, "ORIGINAL FAILURE").endswith("STILL FAILS")


def test_a_failing_fast_tier_is_not_ok(tmp_path: Path):
    live = _live_repo(tmp_path, {"secure/broken.py": "def broken(:\n"})

    ok, notes = verify_after_promotion(_Run(), _cfg(tmp_path), root=live)

    assert ok is False, notes
    assert _note(notes, "FAST:") == "FAST: status=ok passed=False"
    assert _note(notes, "TARGETED:").startswith("TARGETED: status=ok passed=True")
    assert _note(notes, "ORIGINAL FAILURE").endswith("now passes")


def test_a_failing_targeted_tier_is_not_ok(tmp_path: Path):
    live = _live_repo(tmp_path, {"tests/test_widget_extra.py": "def test_extra():\n    assert False\n"})

    ok, notes = verify_after_promotion(_Run(), _cfg(tmp_path), root=live)

    assert ok is False, notes
    assert _note(notes, "FAST:") == "FAST: status=ok passed=True"
    assert _note(notes, "TARGETED:") == "TARGETED: status=ok passed=False (2 file(s))"
    assert _note(notes, "ORIGINAL FAILURE").endswith("now passes")


def test_nothing_targeted_is_not_ok(tmp_path: Path):
    """No test file maps to the change: that is "nothing checked", not
    "nothing failed"."""
    live = _live_repo(tmp_path, {"README.md": "changed\n"})

    ok, notes = verify_after_promotion(_Run(changed_files=["README.md"]), _cfg(tmp_path), root=live)

    assert ok is False, notes
    assert _note(notes, "FAST:") == "FAST: status=ok passed=True"
    assert _note(notes, "TARGETED:") == "TARGETED: no test files map to the changed files"
    assert _note(notes, "ORIGINAL FAILURE").endswith("now passes")


def test_a_re_check_that_cannot_finish_is_not_ok(tmp_path: Path, monkeypatch):
    live = _live_repo(tmp_path)
    monkeypatch.setattr(promote_module, "_VERIFY_TIMEOUT_SECONDS", 0.001)

    ok, notes = verify_after_promotion(_Run(), _cfg(tmp_path), root=live)

    assert ok is False, notes
    assert _note(notes, "FAST:") == "FAST: status=ok passed=True"
    assert _note(notes, "TARGETED:").startswith("TARGETED: status=ok passed=True")
    assert _note(notes, "ORIGINAL FAILURE") == "ORIGINAL FAILURE re-check: could not run (TimeoutExpired)"


def test_the_re_check_runs_with_a_throwaway_home_and_writes_no_bytecode(tmp_path: Path, monkeypatch):
    """The re-check runs a test in the operator's working tree, so it
    must not see the operator's HOME. The probe test fails unless both
    hold, which turns the environment into the re-check's verdict. The
    calling process's own environment is pinned first, so neither half
    can pass by inheritance."""
    monkeypatch.setenv("HOME", str(tmp_path / "operator-home"))
    monkeypatch.delenv("PYTHONDONTWRITEBYTECODE", raising=False)
    probe = (
        "import os\n\n\ndef test_probe():\n"
        "    assert os.path.basename(os.environ['HOME']).startswith('secure-postpromo-home-')\n"
        "    assert os.environ.get('PYTHONDONTWRITEBYTECODE') == '1'\n"
    )
    live = _live_repo(tmp_path, {"tests/test_probe.py": probe})
    audit_trail: list = []

    ok, notes = verify_after_promotion(
        _Run(trigger_ref="tests/test_probe.py::test_probe"), _cfg(tmp_path), root=live, audit_trail=audit_trail
    )

    assert ok is True, notes
    rechecks = [e for e in audit_trail if e["action"] == "post-promotion original-failure re-check"]
    assert len(rechecks) == 1, audit_trail
    assert rechecks[0]["target"] == "tests/test_probe.py::test_probe"
    assert rechecks[0]["mutating"] is False
    assert rechecks[0]["exit_code"] == 0


def test_a_non_pytest_trigger_has_no_original_failure_to_re_check(tmp_path: Path):
    live = _live_repo(tmp_path, {"secure/widget.py": "def widget():\n    return 1\n"})

    ok, notes = verify_after_promotion(
        _Run(trigger_kind=TRIGGER_VALIDATE_SCENARIO_FAILURE), _cfg(tmp_path), root=live
    )

    assert ok is True, notes
    assert not any(n.startswith("ORIGINAL FAILURE") for n in notes), notes
