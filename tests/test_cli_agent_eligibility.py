"""
Tests for which candidate `secure agent diagnose` and `secure agent
maintain` choose (J-0538).

Both commands promise "the first eligible failure" (and, with `--all`,
"every eligible failure"), but took `candidates[:1]` straight from
`find_repair_candidates()`, which filters by trigger kind only. The
max-attempts and already-verified refusals live in `evaluate_policy()`,
which only `attempt_repair()` consulted — after `diagnose_failure()` had
already reproduced the failure — so an ineligible first candidate was
reproduced, refused with `RepairNotEligible` (exit 2), and every eligible
failure behind it was never reached. `cmd_agent_run` already filtered;
these two now apply the same filter.

No test here runs a real repair, reproduction, or `evaluate_policy()`
against this checkout: the loop and the policy are replaced with fakes
that record what they were given, and each test asserts on that record
so a wrong seam fails instead of quietly doing real work. Each
"skips the ineligible one" test is paired with an all-eligible control,
without which "chose the second candidate" is equally satisfied by a
handler that always skips the first.

Run with:  pytest tests/test_cli_agent_eligibility.py
"""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path
from types import SimpleNamespace

from secure import cli
from secure.agent import diagnose as agent_diagnose
from secure.agent import maintenance as agent_maintenance
from secure.agent import policy as agent_policy
from secure.agent.policy import PolicyDecision, RepairCandidate
from secure.cli import agent as cli_agent
from secure.config import load_config

BLOCKED = RepairCandidate("pytest_failure", "tests/test_a.py::test_blocked", "")
OPEN = RepairCandidate("pytest_failure", "tests/test_b.py::test_open", "")


def _setup(monkeypatch, tmp_path: Path, candidates, refused_refs) -> dict:
    """Isolated app_dir, fake discovery and policy. Returns a call log."""
    monkeypatch.setattr(cli, "load_config", lambda: load_config(app_dir=tmp_path))
    log: dict = {"policy": [], "diagnosed": [], "maintained": []}
    monkeypatch.setattr(agent_policy, "find_repair_candidates", lambda conn, cfg: list(candidates))

    def fake_policy(conn, cfg, candidate, **kwargs):
        log["policy"].append(candidate.trigger_ref)
        if candidate.trigger_ref in refused_refs:
            return PolicyDecision(False, "agent_max_attempts (3) already reached", 3)
        return PolicyDecision(True, "eligible", 0)

    monkeypatch.setattr(cli_agent, "evaluate_policy", fake_policy)

    def fake_diagnose(conn, cfg, candidate, **kwargs):
        log["diagnosed"].append(candidate.trigger_ref)
        return SimpleNamespace(repair_attempted=True)

    def fake_cycle(conn, cfg, candidate, **kwargs):
        log["maintained"].append(candidate.trigger_ref)
        return SimpleNamespace(promotion_eligible=True)

    monkeypatch.setattr(agent_diagnose, "diagnose_failure", fake_diagnose)
    monkeypatch.setattr(agent_diagnose, "describe", lambda result: "diagnosed")
    monkeypatch.setattr(agent_maintenance, "run_maintenance_cycle", fake_cycle)
    monkeypatch.setattr(agent_maintenance, "describe", lambda outcome: "maintained")
    return log


def _run(fn, args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(args)
    return rc, buf.getvalue()


def _diagnose_args(**kw):
    return argparse.Namespace(**{"trigger_ref": None, "all": False, "reproduce_only": False, **kw})


# ---------- diagnose ----------


def test_diagnose_skips_an_ineligible_first_candidate(tmp_path, monkeypatch):
    log = _setup(monkeypatch, tmp_path, [BLOCKED, OPEN], {BLOCKED.trigger_ref})
    rc, out = _run(cli_agent.cmd_agent_diagnose, _diagnose_args())
    assert log["diagnosed"] == [OPEN.trigger_ref]
    assert f"Skipping [pytest_failure] {BLOCKED.trigger_ref}: agent_max_attempts" in out
    assert rc == 0


def test_diagnose_takes_the_first_when_all_are_eligible(tmp_path, monkeypatch):
    log = _setup(monkeypatch, tmp_path, [BLOCKED, OPEN], set())
    rc, out = _run(cli_agent.cmd_agent_diagnose, _diagnose_args())
    assert log["diagnosed"] == [BLOCKED.trigger_ref]
    assert "Skipping" not in out
    assert rc == 0


def test_diagnose_all_is_not_stopped_by_an_ineligible_candidate(tmp_path, monkeypatch):
    third = RepairCandidate("pytest_failure", "tests/test_c.py::test_also_open", "")
    log = _setup(monkeypatch, tmp_path, [OPEN, BLOCKED, third], {BLOCKED.trigger_ref})
    rc, _ = _run(cli_agent.cmd_agent_diagnose, _diagnose_args(all=True))
    assert log["diagnosed"] == [OPEN.trigger_ref, third.trigger_ref]
    assert rc == 0


def test_diagnose_with_only_ineligible_candidates_attempts_nothing(tmp_path, monkeypatch):
    log = _setup(monkeypatch, tmp_path, [BLOCKED], {BLOCKED.trigger_ref})
    rc, out = _run(cli_agent.cmd_agent_diagnose, _diagnose_args())
    assert log["diagnosed"] == []
    assert "No eligible failures found" in out
    assert rc == 0


def test_diagnose_trigger_ref_naming_an_ineligible_failure_says_why(tmp_path, monkeypatch):
    log = _setup(monkeypatch, tmp_path, [BLOCKED, OPEN], {BLOCKED.trigger_ref})
    rc, out = _run(cli_agent.cmd_agent_diagnose, _diagnose_args(trigger_ref=BLOCKED.trigger_ref))
    assert log["diagnosed"] == []
    assert f"Skipping [pytest_failure] {BLOCKED.trigger_ref}" in out
    assert rc == 1


def test_diagnose_reproduce_only_does_not_consult_policy(tmp_path, monkeypatch):
    """Reproduction repairs nothing, so the policy filter is not applied
    to it — the ineligible candidate is still the one reproduced."""
    log = _setup(monkeypatch, tmp_path, [BLOCKED, OPEN], {BLOCKED.trigger_ref})
    reproduced: list = []

    def fake_reproduce(candidate, cfg, **kwargs):
        reproduced.append(candidate.trigger_ref)
        return SimpleNamespace(status="reproduced", reproduced=True, command="pytest")

    monkeypatch.setattr(agent_diagnose, "reproduce_failure", fake_reproduce)
    rc, _ = _run(cli_agent.cmd_agent_diagnose, _diagnose_args(reproduce_only=True))
    assert reproduced == [BLOCKED.trigger_ref]
    assert log["policy"] == []
    assert rc == 0


# ---------- maintain ----------


def test_maintain_skips_an_ineligible_first_candidate(tmp_path, monkeypatch):
    log = _setup(monkeypatch, tmp_path, [BLOCKED, OPEN], {BLOCKED.trigger_ref})
    rc, out = _run(cli_agent.cmd_agent_maintain, argparse.Namespace(all=False))
    assert log["maintained"] == [OPEN.trigger_ref]
    assert f"Skipping [pytest_failure] {BLOCKED.trigger_ref}" in out
    assert rc == 0


def test_maintain_takes_the_first_when_all_are_eligible(tmp_path, monkeypatch):
    log = _setup(monkeypatch, tmp_path, [BLOCKED, OPEN], set())
    rc, _ = _run(cli_agent.cmd_agent_maintain, argparse.Namespace(all=False))
    assert log["maintained"] == [BLOCKED.trigger_ref]
    assert rc == 0


def test_maintain_all_is_not_stopped_by_an_ineligible_candidate(tmp_path, monkeypatch):
    log = _setup(monkeypatch, tmp_path, [BLOCKED, OPEN], {BLOCKED.trigger_ref})
    rc, _ = _run(cli_agent.cmd_agent_maintain, argparse.Namespace(all=True))
    assert log["maintained"] == [OPEN.trigger_ref]
    assert rc == 0


def _assert_maintain_refuses_every_candidate(tmp_path, monkeypatch, all_flag):
    second = RepairCandidate("pytest_failure", "tests/test_c.py::test_also_blocked", "")
    refs = [BLOCKED.trigger_ref, second.trigger_ref]
    log = _setup(monkeypatch, tmp_path, [BLOCKED, second], set(refs))
    rc, out = _run(cli_agent.cmd_agent_maintain, argparse.Namespace(all=all_flag))
    # Every candidate reached the policy, and each refusal was printed —
    # so "nothing maintained" is not satisfied by never looking.
    assert log["policy"] == refs
    for ref in refs:
        assert f"Skipping [pytest_failure] {ref}: agent_max_attempts" in out
    assert log["maintained"] == []
    assert "No eligible failures found. Nothing to maintain." in out
    assert "maintained" not in out  # the fake describe() never printed
    assert rc == 0


def test_maintain_with_only_ineligible_candidates_maintains_nothing(tmp_path, monkeypatch):
    _assert_maintain_refuses_every_candidate(tmp_path, monkeypatch, all_flag=False)


def test_maintain_all_with_only_ineligible_candidates_maintains_nothing(tmp_path, monkeypatch):
    _assert_maintain_refuses_every_candidate(tmp_path, monkeypatch, all_flag=True)
