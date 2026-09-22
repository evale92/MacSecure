"""
Agent-originated change requests must be approved through the
revalidation gate, `secure agent approve <run_id>`, never through plain
`secure ai changes approve`.

secure/agent/orchestrator.py's revalidate_before_approval() "must be
called … before approving any agent-originated change request". The
Change Request Center (Phase 40) sent every pending request, agent ones
included, to `ai changes approve`, which only compares a revision hash
read from the same stored record, so a drifted worktree was approved
without the re-check. `ai changes approve` now refuses a change request
that a repair run proposed and names the command that re-checks it;
`secure agent center show` gives that command for agent requests; and the
lookup that links a change request to its run is exact rather than a scan
of recent runs.

Run with:  pytest tests/test_cli_ai_approve_agent_gate.py
"""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path

from secure import cli
from secure.cli import agent as agent_cli
from secure.cli import ai as ai_cli
from secure.config import load_config
from secure.storage.database import Database
from secure.storage.models import find_ai_change_request
from secure.storage.models.agent import (
    add_agent_repair_run,
    find_agent_repair_run_for_change_request,
    set_agent_repair_run_change_request,
)
from secure.storage.models.ai import add_ai_change_request


def _bootstrap_to_tmp(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(cli, "load_config", lambda: load_config(app_dir=tmp_path))
    return load_config(app_dir=tmp_path)


def _run(fn, **kwargs):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(argparse.Namespace(**kwargs))
    return rc, buf.getvalue()


def _add_cr(conn, cr_id: str) -> str:
    revision_hash = f"hash-{cr_id}"
    add_ai_change_request(
        conn, cr_id=cr_id, created_at="2026-09-22T00:00:00+00:00", revision_hash=revision_hash,
        title="t", proposed_change="p", reason="r", affected_component="c", risks="",
        verification_run_id=None, model_a_opinion="", model_b_opinion="",
    )
    return revision_hash


def _add_run(conn) -> str:
    return add_agent_repair_run(
        conn, created_at="2026-09-22T00:00:00+00:00", attempt_number=1, max_attempts=1,
        trigger_kind="pytest_failure", trigger_ref="tests/test_x.py::test_y", trigger_detail="",
        base_commit="abc", worktree_path="/tmp/wt", agent_home_path="/tmp/home",
        tool_name="mini", model_name="ollama/x",
    )


def _seed_agent_cr(conn, cr_id: str = "CR-1") -> "tuple[str, str]":
    revision_hash = _add_cr(conn, cr_id)
    run_id = _add_run(conn)
    set_agent_repair_run_change_request(conn, run_id=run_id, change_request_id=cr_id)
    return revision_hash, run_id


# ---------- storage: exact lookup ----------


def test_the_run_for_a_change_request_is_found_exactly_not_by_a_recent_scan(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        _, run_id = _seed_agent_cr(db.conn, "CR-1")
        for _ in range(501):  # more than any "recent runs" window
            _add_run(db.conn)
        found = find_agent_repair_run_for_change_request(db.conn, "CR-1")
        assert found is not None and found.run_id == run_id
        assert find_agent_repair_run_for_change_request(db.conn, "CR-404") is None


# ---------- `secure ai changes approve` ----------


def test_plain_approve_refuses_an_agent_originated_change_request(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        revision_hash, run_id = _seed_agent_cr(db.conn)

    rc, out = _run(ai_cli.cmd_ai_changes_approve, cr_id="CR-1", revision_hash=revision_hash, approved_by="erick")

    assert rc == 1
    assert "REFUSED" in out
    assert f"secure agent approve {run_id} --cr-id CR-1" in out
    with Database(cfg.database_path()) as db:
        assert find_ai_change_request(db.conn, "CR-1").status == "pending"


def test_plain_approve_still_approves_a_change_request_no_run_proposed(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        revision_hash = _add_cr(db.conn, "CR-1")

    rc, out = _run(ai_cli.cmd_ai_changes_approve, cr_id="CR-1", revision_hash=revision_hash, approved_by="erick")

    assert rc == 0, out
    with Database(cfg.database_path()) as db:
        assert find_ai_change_request(db.conn, "CR-1").status == "approved"


# ---------- `secure agent center show` ----------


def test_center_show_tells_you_to_approve_an_agent_request_through_the_gate(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        _, run_id = _seed_agent_cr(db.conn)

    rc, out = _run(agent_cli.cmd_agent_center_show, cr_id="CR-1", tests=False, review=False, diff=False)

    assert rc == 0, out
    assert f"secure agent approve {run_id} --cr-id CR-1" in out
    assert "secure ai changes approve" not in out


def test_center_show_keeps_plain_approve_for_a_non_agent_request(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        revision_hash = _add_cr(db.conn, "CR-1")

    rc, out = _run(agent_cli.cmd_agent_center_show, cr_id="CR-1", tests=False, review=False, diff=False)

    assert rc == 0, out
    assert f"secure ai changes approve CR-1 {revision_hash}" in out


# ---------- `secure agent approve --cr-id` ----------


def _relink(conn, run_id: str, cr_id: str) -> str:
    """What revalidation does on drift: a replacement CR, and the run
    re-pointed to it."""
    revision_hash = _add_cr(conn, cr_id)
    set_agent_repair_run_change_request(conn, run_id=run_id, change_request_id=cr_id)
    return revision_hash


def test_agent_approve_refuses_when_the_run_now_links_a_different_request(tmp_path: Path, monkeypatch):
    # The stale-window case: the dialog said CR-1, but revalidation has
    # since superseded it and re-pointed the run to CR-2.
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        _, run_id = _seed_agent_cr(db.conn, "CR-1")
        _relink(db.conn, run_id, "CR-2")

    def must_not_revalidate(*a, **k):
        raise AssertionError("refusal must come before revalidation")

    monkeypatch.setattr(agent_cli, "revalidate_before_approval", must_not_revalidate)
    rc, out = _run(agent_cli.cmd_agent_approve, run_id=run_id, cr_id="CR-1", approved_by="gui")

    assert rc == 1
    assert "REFUSED" in out and "CR-2" in out
    with Database(cfg.database_path()) as db:
        assert find_ai_change_request(db.conn, "CR-2").status == "pending"


def test_agent_approve_with_the_linked_request_goes_on_to_revalidation(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        _, run_id = _seed_agent_cr(db.conn, "CR-1")

    def sentinel(*a, **k):
        raise ValueError("REVALIDATION REACHED")

    monkeypatch.setattr(agent_cli, "revalidate_before_approval", sentinel)
    rc, out = _run(agent_cli.cmd_agent_approve, run_id=run_id, cr_id="CR-1", approved_by="gui")

    assert rc == 1
    assert "REVALIDATION REACHED" in out
    assert "REFUSED" not in out


def test_after_a_drift_the_replacement_is_named_in_the_next_approve_command(tmp_path: Path, monkeypatch):
    from types import SimpleNamespace

    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        _, run_id = _seed_agent_cr(db.conn, "CR-1")
        _add_cr(db.conn, "CR-2")  # the replacement revalidation would create

    drifted = SimpleNamespace(diff_matches=False, old_cr_id="CR-1", new_cr_id="CR-2", detail="diff changed")
    monkeypatch.setattr(agent_cli, "revalidate_before_approval", lambda *a, **k: drifted)
    rc, out = _run(agent_cli.cmd_agent_approve, run_id=run_id, cr_id="CR-1", approved_by="gui")

    assert rc == 1
    assert f"secure agent approve {run_id} --cr-id CR-2" in out
    assert "secure ai changes approve" not in out


def test_agent_approve_refuses_if_revalidation_checked_a_different_request(tmp_path: Path, monkeypatch):
    # Race guard: revalidation re-reads the run, so if something relinked
    # it between the --cr-id check and revalidation, approving would bind
    # to a request the operator did not name.
    from types import SimpleNamespace

    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        _, run_id = _seed_agent_cr(db.conn, "CR-1")
        _add_cr(db.conn, "CR-2")

    other = SimpleNamespace(diff_matches=True, old_cr_id="CR-2", new_cr_id=None, detail="")
    monkeypatch.setattr(agent_cli, "revalidate_before_approval", lambda *a, **k: other)
    rc, out = _run(agent_cli.cmd_agent_approve, run_id=run_id, cr_id="CR-1", approved_by="gui")

    assert rc == 1
    assert "REFUSED" in out
    with Database(cfg.database_path()) as db:
        assert find_ai_change_request(db.conn, "CR-1").status == "pending"
        assert find_ai_change_request(db.conn, "CR-2").status == "pending"
