"""
Tests for the two functions in secure/storage/models/agent.py that had
zero references anywhere in tests/ — list_agent_repair_runs_for_trigger()
and set_agent_repair_run_change_request().

Why these two, and why here.

The Study Mode score called this module "untested = no test imports or
runs it". That is wrong: tests/test_agent.py:73-81 imports five of its
functions from secure.storage.models, and test_agent_verified.py,
test_agent_review.py, test_agent_diagnose.py and test_agent_maintenance.py
reference more (J-0276). The real gap is narrower than the score's and
the score does not name it — 2 of the module's 8 public functions had no
reference in tests/ at all, and one of them is the reader
secure/agent/policy.py's bounded-retry cap is built on.

list_agent_repair_runs_for_trigger() is a PAGINATED reader: it is
`ORDER BY id DESC LIMIT ?` with `limit: int = 20`. Its own docstring
says it returns "every prior attempt against the same failure", and
policy.py:226 takes that literally — `attempts_so_far = len(prior)`.
It is not every prior attempt; it is the newest `limit` of them. With
25 real prior attempts against one trigger, attempts_so_far comes back
as 20, so `attempts_so_far >= cfg.agent_max_attempts` is unreachable
for any agent_max_attempts > 20 (AppConfig has no clamp on it), and
`policy.py:235`'s already_verified guard cannot see a status='verified'
run that has fallen outside the same 20-row window. Measured: at
agent_max_attempts=25, 26 and 100, evaluate_policy() returns
allowed=True "eligible" against 25 prior attempts, one of them
verified. That is J-0275, and the repair belongs in policy.py — which
AppConfig.agent_path_denylist (config.py:337) puts off-limits to an
automated agent, so it is left as a job.

What these tests can do from here is pin the contract policy.py
assumed instead of checking: that the reader is limit-bounded, that it
really is newest-first, and that the table it reads holds more rows
than a default call returns. If a later change makes this reader
unbounded, test_default_limit_under_reports_the_real_attempt_count
fails and names J-0275, because that change is what makes policy.py's
`len()` correct — the two have to move together.

set_agent_repair_run_change_request() carries an invariant-2 claim in
its own docstring: it links the two rows "by id only, never by copying
approval state". Nothing tested either half.

Named test_storage_models_agent.py because targeted_test_files() maps
secure/storage/models/agent.py to its subpackage segment 'storage',
i.e. tests/test_storage*.py — not tests/test_agent*.py.

Run with:  pytest tests/test_storage_models_agent.py
"""

from __future__ import annotations

from pathlib import Path

from secure.storage.database import Database
from secure.storage.models import (
    add_agent_repair_run,
    complete_agent_repair_run,
    find_agent_repair_run,
    list_agent_repair_runs_for_trigger,
    set_agent_repair_run_change_request,
)

TRIGGER_KIND = "pytest_failure"
TRIGGER_REF = "tests/test_x.py::test_y"


def _add_run(conn, *, kind: str = TRIGGER_KIND, ref: str = TRIGGER_REF, n: int = 1) -> str:
    """One prior attempt row, the same way secure/agent/orchestrator.py
    creates it: status='running' before any external tool is invoked."""
    return add_agent_repair_run(
        conn,
        created_at=f"2026-01-01T00:00:{n:02d}+00:00",
        attempt_number=n,
        max_attempts=99,
        trigger_kind=kind,
        trigger_ref=ref,
        trigger_detail="detail",
        base_commit="abc123",
        worktree_path="/worktrees/wt",
        agent_home_path="/worktrees/home",
        tool_name="mini-swe-agent",
        model_name="ollama/test",
    )


def _real_count(conn, *, kind: str = TRIGGER_KIND, ref: str = TRIGGER_REF) -> int:
    """The number of prior attempts that actually exist, counted in SQL
    rather than by measuring a limited page of them."""
    return conn.execute(
        "SELECT COUNT(*) AS c FROM agent_repair_runs WHERE trigger_kind = ? AND trigger_ref = ?",
        (kind, ref),
    ).fetchone()["c"]


# ---------- list_agent_repair_runs_for_trigger: a paginated reader ----------


def test_default_limit_under_reports_the_real_attempt_count(tmp_path: Path):
    """25 prior attempts, but a default call returns 20 of them.

    This is the whole of J-0275 in one assertion. If this test ever
    fails because the reader became unbounded, that is not a broken
    test — it means policy.py:226's `attempts_so_far = len(prior)` has
    finally become true, and J-0275 should be closed rather than this
    assertion relaxed.
    """
    with Database(tmp_path / "secure.db") as db:
        for n in range(1, 26):
            _add_run(db.conn, n=n)

        assert _real_count(db.conn) == 25
        assert len(list_agent_repair_runs_for_trigger(
            db.conn, trigger_kind=TRIGGER_KIND, trigger_ref=TRIGGER_REF)) == 20

        # Positive control: the rows the default call dropped are
        # present and reachable, so 20 is the limit talking and not an
        # insert that silently failed.
        assert len(list_agent_repair_runs_for_trigger(
            db.conn, trigger_kind=TRIGGER_KIND, trigger_ref=TRIGGER_REF, limit=100)) == 25


def test_limit_is_honoured_and_order_is_newest_first(tmp_path: Path):
    """`limit` bounds the page and the page starts at the newest row.

    Both halves matter to the caller: the limit is why len() is not a
    count, and newest-first is why the row that falls out of the window
    is the OLDEST attempt — which is how a status='verified' first
    attempt becomes invisible to policy.py:235.
    """
    with Database(tmp_path / "secure.db") as db:
        for n in range(1, 6):
            _add_run(db.conn, n=n)

        for limit in (1, 2, 4, 5):
            page = list_agent_repair_runs_for_trigger(
                db.conn, trigger_kind=TRIGGER_KIND, trigger_ref=TRIGGER_REF, limit=limit)
            assert len(page) == limit
            assert [r.attempt_number for r in page] == list(range(5, 5 - limit, -1))

        # And a limit above the row count is not padded or truncated.
        page = list_agent_repair_runs_for_trigger(
            db.conn, trigger_kind=TRIGGER_KIND, trigger_ref=TRIGGER_REF, limit=50)
        assert [r.attempt_number for r in page] == [5, 4, 3, 2, 1]


def test_an_older_verified_run_falls_outside_the_default_window(tmp_path: Path):
    """The second half of J-0275, stated where it can be measured.

    policy.py:235 asks `any(r.status == "verified" for r in prior)`
    over the same default page. A run verified early and then followed
    by 20 more attempts is outside that page, so the guard reads False
    while the verified row is sitting in the table.
    """
    with Database(tmp_path / "secure.db") as db:
        first = _add_run(db.conn, n=1)
        complete_agent_repair_run(
            db.conn, run_id=first, completed_at="2026-01-01T01:00:00+00:00", status="verified")
        for n in range(2, 26):
            _add_run(db.conn, n=n)

        default_page = list_agent_repair_runs_for_trigger(
            db.conn, trigger_kind=TRIGGER_KIND, trigger_ref=TRIGGER_REF)
        assert not any(r.status == "verified" for r in default_page)

        # Positive control: the verified run exists and an unbounded
        # read finds it, so the line above is the window and not a
        # status that never got written.
        assert find_agent_repair_run(db.conn, first).status == "verified"
        full = list_agent_repair_runs_for_trigger(
            db.conn, trigger_kind=TRIGGER_KIND, trigger_ref=TRIGGER_REF, limit=100)
        assert [r.run_id for r in full if r.status == "verified"] == [first]


def test_both_trigger_kind_and_trigger_ref_filter(tmp_path: Path):
    """Neither half of the WHERE clause is decoration.

    A reader that matched on trigger_ref alone would let one failing
    test's attempts be counted against another trigger kind, and vice
    versa. Every cross combination is checked, not just the one the
    caller happens to pass.
    """
    with Database(tmp_path / "secure.db") as db:
        _add_run(db.conn, kind="pytest_failure", ref="tests/a.py::x", n=1)
        _add_run(db.conn, kind="pytest_failure", ref="tests/b.py::x", n=2)
        _add_run(db.conn, kind="validate_scenario_failure", ref="tests/a.py::x", n=3)

        def refs(kind: str, ref: str) -> "list[int]":
            return [r.attempt_number for r in list_agent_repair_runs_for_trigger(
                db.conn, trigger_kind=kind, trigger_ref=ref, limit=100)]

        assert refs("pytest_failure", "tests/a.py::x") == [1]
        assert refs("pytest_failure", "tests/b.py::x") == [2]
        assert refs("validate_scenario_failure", "tests/a.py::x") == [3]
        # Same ref, unseen kind, and same kind, unseen ref: both empty.
        assert refs("detect_rule_test_failure", "tests/a.py::x") == []
        assert refs("pytest_failure", "tests/c.py::x") == []


# ---------- set_agent_repair_run_change_request: link by id only ----------


def test_set_change_request_links_by_id_and_leaves_status_alone(tmp_path: Path):
    """Its docstring: links "by id only, never by copying approval state".

    Both halves are asserted — the id is written, and every other field
    of the row is byte-for-byte what it was before the call. A link
    that also nudged `status` would be the run's own record of approval,
    which is exactly what invariant 2 keeps in ai_change_requests.
    """
    with Database(tmp_path / "secure.db") as db:
        run_id = _add_run(db.conn, n=1)
        complete_agent_repair_run(
            db.conn, run_id=run_id, completed_at="2026-01-01T01:00:00+00:00",
            status="verified", verification_passed=True, diff_hash="deadbeef")
        before = find_agent_repair_run(db.conn, run_id)
        assert before.change_request_id is None

        after = set_agent_repair_run_change_request(
            db.conn, run_id=run_id, change_request_id="CR-7")

        assert after.change_request_id == "CR-7"
        assert find_agent_repair_run(db.conn, run_id).change_request_id == "CR-7"
        # Nothing else moved.
        changed = {
            name for name in vars(before)
            if name != "change_request_id" and getattr(before, name) != getattr(after, name)
        }
        assert changed == set()
        assert after.status == "verified"


def test_set_change_request_reports_absence_for_an_unknown_run(tmp_path: Path):
    """Rule 7: an unknown run_id returns None rather than inventing a
    row or silently succeeding, and writes nothing."""
    with Database(tmp_path / "secure.db") as db:
        _add_run(db.conn, n=1)

        assert set_agent_repair_run_change_request(
            db.conn, run_id="AR-999", change_request_id="CR-7") is None

        # Positive control: the same call against a run that does exist
        # succeeds, so None above is the missing row and not a broken
        # call signature.
        assert set_agent_repair_run_change_request(
            db.conn, run_id="AR-1", change_request_id="CR-7") is not None
        assert db.conn.execute(
            "SELECT COUNT(*) AS c FROM agent_repair_runs WHERE change_request_id IS NOT NULL"
        ).fetchone()["c"] == 1


def test_agent_repair_runs_has_no_approval_state_column_of_its_own(tmp_path: Path):
    """The structural half of the same claim: a run's approval status is
    "always read by joining to ai_change_requests, never duplicated onto
    this table, so the two can never disagree". A column to hold it is
    the thing that would make them able to disagree."""
    with Database(tmp_path / "secure.db") as db:
        columns = [
            row["name"] for row in
            db.conn.execute("PRAGMA table_info(agent_repair_runs)").fetchall()
        ]
        # Positive control for the matcher: the link column IS there, so
        # an empty `offenders` below means "no approval column", not
        # "PRAGMA returned nothing".
        assert "change_request_id" in columns
        offenders = [
            c for c in columns
            if "approv" in c or "reject" in c or c in {"approved", "approved_at", "approved_by"}
        ]
        assert offenders == [], f"approval state duplicated onto agent_repair_runs: {offenders}"
