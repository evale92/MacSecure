"""
Tests for `secure/cli/correlate.py` — the five `cmd_correlate_*`
handlers no test in this repository had ever executed.

Why this file exists, as a measurement rather than a grep. The module
defines six handlers. Exactly one of them, `cmd_correlate_mark_alert`,
is reached by an existing test (tests/test_cli_alert_history.py:178,
via the `secure.cli` re-export). The other five had zero test call
sites. Each of the six was given a crashing first statement (a call to
an undefined `_NEVER_RUN_MARKER_UNDEFINED()`) and the full suite was
run at ddc9e77: only `cmd_correlate_mark_alert` produced a
`NameError`, which is this experiment's own positive control — it
proves a marker that IS reached does kill a test, so the silence of
the other five is evidence of never being executed and not evidence of
a mutation that does nothing. The same technique established the same
claim for secure/cli/integrations.py and secure/cli/persistence.py.

Note for anyone re-running the underexamination score against this
module: its stated reason, "untested = no test imports or runs it,"
was wrong. `cli.cmd_correlate_mark_alert` runs through the
`secure/cli/__init__.py` re-export, so the module is imported and one
sixth of it executes. The real gap was narrower than the score's and
the score did not name it.

What each test below pins, and why it is worth pinning:

  * **The exit code that means "something new was found."** Both
    `cmd_correlate_run` and `cmd_correlate_chains_run` end in
    `return 1 if result.new_alerts else 0` — a nonzero exit is how a
    caller (a shell script, `run-all`) learns that a pass surfaced
    something to review. Nothing asserted it, so a correlation pass
    that found new cross-module clusters could have started reporting
    the exit code that means "clean" without any test noticing. Both
    directions are asserted, because "returns 1 on new alerts" is
    equally satisfied by a handler that always returns 1.

  * **The chain alert-review audit trail.**
    `cmd_correlate_chains_mark_alert` is a `cmd_*_mark_alert` handler
    whose `_record_alert_review_change()` call — the append-only
    record of a human changing an alert's review state (Product Phase
    13) — had never run. tests/test_cli_alert_history.py's docstring
    claims coverage of "each `cmd_*_mark_alert` handler"; it
    end-to-ends two, and this was not one of them. Its three cases are
    pinned below: a real transition writes exactly one event, a no-op
    re-mark writes none, and an alert that does not exist writes none
    and exits 1.

  * **That the two command families stay separate.** The Phase 22
    comment at secure/cli/correlate.py:117 states that nothing above
    it calls into chain scanning and nothing below it reads or writes
    `correlation_alerts`. Marking a chain alert is asserted here to
    leave `correlation_alerts` untouched, so that separation is a test
    failure to break rather than a comment to contradict.

  * **The dedup report line.** `already_known_clusters` /
    `already_known_chains` are documented on both result dataclasses
    as "proof the idempotent fingerprint dedup worked, not an error,"
    and both handlers print that line only when the count is nonzero.
    Asserted in both directions so the suppression stays deliberate.

The scanner seams: `secure/cli/correlate.py` does
`from secure.correlate import correlate` and
`from secure.correlate.chain_scanner import run_chain_correlation` at
import time, so it holds its own references. Patching
`secure.correlate.correlate` would miss it entirely. These tests patch
the names on `secure.cli.correlate` and each one asserts the fake was
actually called, so a wrong seam fails loudly instead of quietly
running a real pass over whatever database happens to be reachable.

Run with:  pytest tests/test_cli_correlate.py
"""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path

from secure.cli import correlate as cli_correlate
from secure.config import load_config
from secure.correlate.scanner import CorrelationResult
from secure.correlate.chain_scanner import ChainCorrelationResult
from secure.storage.database import Database
from secure import cli
from secure.storage.models import (
    CorrelationAlertRecord,
    add_correlation_alert,
    count_events,
    list_correlation_alerts,
    list_correlation_chain_alerts,
    list_events,
)
from secure.storage.models.correlate_chains import (
    CorrelationChainAlertRecord,
    add_correlation_chain_alert,
)


def _bootstrap_to_tmp(monkeypatch, tmp_path: Path):
    """Point `_bootstrap()` at an isolated temp app_dir, never ~/.secure.
    Same approach as tests/test_cli_alert_history.py."""
    monkeypatch.setattr(cli, "load_config", lambda: load_config(app_dir=tmp_path))
    return load_config(app_dir=tmp_path)


def _run(fn, *args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*args)
    return rc, buf.getvalue()


_MEMBER = {
    "module": "process",
    "kind": "new_process",
    "strength": "strong",
    "identifier": "p1",
    "label": None,
    "source_table": "process_entries",
    "source_id": 1,
    "timestamp": "2026-08-19T00:00:00",
}


def _alert(alert_id: int, **overrides) -> CorrelationAlertRecord:
    fields = dict(
        id=alert_id,
        created_at="2026-08-19T00:02:00",
        run_id="run1",
        fingerprint=f"fp{alert_id}",
        window_seconds=60.0,
        cluster_start="2026-08-19T00:00:00",
        cluster_end="2026-08-19T00:01:00",
        module_count=2,
        signal_count=3,
        score=15,
        severity="high",
        triggered_by=None,
        context_notes=None,
        explanation="explanation line one",
        members=[_MEMBER],
        known=False,
    )
    fields.update(overrides)
    return CorrelationAlertRecord(**fields)


def _chain_alert(alert_id: int, **overrides) -> CorrelationChainAlertRecord:
    fields = dict(
        id=alert_id,
        created_at="2026-08-19T00:02:00",
        run_id="run1",
        fingerprint=f"cfp{alert_id}",
        start_source_table="process_entries",
        start_source_id=1,
        raw_observation_count=4,
        independent_fact_count=3,
        module_count=2,
        source_count=2,
        meaningful_relationship_count=2,
        concentration=0.5,
        raw_score=20,
        score=18,
        severity="high",
        confidence="probable",
        uncertainty_notes=[],
        benign_context_notes=None,
        explanation="chain explanation",
        members=[],
        edges=[],
        known=False,
    )
    fields.update(overrides)
    return CorrelationChainAlertRecord(**fields)


def _patch_correlate(monkeypatch, result: CorrelationResult) -> list:
    """Replace the reference `secure/cli/correlate.py` actually calls.
    Returns a call log the test asserts on, so patching the wrong seam
    (and silently running a real pass) cannot pass."""
    assert hasattr(cli_correlate, "correlate"), (
        "secure/cli/correlate.py no longer binds correlate at import; "
        "this test patches the wrong seam"
    )
    calls: list = []

    def fake_correlate(conn, **kwargs):
        calls.append(kwargs)
        return result

    monkeypatch.setattr(cli_correlate, "correlate", fake_correlate)
    return calls


def _patch_chain(monkeypatch, result: ChainCorrelationResult) -> list:
    assert hasattr(cli_correlate, "run_chain_correlation"), (
        "secure/cli/correlate.py no longer binds run_chain_correlation at "
        "import; this test patches the wrong seam"
    )
    calls: list = []

    def fake_run_chain_correlation(conn, **kwargs):
        calls.append(kwargs)
        return result

    monkeypatch.setattr(cli_correlate, "run_chain_correlation", fake_run_chain_correlation)
    return calls


def _result(**kwargs) -> CorrelationResult:
    fields = dict(
        run_id="run1",
        scanned_at="2026-08-19T00:02:00",
        window_seconds=60.0,
        lookback_hours=24.0,
        triggered_by=None,
        signals_considered=7,
        clusters_considered=3,
        cross_module_clusters=1,
    )
    fields.update(kwargs)
    return CorrelationResult(**fields)


def _chain_result(**kwargs) -> ChainCorrelationResult:
    fields = dict(
        run_id="run1",
        scanned_at="2026-08-19T00:02:00",
        lookback_hours=24.0,
        candidate_start_count=5,
        chains_scored=2,
    )
    fields.update(kwargs)
    return ChainCorrelationResult(**fields)


# ---------- cmd_correlate_run: the "something new was found" exit code ----------


def test_run_exits_one_when_the_pass_produced_new_alerts(tmp_path: Path, monkeypatch):
    """A nonzero exit is how a caller learns a pass surfaced something
    to review. Nothing asserted it before this test."""
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    calls = _patch_correlate(monkeypatch, _result(new_alerts=[_alert(1), _alert(2)]))

    rc, stdout = _run(cli_correlate.cmd_correlate_run,
                      argparse.Namespace(window=60.0, lookback_hours=24.0))

    assert calls, "the patched correlate was never called"
    assert calls[0] == {"window_seconds": 60.0, "lookback_hours": 24.0, "triggered_by": None}
    assert rc == 1
    assert "NEW CORRELATION ALERTS (2):" in stdout
    assert "Signals considered: 7" in stdout
    assert "Time-clusters found: 3 (1 spanning 2+ modules)" in stdout
    assert "Review these, then: secure correlate mark-alert <id> known|unknown" in stdout
    # Newest first: the handler sorts by id descending, so #2 precedes #1.
    assert stdout.index("#2 [HIGH]") < stdout.index("#1 [HIGH]")
    assert "No new cross-module correlation clusters this run." not in stdout


def test_run_exits_zero_when_the_pass_found_nothing_new(tmp_path: Path, monkeypatch):
    """Positive control for the test above: without it, "returns 1 on
    new alerts" is equally satisfied by a handler that always
    returns 1."""
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    calls = _patch_correlate(monkeypatch, _result(cross_module_clusters=0))

    rc, stdout = _run(cli_correlate.cmd_correlate_run,
                      argparse.Namespace(window=60.0, lookback_hours=24.0))

    assert calls
    assert rc == 0
    assert "No new cross-module correlation clusters this run." in stdout
    assert "NEW CORRELATION ALERTS" not in stdout


def test_run_reports_already_known_clusters_only_when_there_are_some(tmp_path: Path, monkeypatch):
    """`already_known_clusters` is documented on CorrelationResult as
    "proof the idempotent fingerprint dedup worked, not an error", and
    the handler suppresses the line at zero. Both directions, so the
    suppression stays a decision."""
    _bootstrap_to_tmp(monkeypatch, tmp_path)

    _patch_correlate(monkeypatch, _result(already_known_clusters=4))
    _, with_dedup = _run(cli_correlate.cmd_correlate_run,
                         argparse.Namespace(window=60.0, lookback_hours=24.0))

    _patch_correlate(monkeypatch, _result(already_known_clusters=0))
    _, without_dedup = _run(cli_correlate.cmd_correlate_run,
                            argparse.Namespace(window=60.0, lookback_hours=24.0))

    assert "Already on record from an earlier run: 4" in with_dedup
    assert "Already on record from an earlier run" not in without_dedup


# ---------- cmd_correlate_list ----------


def test_list_reports_an_honest_empty_state_and_exits_zero(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()):
        pass  # create the schema, record nothing

    rc, stdout = _run(cli_correlate.cmd_correlate_list, argparse.Namespace())

    assert rc == 0
    assert "No correlation alerts recorded yet." in stdout
    # An empty list must point at how to populate it rather than read
    # as "ran and found nothing" (AGENTS.md rule 7).
    assert "secure correlate run" in stdout


def test_list_distinguishes_reviewed_from_unreviewed_alerts(tmp_path: Path, monkeypatch):
    """The KNOWN/UNKNOWN tag is the only thing on the line that says
    whether a human has looked at the alert."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_correlation_alert(
            db.conn, "run1", "fp1", 60.0, "2026-08-19T00:00:00", "2026-08-19T00:01:00",
            2, 3, 15, "high", None, None, "explanation line one", [_MEMBER],
        )

    rc, stdout = _run(cli_correlate.cmd_correlate_list, argparse.Namespace())

    assert rc == 0
    assert "[UNKNOWN]" in stdout
    assert "#1" in stdout
    assert "[HIGH" in stdout
    assert "score 15" in stdout
    assert "2 modules, 3 signals" in stdout
    assert "2026-08-19T00:00:00 to 2026-08-19T00:01:00" in stdout
    assert "explanation line one" in stdout
    assert "No correlation alerts recorded yet." not in stdout


# ---------- cmd_correlate_chains_run ----------


def test_chains_run_exits_one_when_the_pass_produced_new_alerts(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    calls = _patch_chain(monkeypatch, _chain_result(new_alerts=[_chain_alert(1)]))

    rc, stdout = _run(cli_correlate.cmd_correlate_chains_run,
                      argparse.Namespace(lookback_hours=24.0))

    assert calls, "the patched run_chain_correlation was never called"
    assert calls[0] == {"lookback_hours": 24.0}
    assert rc == 1
    assert "NEW CHAIN ALERTS (1):" in stdout
    assert "Candidate starting nodes: 5" in stdout
    assert "Chains scored this pass: 2" in stdout
    assert "#1 [HIGH] confidence probable score 18" in stdout
    assert "3 independent fact(s), 2 module(s), 2 meaningful relationship(s)" in stdout
    assert "Review these, then: secure correlate chains mark-alert <id> known|unknown" in stdout
    assert "No new evidence chains this run." not in stdout


def test_chains_run_exits_zero_when_the_pass_found_nothing_new(tmp_path: Path, monkeypatch):
    """Positive control, as above."""
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    calls = _patch_chain(monkeypatch, _chain_result(chains_scored=0))

    rc, stdout = _run(cli_correlate.cmd_correlate_chains_run,
                      argparse.Namespace(lookback_hours=24.0))

    assert calls
    assert rc == 0
    assert "No new evidence chains this run." in stdout
    assert "NEW CHAIN ALERTS" not in stdout


def test_chains_run_reports_already_known_chains_only_when_there_are_some(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)

    _patch_chain(monkeypatch, _chain_result(already_known_chains=3))
    _, with_dedup = _run(cli_correlate.cmd_correlate_chains_run,
                         argparse.Namespace(lookback_hours=24.0))

    _patch_chain(monkeypatch, _chain_result(already_known_chains=0))
    _, without_dedup = _run(cli_correlate.cmd_correlate_chains_run,
                            argparse.Namespace(lookback_hours=24.0))

    assert "Already on record from an earlier run: 3" in with_dedup
    assert "Already on record from an earlier run" not in without_dedup


# ---------- cmd_correlate_chains_list ----------


def test_chains_list_empty_state_says_chains_need_their_own_pass(tmp_path: Path, monkeypatch):
    """Phase 22's separation is operator-visible here: `run-all` runs
    every scan but does NOT run chain correlation, and the empty-state
    text is the only place that is said."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()):
        pass

    rc, stdout = _run(cli_correlate.cmd_correlate_chains_list, argparse.Namespace())

    assert rc == 0
    assert "No chain alerts recorded yet." in stdout
    assert "secure correlate chains run" in stdout
    assert "needs its own explicit `chains run` pass" in stdout


def test_chains_list_prints_the_starting_node_and_review_tag(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_correlation_chain_alert(
            db.conn, "run1", "cfp1", "process_entries", 1,
            4, 3, 2, 2, 2, 0.5, 20, 18, "high", "probable",
            [], None, "chain explanation", [], [],
        )

    rc, stdout = _run(cli_correlate.cmd_correlate_chains_list, argparse.Namespace())

    assert rc == 0
    assert "[UNKNOWN]" in stdout
    assert "score 18" in stdout
    assert "3 fact(s), 2 module(s), 2 meaningful relationship(s)" in stdout
    # The starting node is the chain's provenance anchor; without it a
    # reviewer cannot tell which observation the walk began from.
    assert "start: process_entries:1" in stdout
    assert "chain explanation" in stdout


# ---------- cmd_correlate_chains_mark_alert: the audit trail ----------


def _add_chain_alert(db):
    return add_correlation_chain_alert(
        db.conn, "run1", "cfp1", "process_entries", 1,
        4, 3, 2, 2, 2, 0.5, 20, 18, "high", "probable",
        [], None, "chain explanation", [], [],
    )


def test_chains_mark_alert_writes_exactly_one_review_event(tmp_path: Path, monkeypatch):
    """The append-only record of a human changing an alert's review
    state (Product Phase 13). This handler's
    `_record_alert_review_change()` call site had never executed."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        _add_chain_alert(db)

    rc, stdout = _run(cli_correlate.cmd_correlate_chains_mark_alert,
                      argparse.Namespace(alert_id="1", status="known"))

    assert rc == 0
    assert "Marked #1 as known." in stdout

    with Database(cfg.database_path()) as db:
        alerts = list_correlation_chain_alerts(db.conn)
        events = list_events(db.conn)
        # Phase 22 separation: the chain family never touches
        # correlation_alerts (secure/cli/correlate.py:117).
        assert list_correlation_alerts(db.conn) == []

    assert alerts[0].known is True
    review_events = [e for e in events if e.category == "alert_review_change"]
    assert len(review_events) == 1
    assert "correlation_chain_alerts alert #1" in review_events[0].message
    # The subject is the independent-fact count, not the full
    # explanation — the helper's docstring says it stores a concise
    # subject so repeated marking doesn't pile up long text.
    assert "3-fact chain" in review_events[0].message
    assert "severity=high" in review_events[0].message
    assert "UNKNOWN -> KNOWN" in review_events[0].message
    assert "chain explanation" not in review_events[0].message


def test_chains_mark_alert_no_op_remark_writes_no_second_event(tmp_path: Path, monkeypatch):
    """`_record_alert_review_change()` is documented as being called
    only on an actual transition. Re-marking an already-known alert
    must not append a second history row."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        _add_chain_alert(db)

    _run(cli_correlate.cmd_correlate_chains_mark_alert,
         argparse.Namespace(alert_id="1", status="known"))
    rc, stdout = _run(cli_correlate.cmd_correlate_chains_mark_alert,
                      argparse.Namespace(alert_id="1", status="known"))

    # The command still succeeds and still reports what it did; only
    # the history stays silent.
    assert rc == 0
    assert "Marked #1 as known." in stdout

    with Database(cfg.database_path()) as db:
        events = list_events(db.conn)
    review_events = [e for e in events if e.category == "alert_review_change"]
    assert len(review_events) == 1


def test_chains_mark_alert_records_the_reverse_transition(tmp_path: Path, monkeypatch):
    """KNOWN -> UNKNOWN is a real transition too, and the helper
    records the direction rather than just the new value."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        _add_chain_alert(db)

    _run(cli_correlate.cmd_correlate_chains_mark_alert,
         argparse.Namespace(alert_id="1", status="known"))
    rc, _ = _run(cli_correlate.cmd_correlate_chains_mark_alert,
                 argparse.Namespace(alert_id="1", status="unknown"))

    assert rc == 0
    with Database(cfg.database_path()) as db:
        alerts = list_correlation_chain_alerts(db.conn)
        events = list_events(db.conn)

    assert alerts[0].known is False
    # list_events() returns newest first, so sort by id to read the
    # history in the order it was written.
    review_events = sorted(
        (e for e in events if e.category == "alert_review_change"), key=lambda e: e.id
    )
    assert len(review_events) == 2
    assert review_events[0].message.endswith("UNKNOWN -> KNOWN")
    assert review_events[1].message.endswith("KNOWN -> UNKNOWN")


def test_chains_mark_alert_not_found_exits_one_and_writes_nothing(tmp_path: Path, monkeypatch):
    """An id that does not exist must not report the exit code that
    means "marked it" (AGENTS.md rule 7), and must leave no history."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()):
        pass

    rc, stdout = _run(cli_correlate.cmd_correlate_chains_mark_alert,
                      argparse.Namespace(alert_id="999", status="known"))

    assert rc == 1
    assert "No chain alert found with id 999" in stdout
    assert "Marked #999" not in stdout

    with Database(cfg.database_path()) as db:
        assert count_events(db.conn) == 0
