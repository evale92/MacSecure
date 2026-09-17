"""secure/loghunt: fixed predicates, a bounded window, and no clean zero from an incomplete run."""

from __future__ import annotations

import argparse
import json

import pytest

import secure.cli.loghunt as cli_loghunt
from secure.loghunt import HUNTS, MAX_HOURS, run_hunts
from secure.loghunt._shell import ShellResult
from secure.loghunt.hunts import summarise


def _ndjson(events, finished=True):
    lines = [json.dumps(e) for e in events]
    if finished:
        lines.append(json.dumps({"count": len(events), "finished": 1}))
    return "\n".join(lines) + "\n"


EVENTS = [
    {"timestamp": "2026-09-16 10:00:00", "processImagePath": "/usr/libexec/syspolicyd",
     "formatString": "GK performScan: %@", "eventMessage": "GK performScan: <private>"},
    {"timestamp": "2026-09-16 11:00:00", "processImagePath": "/usr/libexec/syspolicyd",
     "formatString": "GK performScan: %@", "eventMessage": "GK performScan: <private>"},
    {"timestamp": "2026-09-16 12:00:00", "processImagePath": "/System/Library/.../tccd",
     "formatString": "AUTHREQ_RESULT: authValue=%llu", "eventMessage": "AUTHREQ_RESULT: authValue=0"},
]


def test_summary_groups_by_template_with_first_last_and_an_example():
    total, complete, rows = summarise("Filtering the log data using ...\n" + _ndjson(EVENTS))
    assert (total, complete) == (3, True)
    assert rows[0] == {"template": "syspolicyd: GK performScan: %@", "count": 2, "first": "2026-09-16 10:00:00",
                       "last": "2026-09-16 11:00:00", "example": "GK performScan: <private>"}


def test_every_hunt_runs_fixed_argv_with_the_absolute_log_tool():
    calls = []

    def runner(args):
        calls.append(args)
        return ShellResult(True, _ndjson([]), "", 0)

    results = run_hunts(hours=6, runner=runner)
    assert [r.name for r in results] == list(HUNTS)
    assert all(r.status == "OK" and r.complete and r.total == 0 for r in results)
    assert calls[0][:6] == ["/usr/bin/log", "show", "--style", "ndjson", "--last", "6h"]
    assert calls[0][6:] == ["--predicate", HUNTS["xprotect_remediator"][0]]


def test_output_without_the_finished_marker_is_an_error_not_a_zero():
    results = run_hunts(hours=1, names=["gatekeeper"], runner=lambda a: ShellResult(True, _ndjson(EVENTS, finished=False), "", 0))
    assert results[0].status == "ERROR" and not results[0].complete and "finished marker" in results[0].detail


def test_a_nonzero_exit_is_an_error_even_when_the_finished_marker_is_there():
    # `log show` can print its {"finished": 1} trailer and still exit non-zero — a
    # predicate the running OS rejects late, an archive it could only partly read. The
    # trailer says output ended tidily, not that the hunt was allowed to finish.
    quiet = run_hunts(hours=1, names=["gatekeeper"],
                      runner=lambda a: ShellResult(False, _ndjson(EVENTS), "", 1))[0]
    assert quiet.status == "ERROR" and quiet.detail == "exit 1"
    assert quiet.complete and quiet.total == 3 and quiet.templates    # what it did read is still summarised
    loud = run_hunts(hours=1, names=["gatekeeper"],
                     runner=lambda a: ShellResult(False, _ndjson(EVENTS), "log: archive unreadable", 2))[0]
    assert loud.status == "ERROR" and loud.detail == "log: archive unreadable"
    # Control: the same three events and the same trailer at exit 0 are the OK path, so
    # it is the exit code deciding here and not the summary.
    clean = run_hunts(hours=1, names=["gatekeeper"],
                      runner=lambda a: ShellResult(True, _ndjson(EVENTS), "", 0))[0]
    assert clean.status == "OK" and clean.total == 3 and clean.detail == ""


def test_a_timeout_or_missing_tool_is_reported():
    timed_out = run_hunts(names=["gatekeeper"], runner=lambda a: ShellResult(False, "", "command timed out", None))
    missing = run_hunts(names=["gatekeeper"], runner=lambda a: ShellResult(False, "", "/usr/bin/log: command not found", None))
    assert timed_out[0].status == "ERROR" and missing[0].status == "UNAVAILABLE"


def test_window_and_hunt_names_are_bounded():
    with pytest.raises(ValueError):
        run_hunts(hours=MAX_HOURS + 1, runner=lambda a: None)
    with pytest.raises(ValueError):
        run_hunts(hours=0, runner=lambda a: None)
    with pytest.raises(ValueError):
        run_hunts(names=['process == "x" OR 1'], runner=lambda a: None)


def test_cli_prints_summary_and_exits_nonzero_when_a_hunt_failed(monkeypatch, capsys):
    def fake(hours, names):
        ok = run_hunts(hours, ["gatekeeper"], runner=lambda a: ShellResult(True, _ndjson(EVENTS), "", 0))
        bad = run_hunts(hours, ["tcc_denials"], runner=lambda a: ShellResult(False, "", "command timed out", None))
        return ok + bad

    monkeypatch.setattr(cli_loghunt, "_bootstrap", lambda: None)
    monkeypatch.setattr(cli_loghunt, "run_hunts", fake)
    code = cli_loghunt.cmd_loghunt(argparse.Namespace(hours=24, hunt=None))
    out = capsys.readouterr().out
    assert code == 1
    assert "gatekeeper: 3 event(s)" in out and "GK performScan" in out
    assert "tcc_denials: ERROR" in out and "not the same as no events" in out


def test_the_cli_exposes_loghunt_with_only_the_fixed_hunt_names():
    from secure.cli import build_parser

    args = build_parser().parse_args(["loghunt", "--hours", "6", "--hunt", "gatekeeper", "--hunt", "tcc_denials"])
    assert args.func is cli_loghunt.cmd_loghunt and args.hunt == ["gatekeeper", "tcc_denials"]
    with pytest.raises(SystemExit):
        build_parser().parse_args(["loghunt", "--hunt", "anything else"])


def test_failed_logins_hunt_is_pinned_to_owning_processes_and_last_in_order():
    predicate, meaning = HUNTS["failed_logins"]
    assert list(HUNTS)[-1] == "failed_logins"
    for owner in ('subsystem == "com.apple.opendirectoryd"', 'process == "loginwindow"', 'process == "sshd"', 'process == "sudo"'):
        assert owner in predicate
    # The unanchored phrase that matched ScreenTime/Mail noise must not come back.
    assert 'eventMessage CONTAINS[c] "invalid user"' not in predicate
    calls = []
    run_hunts(hours=24, names=["failed_logins"], runner=lambda a: calls.append(a) or ShellResult(True, _ndjson([]), "", 0))
    assert calls[0][-1] == predicate
