"""
Behavioural tests for the Baseline & Anomalies window's Mark flow
(secure_gui/baseline_view.py), driven through real Tk widgets.

b6312ce fixed `_mark` (it ended in a StringVar written back to itself,
so the screen never changed) and pinned the fix with an AST shape check
in tests/test_gui_baseline_formatters.py. Its commit message records
that the widget itself was never imported or rendered, because that
interpreter had no _tkinter. These tests close that gap: they build the
window, select a row, press Mark and assert what reaches run_command and
the status line.

Data and the confirmation dialog are replaced in the baseline_view
namespace (it imports them by name), so no database or dialog is
involved. tkinter is imported inside the fixture, never at module level,
so this file still collects under an interpreter without _tkinter and
the tests skip there instead of erroring.

Run with:  pytest tests/test_gui_baseline_window.py
"""

from __future__ import annotations

import pytest

from secure_gui.data_access import AnomalyRow, BaselineOverview


def _anomaly(*, id: int = 7, known: bool = False) -> AnomalyRow:
    return AnomalyRow(
        id=id, entity_type="process", entity_key="/usr/bin/curl",
        feature_name="signing_status", observed_value="unsigned",
        observed_at="2026-09-21T10:00:00+00:00", created_at="2026-09-21T10:00:01+00:00",
        run_id="run-1", expected_summary="signed", score_breakdown={"novelty": 3},
        anomaly_score=3, anomaly_tier="medium", maturity_state_at_time="established",
        eligible_weight_total_at_time=25.0, eligible_distinct_days_at_time=25,
        source_table=None, source_id=None, known=known, caveats=(), raw={"id": id},
    )


def _overview() -> BaselineOverview:
    return BaselineOverview(
        total_entities=1, maturity_counts={"established": 1}, excluded_count=0,
        frozen_count=0, cap_usage={}, total_anomalies=1, tier_counts={"medium": 1},
        unreviewed_anomalies=1, latest_run=None, total_runs=0, partial_runs=0, failed_runs=0,
    )


@pytest.fixture
def tk_root():
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError as exc:  # no display available
        pytest.skip(f"Tk cannot create a root window here: {exc}")
    root.withdraw()
    yield root
    root.destroy()


def _walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


def _open(tk_root, monkeypatch, rows, *, confirm=True):
    from secure_gui import baseline_view

    monkeypatch.setattr(baseline_view, "fetch_baseline_overview_now", _overview)
    monkeypatch.setattr(baseline_view, "fetch_all_anomalies", lambda limit=300: list(rows))
    monkeypatch.setattr(baseline_view, "format_baseline_overview_text", lambda overview: "overview")
    monkeypatch.setattr(baseline_view, "format_anomaly_evidence_text", lambda row: "evidence")
    prompts = []

    def fake_confirm(parent, *, title, body):
        prompts.append((title, body))
        return confirm

    monkeypatch.setattr(baseline_view, "confirm_action", fake_confirm)
    calls = []
    win = baseline_view.open_baseline_window(
        tk_root, run_command=lambda label, args, flag: calls.append((label, list(args), flag))
    )
    return win, calls, prompts


def _find(win, kind, **match):
    for w in _walk(win):
        if w.winfo_class() != kind:
            continue
        if all(str(w.cget(k)) == v for k, v in match.items()):
            return w
    raise AssertionError(f"no {kind} matching {match}")


def _status_lines(win):
    lines = []
    for w in _walk(win):
        try:
            var = str(w.cget("textvariable"))
        except Exception:  # noqa: BLE001 — widget has no textvariable option
            continue
        if var:
            lines.append(win.getvar(var))
    return lines


def _select_first_row(win, row):
    tree = _find(win, "Treeview")
    tree.selection_set(str(row.id))
    win.update()  # let <<TreeviewSelect>> fire before the button is pressed


def test_mark_known_sends_the_exact_command_and_tells_the_operator(tk_root, monkeypatch):
    row = _anomaly(id=7, known=False)
    win, calls, prompts = _open(tk_root, monkeypatch, [row])
    _select_first_row(win, row)
    mark_btn = _find(win, "Button", text="Mark Known")
    assert str(mark_btn.cget("state")) == "normal"

    mark_btn.invoke()

    assert len(calls) == 1
    label, args, flag = calls[0]
    assert args == ["anomalies", "mark", "7", "known"]
    assert flag is False
    assert "#7" in label
    assert prompts and "KNOWN" in prompts[0][1]
    assert any(line.startswith("Sent — check Console") for line in _status_lines(win))


def test_mark_unknown_on_a_known_row_sends_unknown(tk_root, monkeypatch):
    row = _anomaly(id=9, known=True)
    win, calls, _prompts = _open(tk_root, monkeypatch, [row])
    _select_first_row(win, row)

    _find(win, "Button", text="Mark Unknown").invoke()

    assert [c[1] for c in calls] == [["anomalies", "mark", "9", "unknown"]]


def test_cancelling_the_confirmation_sends_nothing(tk_root, monkeypatch):
    row = _anomaly(id=7, known=False)
    win, calls, prompts = _open(tk_root, monkeypatch, [row], confirm=False)
    _select_first_row(win, row)

    _find(win, "Button", text="Mark Known").invoke()

    assert prompts, "the operator must be asked before anything is sent"
    assert calls == []
    assert not any(line.startswith("Sent") for line in _status_lines(win))
