"""
Tests for secure_gui/view_models.py: the Tk-free decisions extracted from
request that baseline_view and alerts_view build before dispatching.

The expected strings are the ones each view built inline before the
extraction, so a passing run means the operator sees and sends exactly
what they did before.

Run with:  pytest tests/test_gui_view_models.py
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from secure_gui.data_access import ALERT_MARK_COMMANDS, AnomalyRow

_MODULE = Path(__file__).resolve().parent.parent / "secure_gui" / "view_models.py"


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


def _alert(*, known: bool = False, command=ALERT_MARK_COMMANDS["arp_alerts"]):
    # Only the fields the mark request reads; AlertRow itself also needs
    # a full Explanation, which has nothing to do with marking.
    return SimpleNamespace(module="arpwatch", source_id=42, known=known, mark_command=command)


# ---------- anomaly_mark_request ----------


def test_anomaly_mark_request_for_an_unreviewed_row_marks_it_known():
    from secure_gui.view_models import anomaly_mark_request

    req = anomaly_mark_request(_anomaly(id=7, known=False))

    assert req.new_status == "known"
    assert req.args == ("anomalies", "mark", "7", "known")
    assert req.confirm_title == "Mark anomaly"
    assert req.confirm_body == (
        "Mark anomaly #7 (process//usr/bin/curl, signing_status) as KNOWN?"
    )
    assert req.label == "Mark Anomaly Known/Unknown… (#7, via Baseline & Anomalies table)"


def test_anomaly_mark_request_for_a_known_row_marks_it_unknown():
    from secure_gui.view_models import anomaly_mark_request

    req = anomaly_mark_request(_anomaly(id=9, known=True))

    assert req.new_status == "unknown"
    assert req.args == ("anomalies", "mark", "9", "unknown")
    assert req.confirm_body.endswith("as UNKNOWN?")


# ---------- alert_mark_request ----------


def test_alert_mark_request_uses_the_rows_own_command_and_source_id():
    from secure_gui.view_models import alert_mark_request

    req = alert_mark_request(_alert(known=False))

    assert req.new_status == "known"
    assert req.args == ("arpwatch", "mark", "42", "known")
    assert req.confirm_title == "Mark alert"
    assert req.confirm_body == "Mark this arpwatch alert as KNOWN?"
    assert req.label == "Mark Alert Known/Unknown… (arpwatch, via Alerts table)"


def test_alert_mark_request_for_a_known_alert_marks_it_unknown():
    from secure_gui.view_models import alert_mark_request

    req = alert_mark_request(_alert(known=True))

    assert req.args[-1] == "unknown"
    assert req.confirm_body == "Mark this arpwatch alert as UNKNOWN?"


def test_alert_mark_request_is_none_when_the_source_has_no_mark_command():
    from secure_gui.view_models import alert_mark_request

    assert alert_mark_request(_alert(command=None)) is None


# ---------- purity guard ----------


def test_view_models_imports_no_tk_storage_or_subprocess():
    # The point of view_models is that every decision in it can be tested
    # without a display, a database or a child process.
    forbidden = ("tkinter", "_tkinter", "secure.storage", "subprocess", "sqlite3", "os")
    imported = set()
    for node in ast.walk(ast.parse(_MODULE.read_text())):
        if isinstance(node, ast.Import):
            imported |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    bad = sorted(m for m in imported for f in forbidden if m == f or m.startswith(f + "."))
    assert bad == []


def test_view_models_imports_with_tkinter_unavailable():
    code = (
        "import sys; sys.modules['tkinter'] = None; sys.modules['_tkinter'] = None; "
        "import secure_gui.view_models"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], cwd=str(_MODULE.parent.parent),
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr


# ---------- cr_approve_request (Change Request Center) ----------


def _cr_view(*, run_id=None):
    return SimpleNamespace(
        cr_id="CR-3", run_id=run_id, revision_hash="abc123", classification="safe", title="Fix widget",
    )


def test_center_approve_of_an_agent_request_goes_through_the_revalidation_gate():
    from secure_gui.view_models import cr_approve_request

    req = cr_approve_request(_cr_view(run_id="AR-2"))

    # Same route agent_view uses: `secure agent approve <run_id>` re-checks
    # the worktree diff before approving (orchestrator.revalidate_before_approval).
    assert req.args == ("agent", "approve", "AR-2", "--cr-id", "CR-3")
    assert req.label == "Approve Agent Repair Change Request (CR-3)"
    assert req.confirm_title == "Approve change request"
    assert "CR-3" in req.confirm_body and "AR-2" in req.confirm_body
    assert "re-check" in req.confirm_body and "supersede" in req.confirm_body


def test_center_approve_of_a_non_agent_request_approves_that_exact_revision():
    from secure_gui.view_models import cr_approve_request

    req = cr_approve_request(_cr_view(run_id=None))

    assert req.args == ("ai", "changes", "approve", "CR-3", "abc123")
    assert req.label == "secure ai changes approve CR-3 abc123"
    assert "abc123" in req.confirm_body
    # No revalidation runs on this path, so the dialog must not promise one.
    assert "supersede" not in req.confirm_body
    assert "refused" in req.confirm_body


def test_agent_approve_args_bind_the_approval_to_the_change_request_shown():
    # `agent approve <run_id>` alone approves whatever request the run links
    # to at click time, which after a drift is a replacement the operator
    # never saw. --cr-id makes the CLI refuse unless it is still this one.
    from secure_gui.view_models import agent_approve_args

    assert agent_approve_args("AR-2", "CR-3") == ("agent", "approve", "AR-2", "--cr-id", "CR-3")
