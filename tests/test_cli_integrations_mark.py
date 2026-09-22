"""
Tests for the four `secure integrations {osquery,yarax,sigma,suricata}
mark-alert` handlers in secure/cli/integrations.py, and for the two
storage functions they are the only production callers of:
`find_integration_alert_by_id()` and `set_integration_alert_known()`
(secure/storage/models/integrations.py:310,319).

Why this file exists (J-0264). Both storage functions had zero
occurrences anywhere under tests/ at 993a249, and so did all four
handler names — the write-back path for every integration alert was
unexecuted by the suite. Two counterfactuals at 993a249, with
__pycache__ cleared and a 300-passed control on both sides:

  * `set_integration_alert_known()` made an unconditional no-op
    (`return` before the UPDATE) — 300 passed, unchanged.
  * all four `_record_alert_review_change(` call sites renamed to an
    undefined name, so executing any of them raises NameError —
    300 passed, unchanged.

The second mutant is the sharper one: it cannot be survived by a test
that merely reaches the line, only by a test that never runs it at all.
So `secure integrations yarax mark-alert 3 known` could print
"Marked #3 (...) as known." and change nothing in the database, and
nothing in this suite would have noticed — a failure reporting success,
which SECURITY_INVARIANTS.md invariant 5 forbids.

The audit trail matters on its own. `_record_alert_review_change()`
writes Product Phase 13's append-only review history into the `events`
table; an alert silently flipping known without that row means the
record of who decided what is simply absent.

tests/test_cli_alert_history.py's docstring says it covers "each
`cmd_*_mark_alert` handler". It covers two of the twenty-three `*_mark*`
handlers under secure/cli/ (cmd_arpwatch_mark, cmd_correlate_mark_alert);
these four were never among them.

Named test_cli_integrations_mark.py so targeted_test_files() keeps it in
the TARGETED tier for secure/cli/integrations.py, which it maps to the
tests/test_cli*.py glob — verified by calling that function, not by
reading the rule.

Run with:  pytest tests/test_cli_integrations_mark.py
"""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path

import pytest

from secure import cli
from secure.cli import integrations as cli_integrations
from secure.config import load_config
from secure.storage.database import Database
from secure.storage.models import (
    add_integration_alert,
    find_integration_alert_by_id,
    list_events,
)

# One case per integration that owns a mark-alert handler. The
# not-found text is asserted verbatim because it is the operator's only
# instruction for recovering from a bad id.
CASES = [
    pytest.param(
        cli_integrations.cmd_integrations_osquery_mark_alert,
        "osquery",
        "No osquery alert found with id",
        "secure integrations osquery alerts",
        id="osquery",
    ),
    pytest.param(
        cli_integrations.cmd_integrations_yarax_mark_alert,
        "yarax",
        "No YARA-X finding found with id",
        "secure integrations yarax alerts",
        id="yarax",
    ),
    pytest.param(
        cli_integrations.cmd_integrations_sigma_mark_alert,
        "sigma",
        "No Sigma match found with id",
        "secure integrations sigma alerts",
        id="sigma",
    ),
    pytest.param(
        cli_integrations.cmd_integrations_suricata_mark_alert,
        "suricata",
        "No Suricata alert found with id",
        "secure integrations suricata alerts",
        id="suricata",
    ),
]


def _bootstrap_to_tmp(monkeypatch, tmp_path: Path):
    """Point secure.cli's _bootstrap() at an isolated temp app_dir.

    secure/cli/integrations.py does `from secure.cli import _bootstrap`,
    which binds the function object into its own namespace — but
    _bootstrap() resolves `load_config` from secure/cli/__init__.py's
    globals at call time, so patching it there does reach these
    handlers. That distinction is the one tests/test_diagnostics.py got
    wrong for secure/diagnostics/hardware.py (J-0181), so it is checked
    here rather than assumed: every test below asserts on database state
    written under tmp_path, which cannot happen if the real
    ~/.secure config were being used.
    """
    monkeypatch.setattr(cli, "load_config", lambda: load_config(app_dir=tmp_path))
    return load_config(app_dir=tmp_path)


def _run(fn, **kwargs):
    """Call a handler with argparse's real argument types. The parsers
    declare `alert_id` as type=int (secure/cli/__init__.py:1233), so an
    int is what a handler actually receives."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(argparse.Namespace(**kwargs))
    return rc, buf.getvalue()


def _seed_alert(cfg, integration: str, *, label: str = "com.example.agent") -> int:
    """Insert one unreviewed (known=0) integration alert and return its id."""
    with Database(cfg.database_path()) as db:
        return add_integration_alert(
            db.conn,
            run_id="run-mark-test",
            integration=integration,
            kind="launch_agent",
            discrepancy="native_only",
            severity="high",
            identity_key="key-1",
            label=label,
            message="A long alert message that must not be copied into the events table.",
        )


def _read_alert(cfg, alert_id: int):
    with Database(cfg.database_path()) as db:
        return find_integration_alert_by_id(db.conn, alert_id)


def _read_events(cfg):
    with Database(cfg.database_path()) as db:
        return list_events(db.conn)


# ---------- the write actually reaches the database ----------


@pytest.mark.parametrize("handler,integration,_notfound,_hint", CASES)
def test_mark_known_persists_the_known_flag(
    handler, integration, _notfound, _hint, tmp_path: Path, monkeypatch
):
    """Kills the `set_integration_alert_known` no-op mutant: the handler
    reports success, so the row must actually have changed."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    alert_id = _seed_alert(cfg, integration)
    assert _read_alert(cfg, alert_id).known is False

    rc, stdout = _run(handler, alert_id=alert_id, status="known")

    assert rc == 0
    assert f"Marked #{alert_id}" in stdout
    assert "as known." in stdout
    assert _read_alert(cfg, alert_id).known is True


@pytest.mark.parametrize("handler,integration,_notfound,_hint", CASES)
def test_mark_unknown_persists_the_cleared_flag(
    handler, integration, _notfound, _hint, tmp_path: Path, monkeypatch
):
    """The reverse direction, so a mutant hard-coding `known = 1` is
    caught as well as one that writes nothing."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    alert_id = _seed_alert(cfg, integration)
    _run(handler, alert_id=alert_id, status="known")
    assert _read_alert(cfg, alert_id).known is True

    rc, stdout = _run(handler, alert_id=alert_id, status="unknown")

    assert rc == 0
    assert "as unknown." in stdout
    assert _read_alert(cfg, alert_id).known is False


# ---------- the review-state history is written ----------


@pytest.mark.parametrize("handler,integration,_notfound,_hint", CASES)
def test_mark_known_records_the_review_transition(
    handler, integration, _notfound, _hint, tmp_path: Path, monkeypatch
):
    """Kills the `_record_alert_review_change` mutant. Asserts the
    transition's direction and subject, not merely that some event
    exists, so a recorder that logged the wrong direction still fails."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    alert_id = _seed_alert(cfg, integration, label="com.example.agent")

    _run(handler, alert_id=alert_id, status="known")

    events = [e for e in _read_events(cfg) if e.category == "alert_review_change"]
    assert len(events) == 1
    assert f"integration_alerts alert #{alert_id}" in events[0].message
    assert "UNKNOWN -> KNOWN" in events[0].message
    assert "com.example.agent" in events[0].message
    assert "severity=high" in events[0].message


@pytest.mark.parametrize("handler,integration,_notfound,_hint", CASES)
def test_mark_unknown_records_the_reverse_transition(
    handler, integration, _notfound, _hint, tmp_path: Path, monkeypatch
):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    alert_id = _seed_alert(cfg, integration)
    _run(handler, alert_id=alert_id, status="known")

    _run(handler, alert_id=alert_id, status="unknown")

    # list_events() returns newest first (events.py:38), so this counts
    # each direction rather than indexing an end and depending on that.
    messages = [
        e.message for e in _read_events(cfg) if e.category == "alert_review_change"
    ]
    assert len(messages) == 2
    assert sum("UNKNOWN -> KNOWN" in m for m in messages) == 1
    assert sum("KNOWN -> UNKNOWN" in m for m in messages) == 1


@pytest.mark.parametrize("handler,integration,_notfound,_hint", CASES)
def test_history_stores_the_subject_not_the_full_alert_message(
    handler, integration, _notfound, _hint, tmp_path: Path, monkeypatch
):
    """Phase 13's stated reason for taking a `subject` rather than a
    message: re-marking must not pile up duplicated long text."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    alert_id = _seed_alert(cfg, integration)

    _run(handler, alert_id=alert_id, status="known")

    events = [e for e in _read_events(cfg) if e.category == "alert_review_change"]
    assert "A long alert message" not in events[0].message


@pytest.mark.parametrize("handler,integration,_notfound,_hint", CASES)
def test_re_marking_the_same_status_writes_no_second_history_row(
    handler, integration, _notfound, _hint, tmp_path: Path, monkeypatch
):
    """The `if alert.known != known` guard. A no-op re-mark still exits
    0 and still reports success — it just must not invent a transition
    that never happened."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    alert_id = _seed_alert(cfg, integration)

    _run(handler, alert_id=alert_id, status="known")
    rc, stdout = _run(handler, alert_id=alert_id, status="known")

    assert rc == 0
    assert "as known." in stdout
    events = [e for e in _read_events(cfg) if e.category == "alert_review_change"]
    assert len(events) == 1
    assert _read_alert(cfg, alert_id).known is True


# ---------- the not-found path ----------


@pytest.mark.parametrize("handler,integration,notfound,hint", CASES)
def test_unknown_alert_id_exits_1_and_writes_nothing(
    handler, integration, notfound, hint, tmp_path: Path, monkeypatch
):
    """A mark against an id that does not exist must not report success.
    Exercises find_integration_alert_by_id()'s None branch, which no
    test reached before this file."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    real_id = _seed_alert(cfg, integration)

    rc, stdout = _run(handler, alert_id=real_id + 999, status="known")

    assert rc == 1
    assert notfound in stdout
    assert hint in stdout
    assert "Marked #" not in stdout
    assert _read_events(cfg) == []
    assert _read_alert(cfg, real_id).known is False


@pytest.mark.parametrize("handler,integration,_notfound,_hint", CASES)
def test_marking_one_alert_leaves_its_siblings_untouched(
    handler, integration, _notfound, _hint, tmp_path: Path, monkeypatch
):
    """set_integration_alert_known()'s UPDATE is bounded by `WHERE id =
    ?`. A mutant dropping that clause marks every alert in the table at
    once, which no other test would see."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    first = _seed_alert(cfg, integration, label="first")
    second = _seed_alert(cfg, integration, label="second")

    _run(handler, alert_id=first, status="known")

    assert _read_alert(cfg, first).known is True
    assert _read_alert(cfg, second).known is False


# ---------- one integration cannot mark another's alert ----------


@pytest.mark.parametrize("handler,integration,_notfound,_hint", CASES)
def test_marking_another_integrations_alert_is_refused(
    handler, integration, _notfound, _hint, tmp_path: Path, monkeypatch
):
    """The alert id is looked up alone, so `osquery mark-alert <id>` used
    to mark a Sigma alert just as well. Marking known removes an alert
    from review, so the wrong handler must refuse (exit 2, the error code
    of the integrations CLI) and leave the alert and its history alone."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    other = next(name for name in ("osquery", "yarax", "sigma", "suricata") if name != integration)
    foreign_id = _seed_alert(cfg, other)

    rc, stdout = _run(handler, alert_id=foreign_id, status="known")

    assert rc == 2
    assert f"belongs to {other}" in stdout
    assert f"secure integrations {other} mark-alert {foreign_id}" in stdout
    assert "Marked #" not in stdout
    assert _read_alert(cfg, foreign_id).known is False
    assert _read_events(cfg) == []
