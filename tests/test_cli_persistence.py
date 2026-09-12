"""
Tests for `secure/cli/persistence.py` — the seven `cmd_persistence_*`
command handlers.

Why this file exists: before it, **no test in this repository executed
any of those seven handlers.** That is not a grep result, it is a
measurement. Every one of the seven was given a crashing first
statement (a call to an undefined `_NEVER_RUN_MARKER_UNDEFINED()`, which
a positive control confirmed does raise `NameError` when reached) and
the full suite was then run at `a24422d`: the four known pre-existing
baseline failures and nothing else. A mutant that crashes on entry and
kills no test proves the body is never reached, which is a stronger
claim than "unasserted" — see tests/test_cli_integrations_mark.py, which
established the same technique for `secure/cli/integrations.py`.

What that left uncovered, and what each test below pins:

  * **The honest-failure exit code.** `cmd_persistence_scan` returns 1
    when `ps` could not be run, so "the scan could not see the
    processes" is never reported to a caller as the clean 0 that means
    "the scan saw the processes and they were fine" (AGENTS.md rule 7,
    SECURITY_INVARIANTS.md invariant 5). `secure/validate/scenarios/
    persistence.py:201` asserts the scanner *reports* the flag;
    nothing asserted the CLI *acts* on it. The clean-scan test below
    is the required positive control: without it, "returns 1 when ps
    is unavailable" is equally satisfied by a handler that always
    returns 1.

  * **The deliberate asymmetry between the two availability flags.**
    `login_items_available=False` is announced on stdout but does NOT
    change the exit code, because LaunchAgent/LaunchDaemon scanning
    still ran (PROJECT_NOTES.md: "`login_items_available = False`
    doesn't block LaunchAgent/LaunchDaemon scanning from still
    running"). That is a partial degradation, not a blind scan, and it
    is pinned here so that flipping either flag's exit-code treatment
    becomes a test failure rather than a silent change of what an exit
    code means.

  * **The alert-review audit trail.**
    `tests/test_cli_alert_history.py`'s docstring claims coverage of
    "each `cmd_*_mark_alert` handler"; it end-to-ends two of them
    (`cmd_arpwatch_mark`, `cmd_correlate_mark_alert`).
    `cmd_persistence_mark_alert` was not one, so its
    `_record_alert_review_change()` call site — the append-only record
    of a human changing an alert's review state — had never run. Its
    three cases are pinned below: a real transition writes exactly one
    event, a no-op re-mark writes none, and an alert that does not
    exist writes none and exits 1.

  * **That marking a process or a persistence *entry* writes no alert
    history.** Only the alert handler logs to the trail; the other two
    mark handlers deliberately do not (Product Phase 13 added
    `_record_alert_review_change()` to the seven *alert* sources).
    Asserted explicitly so the absence stays a decision.

The `scan_persistence` seam: `secure/cli/persistence.py` does
`from secure.persistence import scan_persistence` at import time, so it
holds its own reference and patching `secure.persistence.scan_persistence`
would miss it entirely and run the real `ps` against this machine. These
tests patch the name on `secure.cli.persistence` and each one asserts the
fake was actually called, so a wrong seam fails loudly instead of quietly
scanning the host.

Run with:  pytest tests/test_cli_persistence.py
"""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path

from secure import cli
from secure.cli import persistence as cli_persistence
from secure.config import load_config
from secure.persistence.scanner import PersistenceAlert, PersistenceScanResult
from secure.storage.database import Database
from secure.storage.models import (
    add_persistence_alert,
    count_events,
    find_persistence_alert_by_id,
    find_persistence_entry_by_id,
    find_process_entry_by_id,
    list_events,
    set_persistence_entry_known,
    set_process_entry_known,
    upsert_persistence_entry,
    upsert_process_entry,
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


def _patch_scan(monkeypatch, result: PersistenceScanResult) -> list:
    """Replace the reference `secure/cli/persistence.py` actually calls.
    Returns a call log the test asserts on, so patching the wrong seam
    (and silently running the real `ps`) cannot pass."""
    assert hasattr(cli_persistence, "scan_persistence"), (
        "secure/cli/persistence.py no longer binds scan_persistence at import; "
        "this test patches the wrong seam"
    )
    calls: list = []

    def fake_scan_persistence(conn):
        calls.append(conn)
        return result

    monkeypatch.setattr(cli_persistence, "scan_persistence", fake_scan_persistence)
    return calls


def _result(**kwargs) -> PersistenceScanResult:
    return PersistenceScanResult(
        scanned_at="2026-09-12T00:00:00+00:00", run_id="run1", **kwargs
    )


# ---------- cmd_persistence_scan: the honest-failure exit code ----------


def test_scan_exits_one_when_ps_could_not_run(tmp_path: Path, monkeypatch):
    """A scan that could not see the processes must not report the exit
    code that means "saw them, all clean" (AGENTS.md rule 7)."""
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    calls = _patch_scan(monkeypatch, _result(processes_available=False, process_count=0))

    rc, stdout = _run(cli_persistence.cmd_persistence_scan, argparse.Namespace())

    assert calls, "the patched scan_persistence was never called"
    assert rc == 1
    assert "Could not run `ps`" in stdout
    assert "No process data was recorded this scan." in stdout
    # The count line would be the "0 processes, all clean" report the
    # flag exists to prevent, so it must be suppressed entirely.
    assert "Processes with a resolvable executable path" not in stdout
    # Deliberately NOT asserted either way: the handler still reaches
    # its `else: print("No new processes detected.")` branch on a scan
    # that could not see any processes, so the report states an
    # affirmative negative two lines below announcing that no process
    # data exists. The exit code and the first two lines are honest, so
    # this is a wording defect rather than a false clean, and changing
    # operator-facing report text is a decision for a human — it is
    # registered as a job rather than fixed or blessed here.


def test_scan_exits_zero_on_a_clean_scan_that_really_ran(tmp_path: Path, monkeypatch):
    """Positive control for the test above: with both sensors available
    and nothing new, the exit code is 0. Without this, "returns 1 when
    ps is unavailable" is also satisfied by always returning 1."""
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    calls = _patch_scan(monkeypatch, _result(process_count=42))

    rc, stdout = _run(cli_persistence.cmd_persistence_scan, argparse.Namespace())

    assert calls
    assert rc == 0
    assert "Processes with a resolvable executable path: 42" in stdout
    assert "No new processes detected." in stdout
    assert "No new persistence entries detected." in stdout
    assert "Could not run `ps`" not in stdout


def test_scan_exits_one_when_a_new_process_is_found(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        record, _ = upsert_process_entry(db.conn, "/tmp/x", "x", "root", "unsigned")
    calls = _patch_scan(monkeypatch, _result(process_count=1, new_processes=[record]))

    rc, stdout = _run(cli_persistence.cmd_persistence_scan, argparse.Namespace())

    assert calls
    assert rc == 1
    assert "NEW PROCESSES DETECTED (1):" in stdout
    assert "/tmp/x" in stdout
    assert "secure persistence mark-process <id> known|unknown" in stdout


def test_scan_exits_one_when_a_new_persistence_entry_is_found(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        record, _, _ = upsert_persistence_entry(
            db.conn, "launch_agent", "/tmp/a.plist", "com.example.a", "/tmp/a", "unsigned"
        )
    calls = _patch_scan(monkeypatch, _result(new_persistence_entries=[record]))

    rc, stdout = _run(cli_persistence.cmd_persistence_scan, argparse.Namespace())

    assert calls
    assert rc == 1
    assert "NEW PERSISTENCE ENTRIES DETECTED (1):" in stdout
    assert "com.example.a" in stdout
    assert "secure persistence mark-item <id> known|unknown" in stdout


def test_scan_exits_one_when_an_alert_is_raised(tmp_path: Path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    alert = PersistenceAlert(
        kind="signing_changed", severity="high", target_type="launch_agent",
        identifier="com.example.a", label="Example", message="signing status changed", id=3,
    )
    calls = _patch_scan(monkeypatch, _result(alerts=[alert]))

    rc, stdout = _run(cli_persistence.cmd_persistence_scan, argparse.Namespace())

    assert calls
    assert rc == 1
    assert "ALERTS (1):" in stdout
    assert "#3 [HIGH] signing_changed (launch_agent) — Example" in stdout
    assert "signing status changed" in stdout


def test_scan_announces_unavailable_login_items_without_changing_the_exit_code(
    tmp_path: Path, monkeypatch
):
    """The two availability flags are deliberately not symmetric.
    `ps` failing blinds the process half of the scan entirely, so it
    exits 1. `osascript` failing costs only the classic login items —
    LaunchAgents and LaunchDaemons were still scanned — so the
    degradation is reported on stdout and the exit code stays 0. This
    pins which flag does what, so changing either becomes a failure
    here rather than a silent change of meaning for an exit code."""
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    calls = _patch_scan(monkeypatch, _result(login_items_available=False, process_count=7))

    rc, stdout = _run(cli_persistence.cmd_persistence_scan, argparse.Namespace())

    assert calls
    assert rc == 0
    assert "Could not read classic login items" in stdout
    assert "LaunchAgents/LaunchDaemons were still scanned normally." in stdout
    assert "Processes with a resolvable executable path: 7" in stdout


def test_scan_unavailable_ps_outranks_new_findings_for_the_exit_code(
    tmp_path: Path, monkeypatch
):
    """Both conditions return 1, so neither can mask the other — but
    the unavailable branch is checked first, and the unavailability is
    still reported even when there is also something to review."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        record, _, _ = upsert_persistence_entry(
            db.conn, "launch_daemon", "/tmp/b.plist", "com.example.b", "/tmp/b", "unsigned"
        )
    calls = _patch_scan(
        monkeypatch, _result(processes_available=False, new_persistence_entries=[record])
    )

    rc, stdout = _run(cli_persistence.cmd_persistence_scan, argparse.Namespace())

    assert calls
    assert rc == 1
    assert "Could not run `ps`" in stdout
    assert "NEW PERSISTENCE ENTRIES DETECTED (1):" in stdout


# ---------- cmd_persistence_mark_alert: the audit trail ----------


def test_mark_alert_records_exactly_one_review_transition(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_persistence_alert(
            db.conn, "run1", "signing_changed", "high", "launch_agent",
            "com.example.a", "Example", "The executable behind 'Example' changed signing.",
        )

    rc, stdout = _run(
        cli_persistence.cmd_persistence_mark_alert,
        argparse.Namespace(alert_id=1, status="known"),
    )
    assert rc == 0
    assert "Marked #1 (signing_changed, Example) as known." in stdout

    with Database(cfg.database_path()) as db:
        assert find_persistence_alert_by_id(db.conn, 1).known is True
        review = [e for e in list_events(db.conn) if e.category == "alert_review_change"]

    assert len(review) == 1
    assert "persistence_alerts alert #1" in review[0].message
    assert "Example" in review[0].message
    assert "severity=high" in review[0].message
    assert "UNKNOWN -> KNOWN" in review[0].message
    # Only the concise subject is stored, never the alert's full text.
    assert "The executable behind" not in review[0].message


def test_mark_alert_both_directions_are_recorded(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_persistence_alert(
            db.conn, "run1", "new_persistence_entry", "medium", "login_item",
            "com.example.c", None, "A new login item appeared.",
        )

    cli_persistence.cmd_persistence_mark_alert(argparse.Namespace(alert_id=1, status="known"))
    rc = cli_persistence.cmd_persistence_mark_alert(
        argparse.Namespace(alert_id=1, status="unknown")
    )
    assert rc == 0

    with Database(cfg.database_path()) as db:
        review = [e for e in list_events(db.conn) if e.category == "alert_review_change"]

    assert len(review) == 2
    # list_events orders id DESC, so the newest transition comes first.
    assert "KNOWN -> UNKNOWN" in review[0].message
    assert "UNKNOWN -> KNOWN" in review[1].message
    # No label, so the identifier is the subject.
    assert "com.example.c" in review[0].message


def test_mark_alert_no_op_remark_writes_no_history(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_persistence_alert(
            db.conn, "run1", "signing_changed", "high", "launch_agent",
            "com.example.a", "Example", "changed",
        )

    cli_persistence.cmd_persistence_mark_alert(argparse.Namespace(alert_id=1, status="known"))
    rc = cli_persistence.cmd_persistence_mark_alert(
        argparse.Namespace(alert_id=1, status="known")
    )
    assert rc == 0

    with Database(cfg.database_path()) as db:
        review = [e for e in list_events(db.conn) if e.category == "alert_review_change"]

    assert len(review) == 1  # the real transition only, not the re-mark


def test_mark_alert_missing_id_exits_one_and_writes_no_history(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()):
        pass  # create the schema, leave it empty

    rc, stdout = _run(
        cli_persistence.cmd_persistence_mark_alert,
        argparse.Namespace(alert_id=999, status="known"),
    )
    assert rc == 1
    assert "No persistence alert found with id 999" in stdout
    assert "secure persistence alerts" in stdout  # tells the operator what to run

    with Database(cfg.database_path()) as db:
        assert count_events(db.conn) == 0


# ---------- cmd_persistence_mark_process / mark_item ----------


def test_mark_process_flips_known_and_writes_no_alert_history(tmp_path: Path, monkeypatch):
    """Marking a process is not marking an alert: Product Phase 13's
    review trail covers the seven alert sources, and this handler
    deliberately does not write to it. Asserted so the absence stays a
    decision rather than becoming an unnoticed omission."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        record, _ = upsert_process_entry(db.conn, "/usr/local/bin/thing", "thing", "root", "unsigned")
        assert record.known is False

    rc, stdout = _run(
        cli_persistence.cmd_persistence_mark_process,
        argparse.Namespace(entry_id=record.id, status="known"),
    )
    assert rc == 0
    assert f"Marked #{record.id} (/usr/local/bin/thing) as known." in stdout

    with Database(cfg.database_path()) as db:
        assert find_process_entry_by_id(db.conn, record.id).known is True
        assert count_events(db.conn) == 0


def test_mark_process_unknown_flips_it_back(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        record, _ = upsert_process_entry(db.conn, "/usr/local/bin/thing", "thing", "root", "unsigned")

    cli_persistence.cmd_persistence_mark_process(
        argparse.Namespace(entry_id=record.id, status="known")
    )
    rc = cli_persistence.cmd_persistence_mark_process(
        argparse.Namespace(entry_id=record.id, status="unknown")
    )
    assert rc == 0

    with Database(cfg.database_path()) as db:
        assert find_process_entry_by_id(db.conn, record.id).known is False


def test_mark_process_missing_id_exits_one(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()):
        pass

    rc, stdout = _run(
        cli_persistence.cmd_persistence_mark_process,
        argparse.Namespace(entry_id=999, status="known"),
    )
    assert rc == 1
    assert "No process entry found with id 999" in stdout
    assert "secure persistence processes" in stdout


def test_mark_item_flips_known_and_writes_no_alert_history(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        record, _, _ = upsert_persistence_entry(
            db.conn, "launch_agent", "/tmp/a.plist", "com.example.a", "/tmp/a", "unsigned"
        )
        assert record.known is False

    rc, stdout = _run(
        cli_persistence.cmd_persistence_mark_item,
        argparse.Namespace(entry_id=record.id, status="known"),
    )
    assert rc == 0
    assert f"Marked #{record.id} (com.example.a) as known." in stdout

    with Database(cfg.database_path()) as db:
        assert find_persistence_entry_by_id(db.conn, record.id).known is True
        assert count_events(db.conn) == 0


def test_mark_item_without_a_label_falls_back_to_the_path(tmp_path: Path, monkeypatch):
    """`entry.label or entry.path or "(unknown)"` — the fallback chain
    the listing and the confirmation line share."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        record, _, _ = upsert_persistence_entry(
            db.conn, "launch_daemon", "/tmp/unlabelled.plist", None, "/tmp/u", "unsigned"
        )

    rc, stdout = _run(
        cli_persistence.cmd_persistence_mark_item,
        argparse.Namespace(entry_id=record.id, status="known"),
    )
    assert rc == 0
    assert "/tmp/unlabelled.plist" in stdout


def test_mark_item_missing_id_exits_one(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()):
        pass

    rc, stdout = _run(
        cli_persistence.cmd_persistence_mark_item,
        argparse.Namespace(entry_id=999, status="known"),
    )
    assert rc == 1
    assert "No persistence entry found with id 999" in stdout
    assert "secure persistence items" in stdout


# ---------- the three read-only listings ----------


def test_listings_on_an_empty_database_say_so_and_exit_zero(tmp_path: Path, monkeypatch):
    """Nothing recorded yet is a real, reportable state, not an error —
    each listing names the command that would populate it."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()):
        pass

    for handler, expected in (
        (cli_persistence.cmd_persistence_processes, "No process entries recorded yet."),
        (cli_persistence.cmd_persistence_items, "No persistence entries recorded yet."),
        (cli_persistence.cmd_persistence_alerts, "No persistence alerts recorded yet."),
    ):
        rc, stdout = _run(handler, argparse.Namespace())
        assert rc == 0, handler.__name__
        assert expected in stdout, handler.__name__
        assert "Run `secure persistence scan` first." in stdout, handler.__name__


def test_processes_listing_tags_known_and_unknown(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        known, _ = upsert_process_entry(db.conn, "/bin/known", "known", "root", "signed_apple")
        upsert_process_entry(db.conn, "/bin/unknown", "unknown", "root", None)
        set_process_entry_known(db.conn, known.id, True)

    rc, stdout = _run(cli_persistence.cmd_persistence_processes, argparse.Namespace())

    assert rc == 0
    assert "[KNOWN  ]" in stdout
    assert "[UNKNOWN]" in stdout
    assert "/bin/known" in stdout
    assert "/bin/unknown" in stdout
    # A process whose signing was never computed reads "unknown", never blank.
    assert "signing: unknown" in stdout
    assert "signing: signed_apple" in stdout
    assert "first seen" in stdout and "last seen" in stdout


def test_items_listing_tags_known_and_shows_a_missing_path_as_none(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        pathless, _, _ = upsert_persistence_entry(
            db.conn, "login_item", None, "Pathless Login Item", None, None
        )
        upsert_persistence_entry(
            db.conn, "launch_agent", "/tmp/a.plist", "com.example.a", "/tmp/a", "unsigned"
        )
        set_persistence_entry_known(db.conn, pathless.id, True)

    rc, stdout = _run(cli_persistence.cmd_persistence_items, argparse.Namespace())

    assert rc == 0
    assert "[KNOWN  ]" in stdout
    assert "[UNKNOWN]" in stdout
    assert "Pathless Login Item" in stdout
    assert "path: (none)" in stdout
    assert "path: /tmp/a.plist" in stdout
    assert "signing: unknown" in stdout


def test_alerts_listing_shows_severity_tag_and_message(tmp_path: Path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_persistence_alert(
            db.conn, "run1", "signing_changed", "high", "launch_agent",
            "com.example.a", "Example", "The executable changed signing status.",
        )
        add_persistence_alert(
            db.conn, "run1", "new_persistence_entry", "medium", "login_item",
            "com.example.c", None, "A new login item appeared.",
        )

    rc, stdout = _run(cli_persistence.cmd_persistence_alerts, argparse.Namespace())

    assert rc == 0
    assert "[HIGH  ]" in stdout
    assert "[MEDIUM]" in stdout
    assert "The executable changed signing status." in stdout
    # No label: the identifier stands in, never an empty field.
    assert "com.example.c" in stdout
    assert "[UNKNOWN]" in stdout  # both are unreviewed


def test_alerts_listing_is_read_only(tmp_path: Path, monkeypatch):
    """Listing alerts must not itself count as reviewing them
    (invariant 4: observation is read-only)."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    with Database(cfg.database_path()) as db:
        add_persistence_alert(
            db.conn, "run1", "signing_changed", "high", "launch_agent",
            "com.example.a", "Example", "changed",
        )

    _run(cli_persistence.cmd_persistence_alerts, argparse.Namespace())

    with Database(cfg.database_path()) as db:
        assert find_persistence_alert_by_id(db.conn, 1).known is False
        assert count_events(db.conn) == 0
