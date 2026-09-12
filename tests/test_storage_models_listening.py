"""
Tests for which run last_listening_run_id() returns, in
secure/storage/models/listening.py.

Its one caller is secure/listening/scanner.py:146, which reads it
before the scan writes anything and then hands the result to
_previous_scan_identities() as the baseline that disappeared-service
detection compares against. So "most recent" is the whole contract:
the docstring says "the run_id of the most recent listening scan", and
scanner.py's own comment says it must be read first "or it would just
be this run's own id".

Measured 2026-09-12 at a07b23f: the function is reached, and reached a
lot. A crash marker as its first statement took
tests/test_listening.py, test_listening_provenance.py, test_storage.py,
test_baseline_history_adapters.py, test_correlate.py and
test_integrations_osquery.py from 3 failed / 207 passed to 14 failed /
196 passed — 11 tests execute it. Not one of them asserts which run it
returns: rewriting its `ORDER BY id DESC` to `ORDER BY id ASC` left
that same set at 3 failed / 207 passed, byte-identical to the control.
(The 3 failures in both runs are pre-existing wifi-marker debris, not
this function.)

The reason the mutation is invisible is that no test anywhere performs
three listening scans. With one scan there is no previous run; with
two, the oldest run and the most recent run are the same row, so DESC
and ASC cannot be distinguished. The third scan is the first one that
tells them apart, which is why it is the case tested here.

What a non-latest baseline would cost is not subtle. scanner.py would
compare each scan against an ancient run rather than the preceding
one, so a service that stopped listening would be re-reported in
disappeared_services on every scan from then on — and
secure/cli/listening.py:77 returns exit code 1 whenever
disappeared_services is non-empty, so `secure listening scan` would
exit non-zero forever after any service ever stopped. A permanently
dirty exit status in a security tool is indistinguishable from a real
finding, which is the shape invariant 5 exists to prevent.

Named test_storage_models_listening.py because targeted_test_files()
maps secure/storage/... to tests/test_storage*.py — see
secure/agent/tiers.py:254 and tests/test_agent_tiers.py.

Run with:  pytest tests/test_storage_models_listening.py
"""

from __future__ import annotations

from pathlib import Path

from secure.storage.database import Database
from secure.storage.models import (
    add_listening_events,
    last_listening_run_id,
)

# One socket per run is enough; this is about which run_id comes back,
# not about how many rows a run has.
_ROWS = [("TCP", "*", 22, "network", 99, "sshd")]


def test_last_listening_run_id_is_none_before_any_scan(tmp_path: Path):
    """No events yet means honestly nothing, not a fabricated run id.

    scanner.py turns this into has_previous_scan=False, which is what
    suppresses disappeared-service reporting on a first scan.
    """
    with Database(tmp_path / "test.db") as db:
        assert last_listening_run_id(db.conn) is None


def test_last_listening_run_id_returns_the_most_recent_of_three_runs(tmp_path: Path):
    """Three runs: the answer is the third, not the first.

    This is the assertion the existing suite cannot make. Every test
    that reaches this function performs at most two scans, where the
    oldest run and the newest run are the same row.
    """
    with Database(tmp_path / "test.db") as db:
        add_listening_events(db.conn, run_id="run-1", rows=_ROWS)
        add_listening_events(db.conn, run_id="run-2", rows=_ROWS)
        add_listening_events(db.conn, run_id="run-3", rows=_ROWS)

        assert last_listening_run_id(db.conn) == "run-3"


def test_last_listening_run_id_tracks_the_latest_run_as_scans_accumulate(tmp_path: Path):
    """Read after every insert: the answer moves forward each time.

    Pins the direction rather than a single endpoint, so a change that
    froze the result at any one run — the first, or whichever happened
    to be latest when the test was written — fails here instead of
    passing by coincidence.
    """
    with Database(tmp_path / "test.db") as db:
        seen = []
        for run_id in ("run-1", "run-2", "run-3", "run-4"):
            add_listening_events(db.conn, run_id=run_id, rows=_ROWS)
            seen.append(last_listening_run_id(db.conn))

        assert seen == ["run-1", "run-2", "run-3", "run-4"]


def test_last_listening_run_id_ignores_run_id_string_order(tmp_path: Path):
    """Insertion order decides, not how the run_id sorts as text.

    Real run ids are uuid4 hex slices (scanner.py:143), so they carry
    no ordering at all; anything that sorted on the run_id column
    instead of on id would pass the ascending-name tests above and
    still be wrong. "run-9" is inserted before "run-10" here, so text
    order and insertion order disagree.
    """
    with Database(tmp_path / "test.db") as db:
        add_listening_events(db.conn, run_id="run-9", rows=_ROWS)
        add_listening_events(db.conn, run_id="run-10", rows=_ROWS)

        assert last_listening_run_id(db.conn) == "run-10"
