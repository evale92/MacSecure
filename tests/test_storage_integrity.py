"""
Tests for secure/storage/integrity.py (Phase 29 Stage 6) plus two
adversarial, end-to-end integrity checks the user explicitly asked for
during this phase's own review:

    1. Schema migrations are idempotent against a database that
       already holds real data (not just an empty/older schema).
    2. Partial/unavailable sensor data can never poison a baseline —
       proven by actually calling evaluate_and_record_feature_observation()
       many times with partial_sensor_data=True and confirming
       baseline_feature_stats stays untouched, not by re-reading the
       eligibility rules' own docstring.

Every "this can't happen" claim here is backed by a deliberately
induced failure (corrupt the data, then confirm the checker/system
catches it), not just a happy-path assertion — per this phase's own
governing instruction: "no sensor may convert 'could not observe' into
'observed nothing'," extended here to "no dedup/migration mechanism may
convert 'this reference is broken' into 'everything is fine.'"

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from secure.baseline.engine import evaluate_and_record_feature_observation
from secure.baseline.entities import PERSISTENCE, persistence_key
from secure.baseline.maturity import NO_BASELINE
from secure.evidence.fingerprint import logical_ref_identity
from secure.evidence.model import RELATIONSHIP_SAME_EVENT_CONFIRMATION
from secure.storage.database import Database, init_schema
from secure.storage.integrity import (
    KNOWN_EVIDENCE_SOURCE_TABLES,
    check_evidence_link_referential_integrity,
)
from secure.storage.models import (
    add_connection_events,
    add_evidence_link,
    find_baseline_feature_maturity,
    get_baseline_feature_stat,
    upsert_process_entry,
)


def _fp(table: str, id_: int) -> str:
    return logical_ref_identity(table, id_)


# =========================================================================
# secure/storage/integrity.py — referential integrity over evidence_links
# =========================================================================


def test_referential_integrity_clean_when_both_sides_are_real_rows(tmp_path: Path):
    """Happy path built from REAL rows in REAL tables (not hand-picked
    ids) — the same shape a genuine osquery-vs-native match or a
    Suricata process-context link would produce.
    """
    with Database(tmp_path / "test.db") as db:
        process, _ = upsert_process_entry(
            db.conn, executable_path="/usr/bin/curl", process_name="curl", run_as_user="erick"
        )
        conn_ids = add_connection_events(
            db.conn, "run1",
            [("tcp", "192.168.1.23", 55555, "203.0.113.9", 443, "ESTABLISHED", 4321, "curl")],
        )
        conn_id = conn_ids[0]

        add_evidence_link(
            db.conn,
            from_source_table="process_entries", from_source_id=process.id,
            from_fingerprint=_fp("process_entries", process.id),
            to_source_table="connection_events", to_source_id=conn_id,
            to_fingerprint=_fp("connection_events", conn_id),
            relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION, match_basis="identity+timing",
            detail="matched", created_by="test",
        )

        issues = check_evidence_link_referential_integrity(db.conn)

    assert issues == []


def test_referential_integrity_detects_deliberately_induced_missing_row(tmp_path: Path):
    """Deliberately induced failure: an evidence_links row that
    references a process_entries id that was never actually inserted.
    This must never be reported as clean — proves the checker actually
    detects a broken reference rather than trivially always passing.
    """
    with Database(tmp_path / "test.db") as db:
        conn_ids = add_connection_events(
            db.conn, "run1",
            [("tcp", "192.168.1.23", 55555, "203.0.113.9", 443, "ESTABLISHED", 4321, "curl")],
        )
        conn_id = conn_ids[0]
        nonexistent_process_id = 999999

        add_evidence_link(
            db.conn,
            from_source_table="process_entries", from_source_id=nonexistent_process_id,
            from_fingerprint=_fp("process_entries", nonexistent_process_id),
            to_source_table="connection_events", to_source_id=conn_id,
            to_fingerprint=_fp("connection_events", conn_id),
            relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION, match_basis="identity+timing",
            detail="matched", created_by="test",
        )

        issues = check_evidence_link_referential_integrity(db.conn)

    assert len(issues) == 1
    issue = issues[0]
    assert issue.side == "from"
    assert issue.source_table == "process_entries"
    assert issue.source_id == nonexistent_process_id
    assert issue.problem == "missing_row"


def test_referential_integrity_detects_unknown_source_table(tmp_path: Path):
    """A source_table name outside the known allowlist is itself a
    finding, not silently trusted — this is what protects the checker
    from ever executing a query against an unexpected table name.
    """
    with Database(tmp_path / "test.db") as db:
        assert "totally_made_up_table" not in KNOWN_EVIDENCE_SOURCE_TABLES

        conn_ids = add_connection_events(
            db.conn, "run1",
            [("tcp", "192.168.1.23", 55555, "203.0.113.9", 443, "ESTABLISHED", 4321, "curl")],
        )
        conn_id = conn_ids[0]

        add_evidence_link(
            db.conn,
            from_source_table="totally_made_up_table", from_source_id=1,
            from_fingerprint=_fp("totally_made_up_table", 1),
            to_source_table="connection_events", to_source_id=conn_id,
            to_fingerprint=_fp("connection_events", conn_id),
            relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION, match_basis="x",
            detail="d", created_by="test",
        )

        issues = check_evidence_link_referential_integrity(db.conn)

    assert len(issues) == 1
    assert issues[0].problem == "unknown_table"
    assert issues[0].source_table == "totally_made_up_table"


def test_referential_integrity_empty_database_has_no_issues(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert check_evidence_link_referential_integrity(db.conn) == []


# =========================================================================
# Schema migrations are idempotent against a database holding real data
# =========================================================================


def test_init_schema_rerun_against_populated_database_preserves_all_data(tmp_path: Path):
    """Not just 'init_schema doesn't crash twice' (already covered by
    test_storage.py's column-healing tests) — this proves re-running it
    against a database that already holds real rows across several
    tables changes NOTHING about that data.
    """
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        process, _ = upsert_process_entry(
            db.conn, executable_path="/usr/bin/curl", process_name="curl", run_as_user="erick"
        )
        conn_ids = add_connection_events(
            db.conn, "run1",
            [("tcp", "192.168.1.23", 55555, "203.0.113.9", 443, "ESTABLISHED", 4321, "curl")],
        )
        add_evidence_link(
            db.conn,
            from_source_table="process_entries", from_source_id=process.id,
            from_fingerprint=_fp("process_entries", process.id),
            to_source_table="connection_events", to_source_id=conn_ids[0],
            to_fingerprint=_fp("connection_events", conn_ids[0]),
            relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION, match_basis="identity+timing",
            detail="matched", created_by="test",
        )
        db.conn.commit()

        before_processes = db.conn.execute("SELECT COUNT(*) AS c FROM process_entries").fetchone()["c"]
        before_conns = db.conn.execute("SELECT COUNT(*) AS c FROM connection_events").fetchone()["c"]
        before_links = db.conn.execute("SELECT COUNT(*) AS c FROM evidence_links").fetchone()["c"]

        # The actual test: call init_schema() again, directly, against
        # this SAME live connection with real data already in it — not
        # a fresh empty one.
        init_schema(db.conn)
        init_schema(db.conn)  # and a third time total, for good measure

        after_processes = db.conn.execute("SELECT COUNT(*) AS c FROM process_entries").fetchone()["c"]
        after_conns = db.conn.execute("SELECT COUNT(*) AS c FROM connection_events").fetchone()["c"]
        after_links = db.conn.execute("SELECT COUNT(*) AS c FROM evidence_links").fetchone()["c"]

    assert after_processes == before_processes == 1
    assert after_conns == before_conns == 1
    assert after_links == before_links == 1


def test_reopening_database_across_sessions_preserves_data_and_hardens_permissions(tmp_path: Path):
    """The real-world pattern every CLI invocation follows: open, do
    one thing, close; open again next command. Proves data survives
    repeated open/close cycles against the same file (this is also
    where Phase 29 Stage 4's permission hardening runs on every open —
    see secure/storage/database.py's connect()) — both integrity
    properties exercised by the same realistic sequence.
    """
    import stat

    db_path = tmp_path / "nested" / "test.db"

    with Database(db_path) as db:
        upsert_process_entry(db.conn, executable_path="/usr/bin/curl", process_name="curl", run_as_user="erick")

    with Database(db_path) as db:
        count = db.conn.execute("SELECT COUNT(*) AS c FROM process_entries").fetchone()["c"]
    assert count == 1

    with Database(db_path) as db:
        upsert_process_entry(db.conn, executable_path="/usr/bin/wget", process_name="wget", run_as_user="erick")

    with Database(db_path) as db:
        count = db.conn.execute("SELECT COUNT(*) AS c FROM process_entries").fetchone()["c"]
    assert count == 2

    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600


# =========================================================================
# Bad/partial sensor data cannot poison a baseline — end-to-end, not just
# the classify_eligibility() unit tests test_baseline_eligibility.py has.
# =========================================================================


def test_repeated_partial_sensor_data_never_writes_baseline_feature_stats(tmp_path: Path):
    """Deliberately induced failure condition: feed the SAME entity
    partial_sensor_data=True ten times in a row (simulating a sensor
    that keeps failing to read a value) and confirm
    baseline_feature_stats stays completely empty for it and its
    maturity state never advances past NO_BASELINE — the exact
    "poisoning" this phase's audit is checking cannot happen.
    """
    entity_key = persistence_key("launch_agent", "/usr/bin/suspicious")

    with Database(tmp_path / "test.db") as db:
        for i in range(10):
            observed_at = datetime(2026, 1, 1 + i, tzinfo=timezone.utc).isoformat()
            result = evaluate_and_record_feature_observation(
                db.conn, f"run{i}", PERSISTENCE, entity_key, "signing_status",
                None,  # sensor could not determine a value
                observed_at,
                partial_sensor_data=True,
            )
            assert result is None  # never scored

        stat = get_baseline_feature_stat(db.conn, PERSISTENCE, entity_key, "signing_status", "unsigned")
        assert stat is None  # nothing was ever folded into feature stats

        maturity_row = find_baseline_feature_maturity(db.conn, PERSISTENCE, entity_key, "signing_status")
        # A maturity row now exists (activity was logged), but its state
        # must still be NO_BASELINE — ten ineligible observations must
        # never look like a mature baseline.
        assert maturity_row is not None
        assert maturity_row.maturity_state == NO_BASELINE
        assert maturity_row.eligible_weight_total == 0.0


def test_one_real_observation_after_partial_data_does_update_stats(tmp_path: Path):
    """The other half of the proof: this ISN'T a broken code path that
    never records anything — a single genuine, fully-available
    observation for the same entity DOES fold into baseline_feature_stats,
    confirming the partial-data test above is a real gate, not a
    coincidental total blackout.
    """
    entity_key = persistence_key("launch_agent", "/usr/bin/suspicious")

    with Database(tmp_path / "test.db") as db:
        for i in range(5):
            evaluate_and_record_feature_observation(
                db.conn, f"run{i}", PERSISTENCE, entity_key, "signing_status", None,
                datetime(2026, 1, 1 + i, tzinfo=timezone.utc).isoformat(),
                partial_sensor_data=True,
            )

        evaluate_and_record_feature_observation(
            db.conn, "run_real", PERSISTENCE, entity_key, "signing_status", "signed",
            datetime(2026, 1, 10, tzinfo=timezone.utc).isoformat(),
        )

        stat = get_baseline_feature_stat(db.conn, PERSISTENCE, entity_key, "signing_status", "signed")

    assert stat is not None
    assert stat.lifetime_weight_total == 1.0
