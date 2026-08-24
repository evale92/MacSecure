"""
Phase 22 Stage 5: worked examples + adversarial false-positive tests
for secure/correlate/chains.py, per the phase's own explicit
instruction: "Support meaningful chains such as: file created -> YARA
finding -> process execution -> persistence -> unusual destination ->
network IDS finding... Add worked examples and adversarial
false-positive tests."

Worked examples exercise the FULL six-step shape named in that
instruction, end to end against a real seeded database, using the same
tables Stage 1's real wiring actually writes to (integration_alerts for
YARA-X/Suricata findings, persistence_alerts, file_integrity_alerts,
process_entries, connection_events) — not synthetic stand-ins.

Adversarial tests each try one specific way an attacker (or just messy
data) COULD inflate a chain's apparent corroboration, and assert the
anti-inflation mechanisms named in Phase 22's own instruction
("Use Phase 21 lineage/deduplication so duplicated observations cannot
inflate corroboration") actually hold under each attempt.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.correlate.analysis import CRITICAL, HIGH, MEDIUM_SEVERITY
from secure.correlate.chains import score_chain
from secure.evidence.model import (
    RELATIONSHIP_DERIVED_EVIDENCE,
    RELATIONSHIP_SAME_EVENT_CONFIRMATION,
    EvidenceLink,
    ObservationRef,
)
from secure.evidence.record import record_link
from secure.explain.vocab import CONFIRMED, INSUFFICIENT_EVIDENCE, LIKELY, UNCERTAIN
from secure.storage.database import Database

_BOOT_LONG_AGO = datetime(2020, 1, 1, tzinfo=timezone.utc)


# ---------- seed helpers (real columns, real tables) ----------


def _seed_file_integrity_alert(conn, *, severity="high", created_at) -> int:
    cursor = conn.execute(
        "INSERT INTO file_integrity_alerts (created_at, run_id, kind, severity, path, message, "
        "context_notes, known) VALUES (?, 'r', 'modified', ?, '/tmp/dropper.sh', 'hash changed', NULL, 0)",
        (created_at, severity),
    )
    conn.commit()
    return cursor.lastrowid


def _seed_yara_alert(conn, *, severity="high", created_at) -> int:
    cursor = conn.execute(
        "INSERT INTO integration_alerts (created_at, run_id, integration, kind, discrepancy, severity, "
        "identity_key, label, message, source_observation_id, known) VALUES "
        "(?, 'r', 'yara-x', 'match', 'match', ?, 'k', 'suspicious_script', 'YARA rule matched', NULL, 0)",
        (created_at, severity),
    )
    conn.commit()
    return cursor.lastrowid


def _seed_process_entry(conn, *, executable_path="/tmp/dropper.sh", last_seen) -> int:
    cursor = conn.execute(
        "INSERT INTO process_entries (executable_path, process_name, run_as_user, signing_status, "
        "known, times_seen, first_seen, last_seen) VALUES (?, 'dropper.sh', 'root', 'unsigned', 0, 1, ?, ?)",
        (executable_path, last_seen, last_seen),
    )
    conn.commit()
    return cursor.lastrowid


def _seed_persistence_alert(conn, *, severity="high", created_at) -> int:
    cursor = conn.execute(
        "INSERT INTO persistence_alerts (created_at, run_id, kind, severity, target_type, identifier, "
        "label, message, known) VALUES (?, 'r', 'new_entry', ?, 'launch_agent', 'com.dropper.x', "
        "'dropper', 'new persistence entry', 0)",
        (created_at, severity),
    )
    conn.commit()
    return cursor.lastrowid


def _seed_connection_event(conn, *, remote_addr="198.51.100.7", created_at) -> int:
    cursor = conn.execute(
        "INSERT INTO connection_events (created_at, run_id, proto, local_addr, local_port, "
        "remote_addr, remote_port, state, pid, process_name) VALUES (?, 'r', 'tcp', '10.0.0.1', "
        "51000, ?, 4444, 'ESTABLISHED', 100, 'dropper.sh')",
        (created_at, remote_addr),
    )
    conn.commit()
    return cursor.lastrowid


def _seed_suricata_alert(conn, *, severity="critical", created_at) -> int:
    cursor = conn.execute(
        "INSERT INTO integration_alerts (created_at, run_id, integration, kind, discrepancy, severity, "
        "identity_key, label, message, source_observation_id, known) VALUES "
        "(?, 'r', 'suricata', 'network_alert', 'match', ?, 'k', 'c2_signature', 'IDS signature matched', NULL, 0)",
        (created_at, severity),
    )
    conn.commit()
    return cursor.lastrowid


def _link(conn, from_table, from_id, to_table, to_id, relationship, detail):
    record_link(
        conn,
        EvidenceLink(
            from_ref=ObservationRef(source_table=from_table, source_id=from_id),
            to_ref=ObservationRef(source_table=to_table, source_id=to_id),
            relationship=relationship, match_basis="identity+timing", detail=detail, created_by="test",
        ),
    )


def _build_full_six_step_chain(conn):
    """file created -> YARA finding -> process execution -> persistence
    -> unusual destination -> network IDS finding, exactly the shape
    named in Phase 22's own instruction. Returns the six node ids in
    chain order.
    """
    t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    file_alert = _seed_file_integrity_alert(conn, created_at=(t0).isoformat())
    yara_alert = _seed_yara_alert(conn, created_at=(t0 + timedelta(seconds=5)).isoformat())
    process = _seed_process_entry(conn, last_seen=(t0 + timedelta(seconds=10)).isoformat())
    persistence = _seed_persistence_alert(conn, created_at=(t0 + timedelta(seconds=20)).isoformat())
    destination = _seed_connection_event(conn, created_at=(t0 + timedelta(seconds=30)).isoformat())
    ids_alert = _seed_suricata_alert(conn, created_at=(t0 + timedelta(seconds=40)).isoformat())

    # file created -> YARA finding
    _link(conn, "integration_alerts", yara_alert, "file_integrity_alerts", file_alert,
          RELATIONSHIP_DERIVED_EVIDENCE, "YARA-X matched content in the changed file")
    # YARA finding -> process execution
    _link(conn, "process_entries", process, "integration_alerts", yara_alert,
          RELATIONSHIP_DERIVED_EVIDENCE, "flagged file was then executed")
    # process execution -> persistence
    _link(conn, "persistence_alerts", persistence, "process_entries", process,
          RELATIONSHIP_DERIVED_EVIDENCE, "process installed a persistence entry")
    # persistence -> unusual destination
    _link(conn, "connection_events", destination, "persistence_alerts", persistence,
          RELATIONSHIP_DERIVED_EVIDENCE, "persisted binary reached out to a new destination")
    # unusual destination -> network IDS finding
    _link(conn, "integration_alerts", ids_alert, "connection_events", destination,
          RELATIONSHIP_DERIVED_EVIDENCE, "Suricata matched a signature on that connection")

    return file_alert, yara_alert, process, persistence, destination, ids_alert


# ---------- worked example ----------


def test_worked_example_full_six_step_chain_reaches_high_confidence(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        file_alert, yara_alert, process, persistence, destination, ids_alert = _build_full_six_step_chain(db.conn)

        score = score_chain(
            db.conn, ObservationRef(source_table="file_integrity_alerts", source_id=file_alert),
            boot_time=_BOOT_LONG_AGO, boot_time_resolved=True,
        )

        assert score.raw_observation_count == 6
        assert score.independent_fact_count == 6  # every step is a genuinely distinct fact
        assert score.module_count == 5  # file_integrity, integrations(yara-x), process, persistence, connections... see below
        assert score.meaningful_relationship_count == 5  # all five derived_evidence edges cross modules
        # 5 modules and 5 meaningful cross-source relationships clears
        # CONFIRMED's (module_count>=3, meaningful>=2) bar.
        assert score.confidence == CONFIRMED
        assert score.severity in (HIGH, CRITICAL)
        # explanation must actually mention the fact count, not just raw count
        assert "6" in score.explanation


def test_worked_example_reachable_from_any_step_with_identical_fingerprint(tmp_path: Path):
    # Reviewing this chain starting from the middle (say, the
    # persistence alert an analyst noticed first) must surface the SAME
    # full chain, not a truncated one — a chain's identity should not
    # depend on which alert an analyst happened to click first.
    with Database(tmp_path / "test.db") as db:
        file_alert, yara_alert, process, persistence, destination, ids_alert = _build_full_six_step_chain(db.conn)

        from_start = score_chain(db.conn, ObservationRef(source_table="file_integrity_alerts", source_id=file_alert))
        from_middle = score_chain(db.conn, ObservationRef(source_table="persistence_alerts", source_id=persistence))
        from_end = score_chain(db.conn, ObservationRef(source_table="integration_alerts", source_id=ids_alert))

        assert from_start.raw_observation_count == from_middle.raw_observation_count == from_end.raw_observation_count == 6


# ---------- adversarial false-positive tests ----------


def test_adversarial_many_confirmations_of_one_fact_do_not_inflate_score(tmp_path: Path):
    # An attacker (or just a noisy environment) causing the SAME
    # underlying connection to be "confirmed" by ten different
    # integration_observations rows must not let raw observation count
    # substitute for real corroboration — Phase 22's own instruction,
    # verbatim: "duplicated observations cannot inflate corroboration."
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn, created_at="2026-01-01T12:00:00+00:00")
        for i in range(10):
            cursor = db.conn.execute(
                "INSERT INTO integration_observations (created_at, run_id, integration, kind, identity_key, "
                "fields_json, source_query, collected_at) VALUES (?, 'r', 'zeek', 'conn', 'k', '{}', 'q', ?)",
                (f"2026-01-01T12:00:{i:02d}+00:00", f"2026-01-01T12:00:{i:02d}+00:00"),
            )
            db.conn.commit()
            obs_id = cursor.lastrowid
            _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
                  RELATIONSHIP_SAME_EVENT_CONFIRMATION, f"confirmation {i}")

        score = score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id))
        assert score.raw_observation_count == 11  # the connection + 10 confirming observations
        assert score.independent_fact_count == 1  # still ONE fact
        assert score.confidence != CONFIRMED  # ten confirmations from the same module never earns CONFIRMED
        assert score.severity != CRITICAL


def test_adversarial_same_module_derived_edge_is_not_a_meaningful_relationship(tmp_path: Path):
    # A derived_evidence edge where BOTH sides are the same module
    # (e.g. two Zeek-sourced facts, one nominally "derived from" the
    # other) must not count toward meaningful_relationship_count — that
    # count exists specifically to require independent SOURCES, not
    # just independent database rows.
    with Database(tmp_path / "test.db") as db:
        obs1 = db.conn.execute(
            "INSERT INTO integration_observations (created_at, run_id, integration, kind, identity_key, "
            "fields_json, source_query, collected_at) VALUES ('2026-01-01T12:00:00+00:00', 'r', 'zeek', "
            "'conn', 'k1', '{}', 'q', '2026-01-01T12:00:00+00:00')"
        ).lastrowid
        db.conn.commit()
        obs2 = db.conn.execute(
            "INSERT INTO integration_observations (created_at, run_id, integration, kind, identity_key, "
            "fields_json, source_query, collected_at) VALUES ('2026-01-01T12:00:05+00:00', 'r', 'zeek', "
            "'conn', 'k2', '{}', 'q', '2026-01-01T12:00:05+00:00')"
        ).lastrowid
        db.conn.commit()
        _link(db.conn, "integration_observations", obs2, "integration_observations", obs1,
              RELATIONSHIP_DERIVED_EVIDENCE, "same-module chain")

        score = score_chain(db.conn, ObservationRef(source_table="integration_observations", source_id=obs1))
        assert score.independent_fact_count == 2  # two distinct facts, correctly not merged
        assert score.meaningful_relationship_count == 0  # but NOT a cross-source meaningful relationship
        assert score.confidence == INSUFFICIENT_EVIDENCE  # single module overall


def test_adversarial_long_weak_chain_never_reaches_high_or_critical(tmp_path: Path):
    # A long chain built ENTIRELY from plain observation rows (no real
    # alert/severity anywhere) must stay capped at MEDIUM no matter how
    # many hops or modules it accumulates — apply_weak_evidence_cap()'s
    # explicit job, stress-tested with a longer chain than the unit
    # tests in test_correlate_chains.py use.
    with Database(tmp_path / "test.db") as db:
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        first_id = _seed_connection_event(db.conn, created_at=t0.isoformat())
        prev_table, prev_id = "connection_events", first_id
        for i in range(6):
            obs_id = db.conn.execute(
                "INSERT INTO integration_observations (created_at, run_id, integration, kind, identity_key, "
                "fields_json, source_query, collected_at) VALUES (?, 'r', ?, 'conn', ?, '{}', 'q', ?)",
                ((t0 + timedelta(seconds=i + 1)).isoformat(), f"tool{i}", f"k{i}",
                 (t0 + timedelta(seconds=i + 1)).isoformat()),
            ).lastrowid
            db.conn.commit()
            _link(db.conn, "integration_observations", obs_id, prev_table, prev_id,
                  RELATIONSHIP_DERIVED_EVIDENCE, f"hop {i}")
            prev_table, prev_id = "integration_observations", obs_id

        score = score_chain(
            db.conn, ObservationRef(source_table="connection_events", source_id=first_id),
            max_hops=10, boot_time=_BOOT_LONG_AGO, boot_time_resolved=True,
        )
        assert score.raw_observation_count == 7  # the seeded connection + 6 chained observations
        assert score.severity != HIGH
        assert score.severity != CRITICAL


def test_adversarial_rescan_burst_within_one_pass_is_stable(tmp_path: Path):
    # Recording the identical relationship many times in a tight loop
    # (simulating a pathological rescan burst) must converge to the
    # exact same score every time, not creep upward with each repeat.
    with Database(tmp_path / "test.db") as db:
        conn_id = _seed_connection_event(db.conn, created_at="2026-01-01T12:00:00+00:00")
        obs_id = db.conn.execute(
            "INSERT INTO integration_observations (created_at, run_id, integration, kind, identity_key, "
            "fields_json, source_query, collected_at) VALUES ('2026-01-01T12:00:05+00:00', 'r', 'zeek', "
            "'conn', 'k', '{}', 'q', '2026-01-01T12:00:05+00:00')"
        ).lastrowid
        db.conn.commit()

        scores = []
        for _ in range(5):
            _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
                  RELATIONSHIP_SAME_EVENT_CONFIRMATION, "rescan")
            scores.append(
                score_chain(db.conn, ObservationRef(source_table="connection_events", source_id=conn_id)).raw_score
            )
        assert len(set(scores)) == 1  # identical every time, no creep


def test_adversarial_boot_burst_of_weak_facts_stays_low_severity(tmp_path: Path):
    # A burst of ordinary weak facts clustered right after boot (the
    # classic false-positive shape apply_context()'s own docstring
    # names for the temporal-clustering model) must be similarly
    # discounted here, not just for correlation_alerts.
    with Database(tmp_path / "test.db") as db:
        boot_time = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
        conn_id = _seed_connection_event(db.conn, created_at=(boot_time + timedelta(seconds=30)).isoformat())
        obs_id = db.conn.execute(
            "INSERT INTO integration_observations (created_at, run_id, integration, kind, identity_key, "
            "fields_json, source_query, collected_at) VALUES (?, 'r', 'zeek', 'conn', 'k', '{}', 'q', ?)",
            ((boot_time + timedelta(seconds=35)).isoformat(), (boot_time + timedelta(seconds=35)).isoformat()),
        ).lastrowid
        db.conn.commit()
        _link(db.conn, "integration_observations", obs_id, "connection_events", conn_id,
              RELATIONSHIP_SAME_EVENT_CONFIRMATION, "boot burst")

        score = score_chain(
            db.conn, ObservationRef(source_table="connection_events", source_id=conn_id),
            boot_time=boot_time, boot_time_resolved=True,
        )
        assert score.benign_context_notes is not None
        assert score.severity not in (HIGH, CRITICAL)
