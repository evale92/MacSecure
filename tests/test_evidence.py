"""
Tests for secure/evidence/ (Phase 21: unified evidence, lineage, and
deduplication model).

Stage 1 scope: pure model (model.py) and the pure identity+timing
matching / stable-hashing toolkit (fingerprint.py) — no database, no
integration wiring yet (that's Stage 2/3; see PROJECT_NOTES.md).

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from secure.evidence.record import record_link
from secure.storage.database import Database
from secure.storage.models import (
    add_evidence_link,
    find_evidence_link_by_fingerprint,
    list_evidence_link_observations,
    list_evidence_links_for,
    touch_evidence_link,
)
from secure.evidence.fingerprint import (
    CandidateSide,
    MatchTarget,
    find_best_identity_timing_match,
    logical_ref_identity,
    observation_part,
    stable_fingerprint,
)
from secure.evidence.model import (
    RELATIONSHIP_DERIVED_EVIDENCE,
    RELATIONSHIP_DUPLICATE_OBSERVATION,
    RELATIONSHIP_SAME_EVENT_CONFIRMATION,
    SOURCE_INTEGRATION,
    SOURCE_NATIVE,
    SOURCE_THREATINTEL,
    EvidenceLink,
    ObservationRef,
    SourceRef,
)


# =========================================================================
# model.py — SourceRef
# =========================================================================


def test_source_ref_valid_kinds():
    assert SourceRef(kind=SOURCE_NATIVE, name="connections").kind == SOURCE_NATIVE
    assert SourceRef(kind=SOURCE_INTEGRATION, name="suricata").kind == SOURCE_INTEGRATION
    assert SourceRef(kind=SOURCE_THREATINTEL, name="virustotal").kind == SOURCE_THREATINTEL


def test_source_ref_rejects_invalid_kind():
    try:
        SourceRef(kind="not_a_real_kind", name="x")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "invalid SourceRef.kind" in str(exc)


def test_source_ref_rejects_empty_name():
    try:
        SourceRef(kind=SOURCE_NATIVE, name="")
        assert False, "expected ValueError"
    except ValueError:
        pass


# =========================================================================
# model.py — ObservationRef
# =========================================================================


def test_observation_ref_valid():
    ref = ObservationRef(source_table="connection_events", source_id=42)
    assert ref.source_table == "connection_events"
    assert ref.source_id == 42


def test_observation_ref_rejects_empty_table():
    try:
        ObservationRef(source_table="", source_id=1)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_observation_ref_rejects_none_id():
    try:
        ObservationRef(source_table="connection_events", source_id=None)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_observation_ref_allows_id_zero():
    # 0 is a legitimate (if unusual) primary key value — must not be
    # confused with None by an `if not source_id` style check.
    ref = ObservationRef(source_table="connection_events", source_id=0)
    assert ref.source_id == 0


def test_observation_ref_logical_key_defaults_to_none():
    ref = ObservationRef(source_table="connection_events", source_id=1)
    assert ref.logical_key is None


def test_observation_ref_accepts_logical_key():
    ref = ObservationRef(source_table="integration_observations", source_id=1, logical_key="osquery:listening_port:tcp:22")
    assert ref.logical_key == "osquery:listening_port:tcp:22"


def test_observation_ref_rejects_empty_logical_key():
    try:
        ObservationRef(source_table="connection_events", source_id=1, logical_key="")
        assert False, "expected ValueError"
    except ValueError:
        pass


# =========================================================================
# fingerprint.py — logical_ref_identity
# =========================================================================


def test_logical_ref_identity_falls_back_to_source_id_when_no_logical_key():
    # Zeek/Suricata's own behavior: no logical_key passed, so identity
    # is just table:id — exactly what pre-correction idempotence used.
    assert logical_ref_identity("connection_events", 42) == "connection_events:42"


def test_logical_ref_identity_uses_logical_key_when_given():
    # osquery's own behavior: identity is stable across scans even
    # though source_id (the observation row) is different every time.
    assert (
        logical_ref_identity("integration_observations", 999, "osquery:listening_port:tcp:22")
        == "integration_observations:osquery:listening_port:tcp:22"
    )


def test_logical_ref_identity_same_logical_key_different_source_id_matches():
    a = logical_ref_identity("integration_observations", 1, "osquery:listening_port:tcp:22")
    b = logical_ref_identity("integration_observations", 999999, "osquery:listening_port:tcp:22")
    assert a == b  # the whole point: source_id churn doesn't change identity


def test_logical_ref_identity_different_logical_key_differs():
    a = logical_ref_identity("integration_observations", 1, "osquery:listening_port:tcp:22")
    b = logical_ref_identity("integration_observations", 1, "osquery:listening_port:tcp:23")
    assert a != b


# =========================================================================
# model.py — EvidenceLink and the RELATIONSHIP_* structural invariant
# =========================================================================


def _link(relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION, **overrides) -> EvidenceLink:
    kwargs = dict(
        from_ref=ObservationRef(source_table="integration_observations", source_id=1),
        to_ref=ObservationRef(source_table="connection_events", source_id=2),
        relationship=relationship,
        match_basis="identity+timing",
        detail="test link",
        created_by="test",
        time_delta_seconds=12.5,
    )
    kwargs.update(overrides)
    return EvidenceLink(**kwargs)


def test_evidence_link_valid_construction_every_relationship():
    for rel in (RELATIONSHIP_DUPLICATE_OBSERVATION, RELATIONSHIP_SAME_EVENT_CONFIRMATION, RELATIONSHIP_DERIVED_EVIDENCE):
        link = _link(relationship=rel)
        assert link.relationship == rel


def test_evidence_link_rejects_invalid_relationship():
    try:
        _link(relationship="not_a_real_relationship")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "invalid EvidenceLink.relationship" in str(exc)


def test_evidence_link_rejects_empty_match_basis():
    try:
        _link(match_basis="")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_evidence_link_rejects_empty_created_by():
    try:
        _link(created_by="")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_evidence_link_time_delta_optional():
    link = _link(time_delta_seconds=None)
    assert link.time_delta_seconds is None


def test_evidence_link_carries_no_severity_or_confidence_field():
    # Structural check on Phase 21's own explicit instruction: nothing
    # here collapses severity/confidence/anomaly/trust into the
    # evidence model. Asserts the dataclass's own field set directly
    # rather than trusting a comment.
    field_names = set(EvidenceLink.__dataclass_fields__.keys())
    for forbidden in ("severity", "confidence", "anomaly_score", "trust", "known"):
        assert forbidden not in field_names


# =========================================================================
# fingerprint.py — find_best_identity_timing_match
# =========================================================================


def _base_ts():
    return datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc)


def test_find_best_identity_timing_match_finds_exact_match_within_window():
    sides = [CandidateSide(label="dest", addr="203.0.113.5", port=443)]
    targets = [MatchTarget(id=100, proto="TCP", addr="203.0.113.5", port=443, timestamp=_base_ts())]
    outcome = find_best_identity_timing_match(sides, "TCP", _base_ts(), targets, window_seconds=300.0)
    assert outcome is not None
    assert outcome.target_id == 100
    assert outcome.matched_side == "dest"
    assert outcome.time_delta_seconds == 0.0


def test_find_best_identity_timing_match_tries_both_sides():
    sides = [
        CandidateSide(label="src", addr="192.0.2.1", port=51000),
        CandidateSide(label="dest", addr="203.0.113.5", port=443),
    ]
    targets = [MatchTarget(id=1, proto="TCP", addr="192.0.2.1", port=51000, timestamp=_base_ts())]
    outcome = find_best_identity_timing_match(sides, "TCP", _base_ts(), targets, window_seconds=300.0)
    assert outcome is not None
    assert outcome.matched_side == "src"


def test_find_best_identity_timing_match_rejects_outside_window():
    from datetime import timedelta

    sides = [CandidateSide(label="dest", addr="203.0.113.5", port=443)]
    far_ts = _base_ts() + timedelta(seconds=1000)
    targets = [MatchTarget(id=1, proto="TCP", addr="203.0.113.5", port=443, timestamp=far_ts)]
    outcome = find_best_identity_timing_match(sides, "TCP", _base_ts(), targets, window_seconds=300.0)
    assert outcome is None


def test_find_best_identity_timing_match_rejects_proto_mismatch():
    sides = [CandidateSide(label="dest", addr="203.0.113.5", port=443)]
    targets = [MatchTarget(id=1, proto="UDP", addr="203.0.113.5", port=443, timestamp=_base_ts())]
    outcome = find_best_identity_timing_match(sides, "TCP", _base_ts(), targets, window_seconds=300.0)
    assert outcome is None


def test_find_best_identity_timing_match_rejects_address_mismatch():
    sides = [CandidateSide(label="dest", addr="203.0.113.5", port=443)]
    targets = [MatchTarget(id=1, proto="TCP", addr="203.0.113.9", port=443, timestamp=_base_ts())]
    outcome = find_best_identity_timing_match(sides, "TCP", _base_ts(), targets, window_seconds=300.0)
    assert outcome is None


def test_find_best_identity_timing_match_picks_closest_in_time():
    from datetime import timedelta

    sides = [CandidateSide(label="dest", addr="203.0.113.5", port=443)]
    targets = [
        MatchTarget(id=1, proto="TCP", addr="203.0.113.5", port=443, timestamp=_base_ts() + timedelta(seconds=200)),
        MatchTarget(id=2, proto="TCP", addr="203.0.113.5", port=443, timestamp=_base_ts() + timedelta(seconds=20)),
        MatchTarget(id=3, proto="TCP", addr="203.0.113.5", port=443, timestamp=_base_ts() + timedelta(seconds=280)),
    ]
    outcome = find_best_identity_timing_match(sides, "TCP", _base_ts(), targets, window_seconds=300.0)
    assert outcome is not None
    assert outcome.target_id == 2
    assert outcome.time_delta_seconds == 20.0


def test_find_best_identity_timing_match_no_candidates_returns_none():
    outcome = find_best_identity_timing_match([], "TCP", _base_ts(), [], window_seconds=300.0)
    assert outcome is None


def test_find_best_identity_timing_match_no_targets_returns_none():
    sides = [CandidateSide(label="dest", addr="203.0.113.5", port=443)]
    outcome = find_best_identity_timing_match(sides, "TCP", _base_ts(), [], window_seconds=300.0)
    assert outcome is None


# =========================================================================
# fingerprint.py — stable_fingerprint / observation_part
# =========================================================================


def test_stable_fingerprint_order_independent():
    a = stable_fingerprint(["connection_events:1", "integration_observations:2"])
    b = stable_fingerprint(["integration_observations:2", "connection_events:1"])
    assert a == b


def test_stable_fingerprint_different_parts_differ():
    a = stable_fingerprint(["connection_events:1"])
    b = stable_fingerprint(["connection_events:2"])
    assert a != b


def test_stable_fingerprint_deterministic_across_calls():
    parts = ["connection_events:1", "integration_observations:2"]
    assert stable_fingerprint(parts) == stable_fingerprint(list(parts))


def test_observation_part_shape():
    assert observation_part("connection_events", 42) == "connection_events:42"


# =========================================================================
# storage/models/evidence.py — round trip + idempotence
# =========================================================================


def _fp(table: str, id_: int) -> str:
    return logical_ref_identity(table, id_)


def test_add_and_find_evidence_link_round_trip(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        new_id = add_evidence_link(
            db.conn, from_source_table="integration_observations", from_source_id=1,
            from_fingerprint=_fp("integration_observations", 1),
            to_source_table="connection_events", to_source_id=2,
            to_fingerprint=_fp("connection_events", 2),
            relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION, match_basis="identity+timing",
            detail="matched", created_by="test", time_delta_seconds=5.0,
        )
        found = find_evidence_link_by_fingerprint(
            db.conn, _fp("integration_observations", 1), _fp("connection_events", 2),
            RELATIONSHIP_SAME_EVENT_CONFIRMATION,
        )
        assert found is not None
        assert found.id == new_id
        assert found.time_delta_seconds == 5.0
        assert found.created_by == "test"
        assert found.first_source_id == 1
        assert found.times_seen == 1
        assert found.first_seen == found.last_seen


def test_find_evidence_link_by_fingerprint_returns_none_when_absent(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert find_evidence_link_by_fingerprint(
            db.conn, _fp("integration_observations", 999), _fp("connection_events", 888),
            RELATIONSHIP_SAME_EVENT_CONFIRMATION,
        ) is None


def test_add_evidence_link_raises_on_exact_fingerprint_duplicate(tmp_path: Path):
    import sqlite3

    with Database(tmp_path / "test.db") as db:
        add_evidence_link(
            db.conn, from_source_table="a", from_source_id=1, from_fingerprint=_fp("a", 1),
            to_source_table="b", to_source_id=2, to_fingerprint=_fp("b", 2),
            relationship=RELATIONSHIP_DUPLICATE_OBSERVATION, match_basis="x", detail="d", created_by="c",
        )
        try:
            add_evidence_link(
                db.conn, from_source_table="a", from_source_id=1, from_fingerprint=_fp("a", 1),
                to_source_table="b", to_source_id=2, to_fingerprint=_fp("b", 2),
                relationship=RELATIONSHIP_DUPLICATE_OBSERVATION, match_basis="x", detail="d", created_by="c",
            )
            assert False, "expected sqlite3.IntegrityError"
        except sqlite3.IntegrityError:
            pass


def test_add_evidence_link_allows_same_pair_different_relationship(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_evidence_link(
            db.conn, from_source_table="a", from_source_id=1, from_fingerprint=_fp("a", 1),
            to_source_table="b", to_source_id=2, to_fingerprint=_fp("b", 2),
            relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION, match_basis="x", detail="d", created_by="c",
        )
        # Same (from, to) pair, DIFFERENT relationship — must not collide
        # with the unique index (it's scoped to include relationship).
        second_id = add_evidence_link(
            db.conn, from_source_table="a", from_source_id=1, from_fingerprint=_fp("a", 1),
            to_source_table="b", to_source_id=2, to_fingerprint=_fp("b", 2),
            relationship=RELATIONSHIP_DERIVED_EVIDENCE, match_basis="y", detail="d2", created_by="c",
        )
        assert second_id is not None


def test_touch_evidence_link_advances_last_seen_and_times_seen(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        link_id = add_evidence_link(
            db.conn, from_source_table="integration_observations", from_source_id=1,
            from_fingerprint="integration_observations:osquery:listening_port:tcp:22",
            to_source_table="listening_services", to_source_id=5,
            to_fingerprint=_fp("listening_services", 5),
            relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION, match_basis="structural_agreement",
            detail="first", created_by="osquery_crosscheck",
        )
        touch_evidence_link(db.conn, link_id, latest_source_id=2)
        found = find_evidence_link_by_fingerprint(
            db.conn, "integration_observations:osquery:listening_port:tcp:22",
            _fp("listening_services", 5), RELATIONSHIP_SAME_EVENT_CONFIRMATION,
        )
        assert found.times_seen == 2
        assert found.first_source_id == 1     # untouched
        assert found.from_source_id == 2      # advanced to "latest"
        assert found.detail == "first"        # untouched


def test_list_evidence_links_for_finds_from_either_side(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        add_evidence_link(
            db.conn, from_source_table="integration_observations", from_source_id=10,
            from_fingerprint=_fp("integration_observations", 10),
            to_source_table="connection_events", to_source_id=20,
            to_fingerprint=_fp("connection_events", 20),
            relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION, match_basis="x", detail="d", created_by="c",
        )
        # queried from the "to" side
        links_to = list_evidence_links_for(db.conn, "connection_events", 20)
        assert len(links_to) == 1
        # queried from the "from" side
        links_from = list_evidence_links_for(db.conn, "integration_observations", 10)
        assert len(links_from) == 1
        assert links_to[0].id == links_from[0].id


def test_list_evidence_links_for_empty_when_unlinked(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        assert list_evidence_links_for(db.conn, "connection_events", 999) == []


# =========================================================================
# evidence/record.py — record_link() idempotent orchestration
# =========================================================================


def _sample_link(**overrides) -> EvidenceLink:
    kwargs = dict(
        from_ref=ObservationRef(source_table="integration_observations", source_id=1),
        to_ref=ObservationRef(source_table="connection_events", source_id=2),
        relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION,
        match_basis="identity+timing",
        detail="matched via identity+timing",
        created_by="test_mechanism",
        time_delta_seconds=3.5,
    )
    kwargs.update(overrides)
    return EvidenceLink(**kwargs)


def test_record_link_creates_new_link(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record, created = record_link(db.conn, _sample_link())
        assert created is True
        assert record.relationship == RELATIONSHIP_SAME_EVENT_CONFIRMATION
        assert record.from_source_table == "integration_observations"
        assert record.to_source_id == 2


def test_record_link_is_idempotent_on_second_call(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        first, first_created = record_link(db.conn, _sample_link())
        second, second_created = record_link(db.conn, _sample_link())
        assert first_created is True
        assert second_created is False
        assert first.id == second.id  # no duplicate row was created
        assert second.times_seen == 2

        all_links = list_evidence_links_for(db.conn, "connection_events", 2)
        assert len(all_links) == 1


def test_record_link_with_logical_key_dedupes_across_different_source_ids(tmp_path: Path):
    # The actual osquery scenario (test 1/2 of the required set): two
    # calls with the SAME logical_key but a DIFFERENT raw from_ref
    # source_id (a fresh integration_observations row each scan) must
    # be recognized as the same logical relationship — not a duplicate
    # observation row id (which would always differ) and not a new
    # relationship.
    with Database(tmp_path / "test.db") as db:
        link_scan_1 = _sample_link(
            from_ref=ObservationRef(
                source_table="integration_observations", source_id=101,
                logical_key="osquery:listening_port:tcp:22",
            ),
            to_ref=ObservationRef(source_table="listening_services", source_id=5),
        )
        link_scan_2 = _sample_link(
            from_ref=ObservationRef(
                source_table="integration_observations", source_id=202,  # a brand-new row this scan
                logical_key="osquery:listening_port:tcp:22",              # same real fact
            ),
            to_ref=ObservationRef(source_table="listening_services", source_id=5),
        )
        first, first_created = record_link(db.conn, link_scan_1)
        second, second_created = record_link(db.conn, link_scan_2)

        assert first_created is True
        assert second_created is False
        assert first.id == second.id  # ONE logical relationship, not two

        # test 5 of the required set: exact first/latest provenance preserved
        assert second.first_source_id == 101
        assert second.from_source_id == 202
        assert second.times_seen == 2

        all_links = list_evidence_links_for(db.conn, "listening_services", 5)
        assert len(all_links) == 1  # test 6: no inflation from repeat scans


def test_record_link_new_native_counterpart_creates_a_second_link(tmp_path: Path):
    # test 3 of the required set: the relationship genuinely CHANGES
    # (same osquery identity_key, but this time matched against a
    # DIFFERENT native row) — this must NOT be folded into the existing
    # link; it's a different relationship and needs its own row.
    with Database(tmp_path / "test.db") as db:
        original_match = _sample_link(
            from_ref=ObservationRef(
                source_table="integration_observations", source_id=101,
                logical_key="osquery:listening_port:tcp:22",
            ),
            to_ref=ObservationRef(source_table="listening_services", source_id=5),
        )
        changed_match = _sample_link(
            from_ref=ObservationRef(
                source_table="integration_observations", source_id=202,
                logical_key="osquery:listening_port:tcp:22",  # same osquery-side identity
            ),
            to_ref=ObservationRef(source_table="listening_services", source_id=9),  # different native row
        )
        first, first_created = record_link(db.conn, original_match)
        second, second_created = record_link(db.conn, changed_match)

        assert first_created is True
        assert second_created is True  # genuinely a new relationship
        assert first.id != second.id
        assert first.times_seen == 1
        assert second.times_seen == 1


def test_record_link_appends_evidence_link_observation_every_call(tmp_path: Path):
    # Exact per-confirmation provenance is preserved even though
    # evidence_links itself only keeps one logical row — see
    # evidence.py's own CORRECTION docstring.
    with Database(tmp_path / "test.db") as db:
        link_scan_1 = _sample_link(
            from_ref=ObservationRef(
                source_table="integration_observations", source_id=101,
                logical_key="osquery:listening_port:tcp:22",
            ),
            to_ref=ObservationRef(source_table="listening_services", source_id=5),
        )
        link_scan_2 = _sample_link(
            from_ref=ObservationRef(
                source_table="integration_observations", source_id=202,
                logical_key="osquery:listening_port:tcp:22",
            ),
            to_ref=ObservationRef(source_table="listening_services", source_id=5),
        )
        record, _ = record_link(db.conn, link_scan_1)
        record_link(db.conn, link_scan_2)

        observations = list_evidence_link_observations(db.conn, record.id)
        assert len(observations) == 2
        source_ids = {o.from_source_id for o in observations}
        assert source_ids == {101, 202}


def test_record_link_different_relationship_creates_a_second_link(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record_link(db.conn, _sample_link(relationship=RELATIONSHIP_SAME_EVENT_CONFIRMATION))
        record_link(db.conn, _sample_link(relationship=RELATIONSHIP_DERIVED_EVIDENCE))
        all_links = list_evidence_links_for(db.conn, "connection_events", 2)
        assert len(all_links) == 2
        relationships = {link.relationship for link in all_links}
        assert relationships == {RELATIONSHIP_SAME_EVENT_CONFIRMATION, RELATIONSHIP_DERIVED_EVIDENCE}


def test_record_link_preserves_first_detail_never_overwrites(tmp_path: Path):
    with Database(tmp_path / "test.db") as db:
        record_link(db.conn, _sample_link(detail="first classification"))
        record, created = record_link(db.conn, _sample_link(detail="a different re-classification"))
        assert created is False
        assert record.detail == "first classification"  # never silently revised
