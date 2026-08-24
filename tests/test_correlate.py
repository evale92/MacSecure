"""
Tests for secure/correlate/* (Cross-Module Correlation).

strength.py and analysis.py are pure and tested directly with
hand-built Signal objects — no database, no Mac needed. context.py's
one subprocess call (`sysctl -n kern.boottime`) is tested via its
`_read_boottime_output()` seam, same "patch the wrapper" pattern every
other package in this app uses. signals.py is tested against a real
temp database seeded through secure.storage.models — it only reads
SQL, so this exercises the real code path, not a mock of it.
scanner.correlate() is tested end-to-end over that same kind of seeded
database.

Run with:  pytest
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from secure.correlate.analysis import (
    MEANINGFUL_MODULE_PAIRS,
    apply_weak_signal_cap,
    build_explanation,
    cluster_signals,
    correlation_score,
    distinct_modules,
    fingerprint_for_cluster,
    has_meaningful_combo,
    max_strength,
    severity_for_score,
)
from secure.correlate.context import (
    RUN_ALL_TRIGGER,
    apply_context,
    is_likely_update_or_install,
    is_recent_boot,
    parse_boottime_output,
)
from secure.correlate.scanner import correlate
from secure.correlate.signals import Signal, collect_signals
from secure.correlate.strength import (
    MEDIUM,
    STRONG,
    WEAK,
    classify_arp_alert_strength,
    classify_bluetooth_alert_strength,
    classify_listening_strength,
    classify_persistence_alert_strength,
    classify_process_strength,
)
from secure.persistence.codesign import SIGNED_APPLE, SIGNED_DEVELOPER, SIGNED_ADHOC, UNKNOWN, UNSIGNED
from secure.storage.database import Database
from secure.storage.models import (
    add_arp_alert,
    add_bluetooth_alert,
    add_ble_alert,
    add_correlation_alert,
    add_persistence_alert,
    add_wifi_alert,
    find_correlation_alert_by_id,
    list_correlation_alerts,
    set_correlation_alert_known,
    upsert_ble_peripheral,
    upsert_bluetooth_device,
    upsert_device,
    upsert_listening_service,
    upsert_process_entry,
    upsert_remote_endpoint,
    upsert_wifi_network,
)

BASE_TIME = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _sig(module, strength, offset=0, source_id=1, identifier=None, label=None, kind="x"):
    return Signal(
        timestamp=BASE_TIME + timedelta(seconds=offset),
        module=module,
        kind=kind,
        strength=strength,
        identifier=identifier or f"{module}-{source_id}",
        label=label,
        source_table=module,
        source_id=source_id,
    )


# ---------- strength.py ----------


def test_classify_process_strength_unsigned_is_strong():
    assert classify_process_strength(UNSIGNED, "/usr/local/bin/tool") == STRONG
    assert classify_process_strength(SIGNED_ADHOC, "/usr/local/bin/tool") == STRONG


def test_classify_process_strength_unknown_is_medium():
    assert classify_process_strength(UNKNOWN, "/usr/local/bin/tool") == MEDIUM
    assert classify_process_strength(None, "/usr/local/bin/tool") == MEDIUM


def test_classify_process_strength_signed_unusual_location_is_medium():
    assert classify_process_strength(SIGNED_DEVELOPER, "/tmp/tool") == MEDIUM


def test_classify_process_strength_signed_ordinary_location_is_weak():
    assert classify_process_strength(SIGNED_APPLE, "/usr/bin/tool") == WEAK
    assert classify_process_strength(SIGNED_DEVELOPER, "/Applications/Tool.app/tool") == WEAK


def test_classify_persistence_alert_strength():
    assert classify_persistence_alert_strength("high") == STRONG
    assert classify_persistence_alert_strength("medium") == MEDIUM
    assert classify_persistence_alert_strength("low") == MEDIUM  # defensive fallback


def test_classify_listening_strength():
    assert classify_listening_strength("network") == STRONG
    assert classify_listening_strength("localhost") == MEDIUM


def test_classify_arp_alert_strength():
    assert classify_arp_alert_strength("gateway_mac_changed") == STRONG
    assert classify_arp_alert_strength("ip_conflict") == STRONG
    assert classify_arp_alert_strength("mac_changed") == MEDIUM


def test_classify_bluetooth_alert_strength():
    assert classify_bluetooth_alert_strength("new_pairing") == STRONG
    assert classify_bluetooth_alert_strength("first_connection") == MEDIUM
    assert classify_bluetooth_alert_strength("persistent_unknown") == WEAK


# ---------- analysis.py: clustering ----------


def test_cluster_signals_empty():
    assert cluster_signals([]) == []


def test_cluster_signals_single():
    signals = [_sig("process", STRONG)]
    clusters = cluster_signals(signals, window_seconds=60)
    assert clusters == [signals]


def test_cluster_signals_groups_within_window():
    signals = [
        _sig("process", STRONG, offset=0, source_id=1),
        _sig("persistence", STRONG, offset=30, source_id=2),
        _sig("connections", WEAK, offset=55, source_id=3),
    ]
    clusters = cluster_signals(signals, window_seconds=60)
    assert len(clusters) == 1
    assert len(clusters[0]) == 3


def test_cluster_signals_splits_beyond_window():
    signals = [
        _sig("process", STRONG, offset=0, source_id=1),
        _sig("persistence", STRONG, offset=200, source_id=2),
    ]
    clusters = cluster_signals(signals, window_seconds=60)
    assert len(clusters) == 2


def test_cluster_signals_chains_even_when_first_and_last_exceed_window():
    # Each hop is <= 60s from its immediate predecessor, but the first
    # and last signals are 100s apart -- still one cluster, since
    # chaining is against the LAST signal in the cluster, not the first.
    signals = [
        _sig("process", STRONG, offset=0, source_id=1),
        _sig("persistence", STRONG, offset=50, source_id=2),
        _sig("connections", WEAK, offset=100, source_id=3),
    ]
    clusters = cluster_signals(signals, window_seconds=60)
    assert len(clusters) == 1


def test_cluster_signals_exact_boundary_is_included():
    signals = [
        _sig("process", STRONG, offset=0, source_id=1),
        _sig("persistence", STRONG, offset=60, source_id=2),
    ]
    clusters = cluster_signals(signals, window_seconds=60)
    assert len(clusters) == 1


# ---------- analysis.py: module combinations ----------


def test_distinct_modules():
    cluster = [_sig("process", STRONG, source_id=1), _sig("process", WEAK, source_id=2), _sig("wifi", WEAK, source_id=3)]
    assert distinct_modules(cluster) == {"process", "wifi"}


def test_has_meaningful_combo_true_for_known_pair():
    cluster = [_sig("process", WEAK, source_id=1), _sig("connections", WEAK, source_id=2)]
    assert has_meaningful_combo(cluster) is True


def test_has_meaningful_combo_false_for_ambient_pair():
    cluster = [_sig("ble", WEAK, source_id=1), _sig("inventory", WEAK, source_id=2)]
    assert has_meaningful_combo(cluster) is False


def test_has_meaningful_combo_false_for_single_module():
    cluster = [_sig("process", WEAK, source_id=1), _sig("process", STRONG, source_id=2)]
    assert has_meaningful_combo(cluster) is False


def test_max_strength():
    assert max_strength([_sig("a", WEAK, source_id=1), _sig("b", MEDIUM, source_id=2)]) == MEDIUM
    assert max_strength([_sig("a", WEAK, source_id=1), _sig("b", STRONG, source_id=2)]) == STRONG
    assert max_strength([_sig("a", WEAK, source_id=1)]) == WEAK


# ---------- analysis.py: scoring against the user's worked examples ----------


def test_score_ble_and_lan_device_is_low_or_informational():
    cluster = [_sig("ble", WEAK, source_id=1), _sig("inventory", WEAK, source_id=2)]
    score = correlation_score(cluster)
    severity = apply_weak_signal_cap(severity_for_score(score), cluster)
    assert severity in ("informational", "low")


def test_score_signed_process_and_endpoint_is_low_or_medium():
    cluster = [_sig("process", WEAK, source_id=1), _sig("connections", WEAK, source_id=2)]
    score = correlation_score(cluster)
    severity = apply_weak_signal_cap(severity_for_score(score), cluster)
    assert severity in ("low", "medium")


def test_score_unsigned_process_and_endpoint_is_medium_or_high():
    cluster = [_sig("process", STRONG, source_id=1), _sig("connections", WEAK, source_id=2)]
    score = correlation_score(cluster)
    severity = apply_weak_signal_cap(severity_for_score(score), cluster)
    assert severity in ("medium", "high")


def test_score_unsigned_process_and_persistence_is_high():
    cluster = [_sig("process", STRONG, source_id=1), _sig("persistence", STRONG, source_id=2)]
    score = correlation_score(cluster)
    severity = apply_weak_signal_cap(severity_for_score(score), cluster)
    assert severity == "high"


def test_score_process_persistence_connection_triple_is_critical():
    cluster = [
        _sig("process", STRONG, source_id=1),
        _sig("persistence", STRONG, source_id=2),
        _sig("connections", WEAK, source_id=3),
    ]
    score = correlation_score(cluster)
    severity = apply_weak_signal_cap(severity_for_score(score), cluster)
    assert severity == "critical"


def test_score_gateway_change_and_new_device_reaches_high():
    # The full worked example also includes a DNS change, which this
    # app has no signal source for yet (see PROJECT_NOTES.md) -- the
    # two-signal version should still land solidly high.
    cluster = [_sig("arpwatch", STRONG, source_id=1), _sig("inventory", WEAK, source_id=2)]
    score = correlation_score(cluster)
    severity = apply_weak_signal_cap(severity_for_score(score), cluster)
    assert severity in ("high", "critical")


# ---------- analysis.py: the weak-signal cap ----------


def test_weak_signal_cap_never_reaches_high():
    # Stack up enough weak signals across enough modules that the raw
    # score alone would cross into "high" territory.
    cluster = [
        _sig("ble", WEAK, source_id=1),
        _sig("inventory", WEAK, source_id=2),
        _sig("wifi", WEAK, source_id=3),
        _sig("bluetooth", WEAK, source_id=4),
        _sig("connections", WEAK, source_id=5),
    ]
    raw_severity = severity_for_score(correlation_score(cluster))
    assert raw_severity in ("high", "critical")  # confirms the cap is actually doing something
    capped = apply_weak_signal_cap(raw_severity, cluster)
    assert capped == "medium"


def test_weak_signal_cap_leaves_non_weak_clusters_alone():
    cluster = [_sig("process", STRONG, source_id=1), _sig("persistence", STRONG, source_id=2)]
    severity = severity_for_score(correlation_score(cluster))
    assert apply_weak_signal_cap(severity, cluster) == severity


def test_weak_signal_cap_allows_medium_for_all_weak():
    cluster = [_sig("process", WEAK, source_id=1), _sig("connections", WEAK, source_id=2)]
    # This combo scores into medium territory (meaningful pair bonus) --
    # confirm the cap doesn't push it down further than necessary.
    severity = apply_weak_signal_cap(severity_for_score(correlation_score(cluster)), cluster)
    assert severity in ("low", "medium")


# ---------- analysis.py: fingerprint + explanation ----------


def test_fingerprint_stable_and_order_independent():
    cluster_a = [_sig("process", STRONG, source_id=1), _sig("persistence", STRONG, source_id=2)]
    cluster_b = list(reversed(cluster_a))
    assert fingerprint_for_cluster(cluster_a) == fingerprint_for_cluster(cluster_b)


def test_fingerprint_differs_for_different_members():
    cluster_a = [_sig("process", STRONG, source_id=1), _sig("persistence", STRONG, source_id=2)]
    cluster_b = [_sig("process", STRONG, source_id=1), _sig("persistence", STRONG, source_id=3)]
    assert fingerprint_for_cluster(cluster_a) != fingerprint_for_cluster(cluster_b)


def test_build_explanation_contains_key_facts():
    cluster = [_sig("process", STRONG, source_id=1), _sig("persistence", STRONG, source_id=2)]
    score = correlation_score(cluster)
    severity = apply_weak_signal_cap(severity_for_score(score), cluster)
    text = build_explanation(cluster, score, score, severity, None)
    assert "process" in text
    assert "persistence" in text
    assert severity.upper() in text
    assert "not proof of a single cause" in text


def test_build_explanation_includes_context_notes_when_present():
    cluster = [_sig("process", WEAK, source_id=1), _sig("connections", WEAK, source_id=2)]
    text = build_explanation(cluster, 8, 5, "low", "Produced during a run-all sweep.")
    assert "Context: Produced during a run-all sweep." in text
    assert "reduced to 5" in text


# ---------- context.py ----------


def test_parse_boottime_output_valid():
    output = "{ sec = 1700000000, usec = 123456 } Wed Nov 15 00:00:00 2023\n"
    result = parse_boottime_output(output)
    assert result is not None
    assert result.timestamp() == 1700000000


def test_parse_boottime_output_empty_or_garbage():
    assert parse_boottime_output(None) is None
    assert parse_boottime_output("") is None
    assert parse_boottime_output("nonsense") is None


def test_is_recent_boot_true_within_window():
    boot_time = BASE_TIME - timedelta(minutes=2)
    assert is_recent_boot(BASE_TIME, boot_time, proximity_minutes=10) is True


def test_is_recent_boot_false_outside_window():
    boot_time = BASE_TIME - timedelta(minutes=30)
    assert is_recent_boot(BASE_TIME, boot_time, proximity_minutes=10) is False


def test_is_recent_boot_false_when_cluster_predates_boot():
    boot_time = BASE_TIME + timedelta(minutes=5)
    assert is_recent_boot(BASE_TIME, boot_time, proximity_minutes=10) is False


def test_is_recent_boot_false_when_boot_time_unknown():
    assert is_recent_boot(BASE_TIME, None) is False


def test_is_likely_update_or_install_matches_keyword():
    cluster = [_sig("process", WEAK, source_id=1, identifier="/tmp/Installer.app/Contents/MacOS/installer")]
    assert is_likely_update_or_install(cluster) is True


def test_is_likely_update_or_install_no_match():
    cluster = [_sig("process", WEAK, source_id=1, identifier="/usr/bin/true")]
    assert is_likely_update_or_install(cluster) is False


def test_apply_context_run_all_reduces_all_weak_cluster():
    cluster = [_sig("ble", WEAK, source_id=1), _sig("inventory", WEAK, source_id=2)]
    score, notes = apply_context(cluster, 10, RUN_ALL_TRIGGER, None, WEAK)
    assert score < 10
    assert notes is not None
    assert "run-all" in notes


def test_apply_context_run_all_does_not_reduce_strong_cluster():
    cluster = [_sig("process", STRONG, source_id=1), _sig("persistence", STRONG, source_id=2)]
    score, notes = apply_context(cluster, 12, RUN_ALL_TRIGGER, None, STRONG)
    assert score == 12  # annotated, but never discounted when a real finding is present
    assert notes is not None


def test_apply_context_boot_proximity_annotated_and_reduced_for_weak():
    cluster = [_sig("inventory", WEAK, source_id=1, offset=0)]
    boot_time = BASE_TIME - timedelta(minutes=1)
    score, notes = apply_context(cluster, 5, None, boot_time, WEAK)
    assert score < 5
    assert "started up" in notes


def test_apply_context_no_matches_returns_none_notes():
    cluster = [_sig("process", STRONG, source_id=1), _sig("persistence", STRONG, source_id=2)]
    score, notes = apply_context(cluster, 12, None, None, STRONG)
    assert score == 12
    assert notes is None


def test_apply_context_score_never_goes_negative():
    cluster = [_sig("ble", WEAK, source_id=1), _sig("inventory", WEAK, source_id=2)]
    boot_time = BASE_TIME
    score, _ = apply_context(cluster, 1, RUN_ALL_TRIGGER, boot_time, WEAK)
    assert score >= 0


# ---------- signals.py: collection against a seeded database ----------


def test_collect_signals_inventory_and_connections(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        upsert_device(db.conn, ip="192.168.1.50", mac="aa:bb:cc:dd:ee:ff", hostname=None, vendor=None)
        upsert_remote_endpoint(
            db.conn, remote_addr="1.2.3.4", remote_port=443, proto="tcp", process_name="curl"
        )
        signals = collect_signals(db.conn, lookback_hours=24)

    modules = {s.module for s in signals}
    assert "inventory" in modules
    assert "connections" in modules
    connections_signal = next(s for s in signals if s.module == "connections")
    assert connections_signal.strength == WEAK


def test_collect_signals_listening_strength_by_bind_scope(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        upsert_listening_service(
            db.conn, proto="tcp", bind_scope="network", process_name="sshd",
            identity_port="22", local_addr="0.0.0.0", local_port=22,
        )
        upsert_listening_service(
            db.conn, proto="tcp", bind_scope="localhost", process_name="dev-server",
            identity_port="ephemeral", local_addr="127.0.0.1", local_port=54321,
        )
        signals = collect_signals(db.conn, lookback_hours=24)

    listening_signals = [s for s in signals if s.module == "listening"]
    assert len(listening_signals) == 2
    strengths = {s.strength for s in listening_signals}
    assert STRONG in strengths
    assert MEDIUM in strengths


def test_collect_signals_arpwatch(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_arp_alert(
            db.conn, run_id="r1", kind="gateway_mac_changed", severity="high",
            ip="192.168.1.1", mac="11:22:33:44:55:66", previous_mac="aa:bb:cc:dd:ee:ff",
            message="gateway changed",
        )
        signals = collect_signals(db.conn, lookback_hours=24)

    arp_signals = [s for s in signals if s.module == "arpwatch"]
    assert len(arp_signals) == 1
    assert arp_signals[0].strength == STRONG


def test_collect_signals_wifi_dedupes_lookalike_against_bare_new(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        upsert_wifi_network(db.conn, ssid="HomeNetwokr", bssid="aa:bb:cc:dd:ee:ff")
        add_wifi_alert(
            db.conn, run_id="r1", kind="lookalike_ssid", severity="medium",
            ssid="HomeNetwokr", bssid="aa:bb:cc:dd:ee:ff", message="lookalike",
        )
        # A second, unrelated new network with no alert -- should still
        # show up as its own WEAK signal.
        upsert_wifi_network(db.conn, ssid="CoffeeShopWiFi", bssid=None)
        signals = collect_signals(db.conn, lookback_hours=24)

    wifi_signals = [s for s in signals if s.module == "wifi"]
    # Exactly two: the STRONG lookalike alert, and the WEAK new network --
    # NOT three (the lookalike SSID's bare-new row must be excluded).
    assert len(wifi_signals) == 2
    strengths_by_identifier = {s.identifier: s.strength for s in wifi_signals}
    assert strengths_by_identifier["HomeNetwokr"] == STRONG
    assert strengths_by_identifier["CoffeeShopWiFi"] == WEAK


def test_collect_signals_bluetooth_dedupes_alert_against_bare_new(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        upsert_bluetooth_device(db.conn, identifier="aa:bb:cc:dd:ee:ff", name="Unknown", rssi=-50)
        add_bluetooth_alert(
            db.conn, run_id="r1", kind="new_pairing", severity="high",
            identifier="aa:bb:cc:dd:ee:ff", name="Unknown", message="new pairing",
        )
        signals = collect_signals(db.conn, lookback_hours=24)

    bt_signals = [s for s in signals if s.module == "bluetooth"]
    assert len(bt_signals) == 1
    assert bt_signals[0].strength == STRONG
    assert bt_signals[0].kind == "new_pairing"


def test_collect_signals_ble_dedupes_alert_against_bare_new(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        upsert_ble_peripheral(db.conn, cb_uuid="1234-uuid", name="Tag", rssi=-40)
        add_ble_alert(
            db.conn, run_id="r1", kind="persistent_unknown", severity="low",
            cb_uuid="1234-uuid", name="Tag", message="keeps showing up",
        )
        signals = collect_signals(db.conn, lookback_hours=24)

    ble_signals = [s for s in signals if s.module == "ble"]
    assert len(ble_signals) == 1
    assert ble_signals[0].strength == WEAK


def test_collect_signals_process_strength(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        upsert_process_entry(
            db.conn, executable_path="/tmp/.hidden/tool", process_name="tool",
            run_as_user="erick", signing_status=UNSIGNED,
        )
        signals = collect_signals(db.conn, lookback_hours=24)

    process_signals = [s for s in signals if s.module == "process"]
    assert len(process_signals) == 1
    assert process_signals[0].strength == STRONG


def test_collect_signals_persistence_excludes_process_target_type(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        add_persistence_alert(
            db.conn, run_id="r1", kind="unusual_unsigned_process", severity="high",
            target_type="process", identifier="/tmp/tool", label=None, message="m",
        )
        add_persistence_alert(
            db.conn, run_id="r1", kind="new_persistence_entry", severity="medium",
            target_type="launch_agent_user", identifier="/x.plist", label="com.example.agent",
            message="m",
        )
        signals = collect_signals(db.conn, lookback_hours=24)

    # Only the launch_agent_user alert should surface as a "persistence"
    # signal -- the "process" target_type alert is deliberately excluded
    # here (process_entries is the sole source for the process dimension).
    persistence_signals = [s for s in signals if s.module == "persistence"]
    assert len(persistence_signals) == 1
    assert persistence_signals[0].identifier == "/x.plist"


def test_collect_signals_upgrades_endpoint_from_matching_unsigned_process(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        upsert_process_entry(
            db.conn, executable_path="/tmp/.hidden/tool", process_name="tool",
            run_as_user="erick", signing_status=UNSIGNED,
        )
        upsert_remote_endpoint(
            db.conn, remote_addr="5.6.7.8", remote_port=4444, proto="tcp", process_name="tool"
        )
        signals = collect_signals(db.conn, lookback_hours=24)

    connections_signal = next(s for s in signals if s.module == "connections")
    assert connections_signal.strength == STRONG
    assert connections_signal.kind == "new_remote_endpoint_from_untrusted_process"


def test_collect_signals_does_not_upgrade_endpoint_for_unrelated_process(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        upsert_process_entry(
            db.conn, executable_path="/tmp/.hidden/tool", process_name="tool",
            run_as_user="erick", signing_status=UNSIGNED,
        )
        upsert_remote_endpoint(
            db.conn, remote_addr="5.6.7.8", remote_port=443, proto="tcp", process_name="Safari"
        )
        signals = collect_signals(db.conn, lookback_hours=24)

    connections_signal = next(s for s in signals if s.module == "connections")
    assert connections_signal.strength == WEAK


def test_collect_signals_respects_lookback_window(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        upsert_device(db.conn, ip="192.168.1.50", mac="aa:bb:cc:dd:ee:ff", hostname=None, vendor=None)
        # A negative lookback window means "nothing from before right
        # now" -- effectively excludes the row just inserted.
        signals = collect_signals(db.conn, lookback_hours=-1)

    assert signals == []


# ---------- scanner.py: end-to-end correlate() ----------


def test_correlate_end_to_end_finds_cross_module_cluster(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        upsert_process_entry(
            db.conn, executable_path="/tmp/.hidden/tool", process_name="tool",
            run_as_user="erick", signing_status=UNSIGNED,
        )
        add_persistence_alert(
            db.conn, run_id="r1", kind="new_persistence_entry", severity="high",
            target_type="launch_agent_user", identifier="/x.plist", label="com.example.agent",
            message="m",
        )
        result = correlate(db.conn, window_seconds=60, lookback_hours=24)

    assert result.cross_module_clusters == 1
    assert len(result.new_alerts) == 1
    assert result.new_alerts[0].severity == "high"
    assert result.new_alerts[0].module_count == 2


def test_correlate_single_module_cluster_is_not_alerted(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        upsert_device(db.conn, ip="192.168.1.50", mac="aa:bb:cc:dd:ee:ff", hostname=None, vendor=None)
        upsert_device(db.conn, ip="192.168.1.51", mac="aa:bb:cc:dd:ee:00", hostname=None, vendor=None)
        result = correlate(db.conn, window_seconds=60, lookback_hours=24)

    assert result.cross_module_clusters == 0
    assert result.new_alerts == []


def test_correlate_is_idempotent_on_rerun(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        upsert_process_entry(
            db.conn, executable_path="/tmp/.hidden/tool", process_name="tool",
            run_as_user="erick", signing_status=UNSIGNED,
        )
        add_persistence_alert(
            db.conn, run_id="r1", kind="new_persistence_entry", severity="high",
            target_type="launch_agent_user", identifier="/x.plist", label="com.example.agent",
            message="m",
        )
        first = correlate(db.conn)
        second = correlate(db.conn)
        stored = list_correlation_alerts(db.conn)

    assert len(first.new_alerts) == 1
    assert len(second.new_alerts) == 0
    assert second.already_known_clusters == 1
    assert len(stored) == 1


def test_correlate_threads_triggered_by_into_context_notes(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        upsert_device(db.conn, ip="192.168.1.50", mac="aa:bb:cc:dd:ee:ff", hostname=None, vendor=None)
        upsert_remote_endpoint(
            db.conn, remote_addr="1.2.3.4", remote_port=443, proto="tcp", process_name="curl"
        )
        result = correlate(db.conn, triggered_by=RUN_ALL_TRIGGER)

    assert result.triggered_by == RUN_ALL_TRIGGER
    if result.new_alerts:
        assert result.new_alerts[0].triggered_by == RUN_ALL_TRIGGER


# ---------- storage round-trips: correlation_alerts ----------


def test_add_correlation_alert_insert_then_idempotent_reinsert(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        record1, was_new1 = add_correlation_alert(
            db.conn, run_id="r1", fingerprint="fp-1", window_seconds=60.0,
            cluster_start="2026-01-01T00:00:00+00:00", cluster_end="2026-01-01T00:00:30+00:00",
            module_count=2, signal_count=2, score=12, severity="high",
            triggered_by=None, context_notes=None, explanation="because reasons",
            members=[{"module": "process", "kind": "new_process"}],
        )
        record2, was_new2 = add_correlation_alert(
            db.conn, run_id="r2", fingerprint="fp-1", window_seconds=60.0,
            cluster_start="2026-01-01T00:00:00+00:00", cluster_end="2026-01-01T00:00:30+00:00",
            module_count=2, signal_count=2, score=99, severity="critical",
            triggered_by=None, context_notes=None, explanation="different call, same fingerprint",
            members=[],
        )
        alerts = list_correlation_alerts(db.conn)

    assert was_new1 is True
    assert was_new2 is False
    assert record2.id == record1.id
    assert record2.score == 12  # the SECOND call was ignored -- original values preserved
    assert len(alerts) == 1
    assert alerts[0].members == [{"module": "process", "kind": "new_process"}]


def test_set_correlation_alert_known(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        record, _ = add_correlation_alert(
            db.conn, run_id="r1", fingerprint="fp-2", window_seconds=60.0,
            cluster_start="2026-01-01T00:00:00+00:00", cluster_end="2026-01-01T00:00:30+00:00",
            module_count=2, signal_count=2, score=10, severity="high",
            triggered_by=None, context_notes=None, explanation="e", members=[],
        )
        assert record.known is False
        set_correlation_alert_known(db.conn, record.id, True)
        updated = find_correlation_alert_by_id(db.conn, record.id)

    assert updated.known is True


def test_find_correlation_alert_by_id_missing_is_none(tmp_path: Path):
    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        assert find_correlation_alert_by_id(db.conn, 9999) is None
