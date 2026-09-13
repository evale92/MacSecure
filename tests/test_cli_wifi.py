"""
Tests for `secure/cli/wifi.py` — the five `cmd_wifi_*` handlers, and the
`_format_bssid()` helper, that no test in this repository had ever
executed.

Why this file exists, as a measurement rather than a grep. The module
defines five handlers plus one helper. Not one of the six had a single
test call site: the names `cmd_wifi_scan`, `cmd_wifi_list`,
`cmd_wifi_mark`, `cmd_wifi_alerts`, `cmd_wifi_mark_alert` and
`_format_bssid` did not appear anywhere under tests/ in any form, not
even inside a docstring, and no test drove the `wifi` subcommand
through `main()`. That is a stronger starting point than the sibling
modules had — `secure/cli/correlate.py` (J-0317) and
`secure/cli/persistence.py` (J-0300) each had at least one handler
already reached — so this module's whole command family was dark.

Verified by mutant, not by grep. Each of the six was given a crashing
first statement (a call to an undefined `_NEVER_RUN_MARKER_CLI_WIFI()`)
and the full suite was run at a07b23f. Because no handler here was
expected to be reached, the experiment carries its own positive
control: `secure/storage/models/wifi.py::list_wifi_networks` — measured
beforehand at five real, non-monkeypatched test call sites — was given
a `_POSITIVE_CONTROL_MARKER()` in the same run. The control was killed
and the six markers in this module were not, which is what makes the
silence of the six evidence of never being executed rather than
evidence of a mutation that does nothing.

Note for anyone re-running the underexamination score against this
module: unlike the last several in this class, its stated reason
("untested = no test imports or runs it") is *correct* here — but only
by accident of where the re-export leads. The score gave the same
reason for `secure/storage/models/ble.py` and
`secure/storage/models/wifi.py`, ranked above this one, and for those
two it is wrong: every public function in both has real call sites via
the `secure/storage/models/__init__.py` re-export. Two wrong, one
right, and the right one ranked third.

What each test below pins, and why it is worth pinning:

  * **The three-way Wi-Fi status outcome, which is the module's one
    security-load-bearing branch.** `secure/wifi/status.py`'s
    `get_wifi_status()` docstring, and a comment in `cmd_wifi_scan`
    itself, both insist that "couldn't tell" must never be reported as
    "confirmed not connected." Nothing enforced it. The three outcomes
    are asserted separately and, for the unknown case, negatively as
    well: the handler must exit 1 *and* must not print the
    not-connected wording. A collapse of `status_unknown` into the
    ordinary disconnected branch would be a sensor failure reported as
    a clean pass — the same shape of defect CLAUDE.md names as the
    worst one for a security tool.

  * **Every disjunct of the scan exit code.** `cmd_wifi_scan` ends in
    `return 1 if result.is_new_network or result.security_severity or
    result.alerts else 0`. Each of the three is asserted alone, with
    the other two false, plus the all-clear case that must return 0 —
    because "returns 1 on a new network" is equally satisfied by a
    handler that always returns 1.

  * **All three `_format_bssid()` branches.** The permission branch
    exists so the CLI says "permission required" only when macOS
    actually withheld the BSSID for that reason, per the
    `bssid_unavailable_reason` field's own comment. The generic branch
    is asserted to *not* claim a permission problem, so the two cannot
    quietly merge into one message that blames Location Services for
    every missing BSSID.

  * **The alert-review audit trail, and the line it is not on both
    sides of.** `cmd_wifi_mark_alert` calls
    `_record_alert_review_change()` (the append-only record of a human
    changing an alert's review state, Product Phase 13) and had never
    run. Its three cases are pinned: a real transition writes exactly
    one event, a no-op re-mark writes none, and an alert that does not
    exist writes none and exits 1. `cmd_wifi_mark` — the *network*
    handler, one screen above it in the same file, with a nearly
    identical body — deliberately writes no event, and that asymmetry
    is asserted too, so it stays a decision rather than something a
    later reader "fixes" symmetrically.

The scanner seam: `secure/cli/wifi.py` does `from secure.wifi import
scan_wifi` at import time, so it holds its own reference. Patching
`secure.wifi.scan_wifi` would miss it entirely. These tests patch the
name on `secure.cli.wifi`, assert up front that the attribute is still
there, and assert the fake was actually called — so a wrong seam fails
loudly instead of quietly running a real Wi-Fi scan against the
operator's actual machine.

Run with:  pytest tests/test_cli_wifi.py
"""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path

from secure import cli
from secure.cli import wifi as cli_wifi
from secure.config import load_config
from secure.storage.database import Database
from secure.storage.models import (
    add_wifi_alert,
    count_events,
    find_wifi_alert_by_id,
    find_wifi_network_by_id,
    list_events,
    list_wifi_networks,
    set_wifi_network_known,
    upsert_wifi_network,
)
from secure.wifi.scanner import WifiAlert, WifiScanResult
from secure.wifi.status import WifiStatus


def _bootstrap_to_tmp(monkeypatch, tmp_path: Path):
    """Point `_bootstrap()` at an isolated temp app_dir, never ~/.secure.
    Same approach as tests/test_cli_correlate.py and
    tests/test_cli_alert_history.py."""
    monkeypatch.setattr(cli, "load_config", lambda: load_config(app_dir=tmp_path))
    return load_config(app_dir=tmp_path)


def _run(fn, *args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn(*args)
    return rc, buf.getvalue()


def _status(**overrides) -> WifiStatus:
    fields = dict(
        connected=True,
        status_unknown=False,
        interface="en0",
        ssid="HomeNet",
        bssid="aa:bb:cc:dd:ee:ff",
        bssid_available=True,
        bssid_unavailable_reason=None,
        channel="149",
        phy_mode="802.11ax",
        security="WPA3 Personal",
        rssi=-52,
        noise=-92,
    )
    fields.update(overrides)
    return WifiStatus(**fields)


def _result(network_record=None, **overrides) -> WifiScanResult:
    fields = dict(
        scanned_at="2026-09-12T00:00:00+00:00",
        run_id="run1",
        connected=True,
        status=_status(),
        network_record=network_record,
        is_new_network=False,
        other_bssids_for_ssid=[],
        security_severity=None,
        security_note="WPA3 Personal — strong.",
        alerts=[],
    )
    fields.update(overrides)
    return WifiScanResult(**fields)


def _patch_scan(monkeypatch, result: WifiScanResult) -> list:
    """Replace the reference `secure/cli/wifi.py` actually calls.

    Returns a call log the test asserts on, so patching the wrong seam
    — and thereby running a real Wi-Fi scan against the machine the
    suite happens to be on — cannot pass silently.
    """
    assert hasattr(cli_wifi, "scan_wifi"), (
        "secure/cli/wifi.py no longer binds scan_wifi at import; "
        "this test patches the wrong seam"
    )
    calls: list = []

    def fake_scan_wifi(conn):
        calls.append(conn)
        return result

    monkeypatch.setattr(cli_wifi, "scan_wifi", fake_scan_wifi)
    return calls


def _seed_network(cfg, ssid="HomeNet", bssid="aa:bb:cc:dd:ee:ff"):
    with Database(cfg.database_path()) as db:
        record, _ = upsert_wifi_network(db.conn, ssid, bssid)
    return record


def _seed_alert(cfg, ssid="HomeNet", severity="medium", kind="similar_ssid"):
    with Database(cfg.database_path()) as db:
        return add_wifi_alert(
            db.conn, "run1", kind, severity, ssid, "aa:bb:cc:dd:ee:ff",
            f"'{ssid}' closely resembles a known network name.",
        )


# ---------- cmd_wifi_scan: the three-way status outcome ----------


def test_scan_status_unknown_exits_nonzero_and_never_claims_disconnected(tmp_path, monkeypatch):
    """"Couldn't tell" is a sensor failure, not a clean pass.

    secure/wifi/status.py's get_wifi_status() docstring and the comment
    inside cmd_wifi_scan both require this outcome to stay distinct
    from a confirmed disconnection. Asserted negatively as well as
    positively: collapsing the two would make an all-sources-failed
    scan exit 0 with "Not currently connected", which no caller could
    tell apart from the real thing.
    """
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    calls = _patch_scan(
        monkeypatch,
        _result(connected=False, status=_status(connected=False, status_unknown=True, ssid=None)),
    )

    rc, out = _run(cli_wifi.cmd_wifi_scan, argparse.Namespace())

    assert calls, "scan_wifi was never called — the patched seam is wrong"
    assert rc == 1
    assert "could not determine Wi-Fi status" in out
    assert "NOT the same as" in out
    assert "Not currently connected" not in out
    assert cfg.database_path().exists()


def test_scan_confirmed_not_connected_is_a_clean_pass(tmp_path, monkeypatch):
    """A confirmed disconnection is a normal state: exit 0, and it must
    not borrow the sensor-failure wording."""
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    calls = _patch_scan(
        monkeypatch,
        _result(connected=False, status=_status(connected=False, status_unknown=False, ssid=None)),
    )

    rc, out = _run(cli_wifi.cmd_wifi_scan, argparse.Namespace())

    assert calls, "scan_wifi was never called — the patched seam is wrong"
    assert rc == 0
    assert "Not currently connected to any Wi-Fi network." in out
    assert "could not determine Wi-Fi status" not in out


def test_scan_connected_but_ssid_undetermined_exits_nonzero(tmp_path, monkeypatch):
    """Connected with no resolvable SSID records nothing, so it must not
    report success — the third of the three outcomes the handler's own
    comment says are deliberately not collapsed."""
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    calls = _patch_scan(
        monkeypatch,
        _result(connected=True, status=_status(connected=True, ssid=None)),
    )

    rc, out = _run(cli_wifi.cmd_wifi_scan, argparse.Namespace())

    assert calls, "scan_wifi was never called — the patched seam is wrong"
    assert rc == 1
    assert "could not be determined" in out
    assert "Nothing was recorded" in out
    assert "Not currently connected" not in out


# ---------- cmd_wifi_scan: every disjunct of the exit code ----------


def test_scan_all_clear_exits_zero(tmp_path, monkeypatch):
    """The baseline the three nonzero cases below are measured against:
    a known network, no severity, no alerts, exit 0."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    record = _seed_network(cfg)
    calls = _patch_scan(monkeypatch, _result(network_record=record))

    rc, out = _run(cli_wifi.cmd_wifi_scan, argparse.Namespace())

    assert calls, "scan_wifi was never called — the patched seam is wrong"
    assert rc == 0
    assert "SSID:     HomeNet" in out
    assert "BSSID:    aa:bb:cc:dd:ee:ff" in out
    assert "Signal:   -52 dBm, noise -92 dBm" in out
    assert "[UNKNOWN] HomeNet" in out  # upsert records known=False
    assert "ALERTS" not in out


def test_scan_new_network_alone_exits_nonzero(tmp_path, monkeypatch):
    """First disjunct, with the other two false."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    record = _seed_network(cfg)
    _patch_scan(
        monkeypatch,
        _result(network_record=record, is_new_network=True, security_severity=None, alerts=[]),
    )

    rc, out = _run(cli_wifi.cmd_wifi_scan, argparse.Namespace())

    assert rc == 1
    assert "[NEW] HomeNet" in out
    assert f"secure wifi mark {record.id} known|unknown" in out


def test_scan_security_severity_alone_exits_nonzero(tmp_path, monkeypatch):
    """Second disjunct, with the other two false. An open network is the
    case this exists for: nothing is new and nothing alerted, but the
    connection is still worth a nonzero exit."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    record = _seed_network(cfg)
    _patch_scan(
        monkeypatch,
        _result(
            network_record=record,
            is_new_network=False,
            security_severity="high",
            security_note="Open network — traffic is unencrypted.",
            alerts=[],
        ),
    )

    rc, out = _run(cli_wifi.cmd_wifi_scan, argparse.Namespace())

    assert rc == 1
    assert "[HIGH] Open network — traffic is unencrypted." in out
    assert "[NEW]" not in out


def test_scan_alerts_alone_exit_nonzero_and_are_listed(tmp_path, monkeypatch):
    """Third disjunct, with the other two false, plus the review hint —
    an alert the operator is never told how to act on is an alert that
    stays unreviewed forever."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    record = _seed_network(cfg)
    alert = WifiAlert(
        kind="similar_ssid", severity="medium", ssid="H0meNet",
        bssid="11:22:33:44:55:66", message="'H0meNet' closely resembles known network 'HomeNet'.",
        id=7,
    )
    _patch_scan(
        monkeypatch,
        _result(network_record=record, is_new_network=False, security_severity=None, alerts=[alert]),
    )

    rc, out = _run(cli_wifi.cmd_wifi_scan, argparse.Namespace())

    assert rc == 1
    assert "ALERTS (1):" in out
    assert "#7 [MEDIUM] similar_ssid — H0meNet" in out
    assert "closely resembles known network" in out
    assert "secure wifi mark-alert <id> known|unknown" in out


def test_scan_other_bssids_line_appears_only_for_a_new_network(tmp_path, monkeypatch):
    """The impersonating-access-point hint is printed only inside the
    is_new_network branch. Asserted in both directions so the
    suppression stays deliberate rather than incidental."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    record = _seed_network(cfg)

    _patch_scan(
        monkeypatch,
        _result(network_record=record, is_new_network=True, other_bssids_for_ssid=["99:88:77:66:55:44"]),
    )
    rc_new, out_new = _run(cli_wifi.cmd_wifi_scan, argparse.Namespace())

    _patch_scan(
        monkeypatch,
        _result(network_record=record, is_new_network=False, other_bssids_for_ssid=["99:88:77:66:55:44"]),
    )
    rc_old, out_old = _run(cli_wifi.cmd_wifi_scan, argparse.Namespace())

    assert rc_new == 1
    assert "other access points on record: 99:88:77:66:55:44" in out_new
    assert "impersonating" in out_new

    assert rc_old == 0
    assert "other access points on record" not in out_old


# ---------- _format_bssid: all three branches ----------


def test_format_bssid_returns_the_bssid_when_available():
    assert _bssid_line(bssid="aa:bb:cc:dd:ee:ff", available=True) == "aa:bb:cc:dd:ee:ff"


def test_format_bssid_blames_location_services_only_for_a_permission_denial():
    """The permission wording exists because macOS withholds the BSSID
    specifically when Location Services is not granted (see
    WifiStatus.bssid_unavailable_reason). Every *other* reason —
    `airport` missing, a parse failure — must not be reported as a
    permission problem, or the operator is sent to fix a setting that
    was never the cause."""
    permission = _bssid_line(bssid=None, available=False, reason="permission")
    other = _bssid_line(bssid=None, available=False, reason=None)

    assert "permission required" in permission
    assert "Location Services" in permission

    assert other == "Unavailable — could not be determined"
    assert "permission" not in other
    assert "Location Services" not in other


def _bssid_line(*, bssid, available, reason=None) -> str:
    return cli_wifi._format_bssid(
        _status(bssid=bssid, bssid_available=available, bssid_unavailable_reason=reason)
    )


# ---------- cmd_wifi_list ----------


def test_list_on_an_empty_database_says_so_and_exits_zero(tmp_path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)

    rc, out = _run(cli_wifi.cmd_wifi_list, argparse.Namespace())

    assert rc == 0
    assert "No Wi-Fi networks recorded yet" in out
    assert "secure wifi scan" in out


def test_list_tags_each_network_known_or_unknown(tmp_path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    known = _seed_network(cfg, "HomeNet", "aa:bb:cc:dd:ee:ff")
    unknown = _seed_network(cfg, "CoffeeShop", None)
    with Database(cfg.database_path()) as db:
        set_wifi_network_known(db.conn, known.id, True)

    rc, out = _run(cli_wifi.cmd_wifi_list, argparse.Namespace())

    assert rc == 0
    assert f"[KNOWN  ] #{known.id}" in out
    assert f"[UNKNOWN] #{unknown.id}" in out
    assert "CoffeeShop (BSSID unknown)" in out
    assert "first seen" in out and "last seen" in out


# ---------- cmd_wifi_mark ----------


def test_mark_sets_known_and_confirms_by_ssid(tmp_path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    record = _seed_network(cfg)

    rc, out = _run(
        cli_wifi.cmd_wifi_mark, argparse.Namespace(network_id=record.id, status="known")
    )

    assert rc == 0
    assert f"Marked #{record.id} (HomeNet) as known." in out
    with Database(cfg.database_path()) as db:
        assert find_wifi_network_by_id(db.conn, record.id).known is True


def test_mark_unknown_reverses_it(tmp_path, monkeypatch):
    """Both directions, because "sets known" is equally satisfied by a
    handler that writes 1 unconditionally."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    record = _seed_network(cfg)

    _run(cli_wifi.cmd_wifi_mark, argparse.Namespace(network_id=record.id, status="known"))
    rc, out = _run(
        cli_wifi.cmd_wifi_mark, argparse.Namespace(network_id=record.id, status="unknown")
    )

    assert rc == 0
    assert "as unknown." in out
    with Database(cfg.database_path()) as db:
        assert find_wifi_network_by_id(db.conn, record.id).known is False


def test_mark_a_network_that_does_not_exist_exits_one_and_changes_nothing(tmp_path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    record = _seed_network(cfg)

    rc, out = _run(cli_wifi.cmd_wifi_mark, argparse.Namespace(network_id=999, status="known"))

    assert rc == 1
    assert "No Wi-Fi network found with id 999" in out
    assert "secure wifi list" in out
    with Database(cfg.database_path()) as db:
        assert find_wifi_network_by_id(db.conn, record.id).known is False
        assert len(list_wifi_networks(db.conn)) == 1


def test_marking_a_network_writes_no_alert_review_event(tmp_path, monkeypatch):
    """The asymmetry between the two mark handlers, asserted so it stays
    a decision.

    cmd_wifi_mark_alert records an append-only review-state change;
    cmd_wifi_mark, one screen above it with a nearly identical body,
    does not — a network's known flag is a preference, not a reviewed
    finding. Without this test the two bodies look like an oversight
    waiting to be made symmetric.
    """
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    record = _seed_network(cfg)

    rc, _ = _run(cli_wifi.cmd_wifi_mark, argparse.Namespace(network_id=record.id, status="known"))

    assert rc == 0
    with Database(cfg.database_path()) as db:
        assert count_events(db.conn) == 0


# ---------- cmd_wifi_alerts ----------


def test_alerts_on_an_empty_database_says_so_and_exits_zero(tmp_path, monkeypatch):
    _bootstrap_to_tmp(monkeypatch, tmp_path)

    rc, out = _run(cli_wifi.cmd_wifi_alerts, argparse.Namespace())

    assert rc == 0
    assert "No wifi alerts recorded yet" in out


def test_alerts_lists_each_alert_with_its_review_state(tmp_path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    alert_id = _seed_alert(cfg, ssid="H0meNet", severity="medium")

    rc, out = _run(cli_wifi.cmd_wifi_alerts, argparse.Namespace())

    assert rc == 0
    assert f"[UNKNOWN] #{alert_id}" in out
    assert "[MEDIUM]" in out
    assert "similar_ssid — H0meNet" in out
    assert "closely resembles" in out


# ---------- cmd_wifi_mark_alert: the audit trail ----------


def test_mark_alert_records_exactly_one_review_change(tmp_path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    alert_id = _seed_alert(cfg, ssid="H0meNet", severity="medium")

    rc, out = _run(
        cli_wifi.cmd_wifi_mark_alert, argparse.Namespace(alert_id=alert_id, status="known")
    )

    assert rc == 0
    assert f"Marked #{alert_id} (similar_ssid, H0meNet) as known." in out

    with Database(cfg.database_path()) as db:
        assert find_wifi_alert_by_id(db.conn, alert_id).known is True
        review = [e for e in list_events(db.conn) if e.category == "alert_review_change"]

    assert len(review) == 1
    assert f"wifi_alerts alert #{alert_id}" in review[0].message
    assert "(H0meNet)" in review[0].message
    assert "severity=medium" in review[0].message
    assert "UNKNOWN -> KNOWN" in review[0].message


def test_mark_alert_records_the_reverse_transition_too(tmp_path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    alert_id = _seed_alert(cfg)

    _run(cli_wifi.cmd_wifi_mark_alert, argparse.Namespace(alert_id=alert_id, status="known"))
    rc, _ = _run(
        cli_wifi.cmd_wifi_mark_alert, argparse.Namespace(alert_id=alert_id, status="unknown")
    )

    assert rc == 0
    with Database(cfg.database_path()) as db:
        assert count_events(db.conn) == 2  # unbounded, unlike list_events' LIMIT 20
        assert find_wifi_alert_by_id(db.conn, alert_id).known is False
        review = [e for e in list_events(db.conn) if e.category == "alert_review_change"]

    # list_events() is newest-first, so the reverse transition comes back first.
    assert [e.message.split(": ")[-1] for e in review] == ["KNOWN -> UNKNOWN", "UNKNOWN -> KNOWN"]


def test_re_marking_an_alert_the_same_way_records_nothing(tmp_path, monkeypatch):
    """`if alert.known != known` is the guard _record_alert_review_change's
    own docstring asks every caller to apply. Re-marking is idempotent,
    so the history must not accumulate a row that records no change."""
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)
    alert_id = _seed_alert(cfg)

    _run(cli_wifi.cmd_wifi_mark_alert, argparse.Namespace(alert_id=alert_id, status="known"))
    rc, _ = _run(
        cli_wifi.cmd_wifi_mark_alert, argparse.Namespace(alert_id=alert_id, status="known")
    )

    assert rc == 0
    with Database(cfg.database_path()) as db:
        review = [e for e in list_events(db.conn) if e.category == "alert_review_change"]

    assert len(review) == 1


def test_mark_alert_that_does_not_exist_exits_one_and_records_nothing(tmp_path, monkeypatch):
    cfg = _bootstrap_to_tmp(monkeypatch, tmp_path)

    rc, out = _run(cli_wifi.cmd_wifi_mark_alert, argparse.Namespace(alert_id=999, status="known"))

    assert rc == 1
    assert "No wifi alert found with id 999" in out
    assert "secure wifi alerts" in out
    with Database(cfg.database_path()) as db:
        assert count_events(db.conn) == 0
