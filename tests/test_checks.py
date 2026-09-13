"""
Tests for secure/checks/*.

These deliberately avoid depending on real macOS commands (fdesetup,
spctl, csrutil, ...) so the test suite passes on any machine —
including CI and non-Mac dev boxes. Each check module separates
"parse this output" (a pure function, e.g. `_evaluate`) from "go run
the command" specifically so it can be tested this way.

Run with:  pytest
"""

from __future__ import annotations

import socket

from secure.checks.filevault import _evaluate as evaluate_filevault
from secure.checks.filevault import check_filevault
from secure.checks.firewall import _evaluate as evaluate_firewall
from secure.checks.firewall import check_firewall
from secure.checks.gatekeeper import _evaluate as evaluate_gatekeeper
from secure.checks.gatekeeper import check_gatekeeper
from secure.checks.models import CheckStatus
from secure.checks.os_version import check_os_version
from secure.checks.runner import run_all_checks
from secure.checks.sharing import _port_is_listening
from secure.checks.sip import _evaluate as evaluate_sip
from secure.checks.sip import check_sip
from secure.checks.software_update import (
    _evaluate_automatic_updates,
    _evaluate_pending_updates,
    check_automatic_updates,
)

# ---------- FileVault ----------


def test_filevault_on():
    result = evaluate_filevault("FileVault is On.")
    assert result.status == CheckStatus.PASS


def test_filevault_off():
    result = evaluate_filevault("FileVault is Off.")
    assert result.status == CheckStatus.FAIL
    assert result.remediation


def test_filevault_unparseable():
    result = evaluate_filevault("some unexpected output")
    assert result.status == CheckStatus.WARNING


# ---------- Firewall ----------


def test_firewall_enabled():
    result = evaluate_firewall("Firewall is enabled. (State = 1)")
    assert result.status == CheckStatus.PASS


def test_firewall_disabled():
    result = evaluate_firewall("Firewall is disabled. (State = 0)")
    assert result.status == CheckStatus.FAIL


def test_firewall_unparseable():
    result = evaluate_firewall("")
    assert result.status == CheckStatus.WARNING


# ---------- Gatekeeper ----------


def test_gatekeeper_enabled():
    result = evaluate_gatekeeper("assessments enabled")
    assert result.status == CheckStatus.PASS


def test_gatekeeper_disabled():
    result = evaluate_gatekeeper("assessments disabled")
    assert result.status == CheckStatus.FAIL


# ---------- SIP ----------


def test_sip_enabled():
    result = evaluate_sip("System Integrity Protection status: enabled.")
    assert result.status == CheckStatus.PASS


def test_sip_disabled():
    result = evaluate_sip("System Integrity Protection status: disabled.")
    assert result.status == CheckStatus.FAIL


# ---------- Automatic / pending updates ----------


def test_automatic_updates_all_on():
    result = _evaluate_automatic_updates(check_enabled=True, critical_install=True)
    assert result.status == CheckStatus.PASS


def test_automatic_updates_checking_off():
    result = _evaluate_automatic_updates(check_enabled=False, critical_install=True)
    assert result.status == CheckStatus.WARNING
    assert "checking for updates" in result.message


def test_automatic_updates_unknown():
    result = _evaluate_automatic_updates(check_enabled=None, critical_install=None)
    assert result.status == CheckStatus.WARNING


# A preference that could not be read is not a preference that is on.
# The PASS branch's message asserts *both* settings are enabled, so it
# may only be reached when both were actually read — one None is enough
# to disqualify it. `test_automatic_updates_all_on` above is the
# positive control that these two do not simply pass by never reaching
# PASS at all.


def test_automatic_updates_one_unreadable_pref_does_not_pass():
    for check_enabled, critical_install, expected_key in (
        (None, True, "AutomaticCheckEnabled"),
        (True, None, "CriticalUpdateInstall"),
    ):
        result = _evaluate_automatic_updates(
            check_enabled=check_enabled, critical_install=critical_install
        )
        assert result.status == CheckStatus.WARNING, (check_enabled, critical_install)
        assert expected_key in result.message, result.message
        assert result.remediation != ""


def test_automatic_updates_definite_off_wins_over_unreadable():
    # (False, None): one setting read as off, one unreadable. The off
    # one is the actionable finding and must not be masked by the
    # "could not read" branch.
    result = _evaluate_automatic_updates(check_enabled=False, critical_install=None)
    assert result.status == CheckStatus.WARNING
    assert "checking for updates" in result.message
    assert "turned off" in result.message


def test_pending_updates_none():
    result = _evaluate_pending_updates("No new software available.")
    assert result.status == CheckStatus.PASS


def test_pending_updates_found():
    output = (
        "Software Update Tool\n\n"
        "* Label: macOS Sequoia Update-15.1\n"
        "\tTitle: macOS Sequoia Update, Version: 15.1, Recommended: YES\n"
    )
    result = _evaluate_pending_updates(output)
    assert result.status == CheckStatus.WARNING
    assert "macOS Sequoia Update" in result.message


def test_pending_updates_unrecognized():
    result = _evaluate_pending_updates("something we've never seen before")
    assert result.status == CheckStatus.WARNING


# ---------- Sharing (real loopback sockets, no macOS-specific commands) ----------


def test_port_is_listening_true():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        assert _port_is_listening(port) is True
    finally:
        server.close()


def test_port_is_listening_false():
    # Bind to get a free port, then close it immediately so (almost
    # certainly) nothing is listening there anymore.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    free_port = probe.getsockname()[1]
    probe.close()

    assert _port_is_listening(free_port, timeout=0.2) is False


# ---------- macOS version ----------
#
# The only check in _SINGLE_CHECKS with no `_evaluate` seam: it reads
# platform.mac_ver() directly, so there is no pure function for the
# pattern this file's docstring describes to grab hold of. That is why
# it went untested. The seam that does exist is platform.mac_ver
# itself, patched on the module object the check reads it from and
# undone by the monkeypatch fixture.


def test_os_version_reports_the_running_version(monkeypatch):
    import secure.checks.os_version as os_version_module

    monkeypatch.setattr(
        os_version_module.platform, "mac_ver", lambda: ("15.4.1", ("", "", ""), "arm64")
    )

    result = check_os_version()

    assert result.status == CheckStatus.PASS
    assert "15.4.1" in result.message


def test_os_version_absent_is_a_warning_not_a_clean_pass(monkeypatch):
    # Invariant 5 / TESTING_POLICY rule 9: platform.mac_ver() returns an
    # empty version on a non-macOS host, and the honest answer there is
    # "could not determine", never a PASS row in the posture report.
    import secure.checks.os_version as os_version_module

    monkeypatch.setattr(
        os_version_module.platform, "mac_ver", lambda: ("", ("", "", ""), "")
    )

    result = check_os_version()

    assert result.status == CheckStatus.WARNING
    assert result.remediation


# ---------- Runner resilience ----------


def test_single_checks_roster_is_exactly_the_posture_check_set():
    # Both runner tests below replace _SINGLE_CHECKS wholesale, so
    # nothing else in the suite reads the real roster: measured against
    # a scratch copy, dropping check_os_version from it — or deleting
    # secure/checks/os_version.py outright — left this file at 20
    # passed. Pinning identity and order here is what makes a check
    # silently falling out of `secure check` a test failure.
    import secure.checks.runner as runner_module

    assert runner_module._SINGLE_CHECKS == [
        check_os_version,
        check_filevault,
        check_firewall,
        check_gatekeeper,
        check_sip,
        check_automatic_updates,
    ]


def test_run_all_checks_survives_a_crashing_check(monkeypatch):
    def boom():
        raise RuntimeError("simulated failure")

    import secure.checks.runner as runner_module

    monkeypatch.setattr(runner_module, "_SINGLE_CHECKS", [boom])
    monkeypatch.setattr(runner_module, "check_sharing_services", list)

    results = run_all_checks(include_pending_updates=False)

    assert len(results) == 1
    assert results[0].status == CheckStatus.WARNING
    assert "simulated failure" in results[0].message


def test_run_all_checks_quick_skips_pending_updates(monkeypatch):
    import secure.checks.runner as runner_module

    monkeypatch.setattr(runner_module, "_SINGLE_CHECKS", [])
    monkeypatch.setattr(runner_module, "check_sharing_services", list)

    calls = []
    monkeypatch.setattr(
        runner_module, "check_pending_updates", lambda: calls.append(1)
    )

    run_all_checks(include_pending_updates=False)

    assert calls == []
