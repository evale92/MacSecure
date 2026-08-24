"""
Tests for secure/listening/* (Listening Port and Service Audit).

Reuses secure.connections.lsof_parser to build sample ConnectionEntry
objects (that parser already has its own dedicated tests in
tests/test_connections.py) — these tests focus on what's new here:
bind-scope classification, risk notes, "what counts as listening," the
ephemeral-port identity bucketing, and scan_listening_services() tested
end-to-end with the lsof call mocked out.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.connections._shell import ShellResult
from secure.connections.lsof_parser import ConnectionEntry
from secure.listening.bind_scope import classify_bind_scope
from secure.listening.risk import evaluate_risk
from secure.listening.bind_scope import identity_port
from secure.listening.scanner import _is_listening, scan_listening_services
from secure.storage.database import Database
from secure.storage.models import list_listening_services, list_recent_listening_events

# ---------- classify_bind_scope ----------


def test_classify_bind_scope_loopback_ipv4():
    assert classify_bind_scope("127.0.0.1") == "localhost"


def test_classify_bind_scope_loopback_ipv6():
    assert classify_bind_scope("::1") == "localhost"


def test_classify_bind_scope_wildcard():
    assert classify_bind_scope("*") == "network"


def test_classify_bind_scope_all_interfaces_ipv4():
    assert classify_bind_scope("0.0.0.0") == "network"


def test_classify_bind_scope_specific_lan_address():
    assert classify_bind_scope("192.168.1.23") == "network"


def test_classify_bind_scope_link_local_ipv6():
    assert classify_bind_scope("fe80::1") == "network"


def test_classify_bind_scope_none_defaults_to_network():
    assert classify_bind_scope(None) == "network"


# ---------- evaluate_risk ----------


def test_evaluate_risk_localhost_is_reassuring():
    note = evaluate_risk(11434, "ollama", "localhost")
    assert "not exposed" in note.lower()


def test_evaluate_risk_sensitive_port_exposed():
    note = evaluate_risk(445, "smbd", "network")
    assert "SMB" in note
    assert "exposed" in note.lower()


def test_evaluate_risk_ssh_exposed_mentions_ssh():
    note = evaluate_risk(22, "sshd", "network")
    assert "SSH" in note


def test_evaluate_risk_discovery_port_is_normal():
    note = evaluate_risk(5353, "mDNSResponder", "network")
    assert "normal" in note.lower()


def test_evaluate_risk_unknown_port_exposed_mentions_process():
    note = evaluate_risk(15611, "Postman", "network")
    assert "Postman" in note


# ---------- _is_listening ----------


def test_is_listening_tcp_listen_state():
    entry = ConnectionEntry(
        proto="TCP", local_addr="*", local_port=22, remote_addr=None,
        remote_port=None, state="LISTEN", pid=1, process_name="sshd",
    )
    assert _is_listening(entry) is True


def test_is_listening_tcp_established_is_not_listening():
    entry = ConnectionEntry(
        proto="TCP", local_addr="192.168.1.2", local_port=54321,
        remote_addr="1.2.3.4", remote_port=443, state="ESTABLISHED",
        pid=1, process_name="Google",
    )
    assert _is_listening(entry) is False


def test_is_listening_udp_with_no_remote_is_listening():
    entry = ConnectionEntry(
        proto="UDP", local_addr="*", local_port=5353, remote_addr=None,
        remote_port=None, state=None, pid=1, process_name="mDNSResponder",
    )
    assert _is_listening(entry) is True


def test_is_listening_udp_with_remote_is_not_listening():
    entry = ConnectionEntry(
        proto="UDP", local_addr="192.168.1.2", local_port=60000,
        remote_addr="1.2.3.4", remote_port=443, state=None,
        pid=1, process_name="Claude",
    )
    assert _is_listening(entry) is False


# ---------- _identity_port ----------


def test_identity_port_none_is_ephemeral():
    assert identity_port(None) == "ephemeral"


def test_identity_port_privileged_port_kept_exact():
    assert identity_port(22) == "22"


def test_identity_port_well_known_high_port_kept_exact():
    assert identity_port(5353) == "5353"  # mDNS — in the common-ports table


def test_identity_port_ordinary_high_port_is_ephemeral():
    assert identity_port(49488) == "ephemeral"  # a typical OS-assigned dev-tool port


# ---------- scan_listening_services (end-to-end, lsof mocked) ----------

_FAKE_STDOUT = """\
COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
sshd         99   root    3u  IPv4 0x1111111111111111      0t0  TCP *:22 (LISTEN)
Postman    1399  erick   8u  IPv4 0x2222222222222222      0t0  TCP 127.0.0.1:49220 (LISTEN)
mDNSRespo    80  _mdns    5u  IPv4 0x3333333333333333      0t0  UDP *:5353
Google     1234  erick  55u  IPv4 0x4444444444444444      0t0  TCP 192.168.1.23:54321->142.250.80.14:443 (ESTABLISHED)
"""


def test_scan_listening_services_filters_to_listening_only(tmp_path: Path, monkeypatch):
    import secure.listening.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module,
        "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_FAKE_STDOUT, stderr="", returncode=0),
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_listening_services(db.conn)
        events = list_recent_listening_events(db.conn, limit=50)
        services = list_listening_services(db.conn)

    assert result.lsof_available is True
    # 3 listening sockets (sshd, Postman, mDNSResponder) — the ESTABLISHED
    # Google connection is excluded, it belongs to Phase 4, not this audit.
    assert len(result.entries) == 3
    assert len(events) == 3
    assert len(services) == 3

    sshd_entry = next(e for e in result.entries if e.process_name == "sshd")
    assert sshd_entry.bind_scope == "network"
    assert "SSH" in sshd_entry.risk_note

    postman_entry = next(e for e in result.entries if e.process_name == "Postman")
    assert postman_entry.bind_scope == "localhost"


def test_scan_listening_services_flags_new_services(tmp_path: Path, monkeypatch):
    import secure.listening.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module,
        "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_FAKE_STDOUT, stderr="", returncode=0),
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_listening_services(db.conn)

    assert len(result.new_services) == 3


def test_scan_listening_services_second_scan_has_no_new_services(tmp_path: Path, monkeypatch):
    import secure.listening.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module,
        "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_FAKE_STDOUT, stderr="", returncode=0),
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        first = scan_listening_services(db.conn)
        second = scan_listening_services(db.conn)

    assert len(first.new_services) == 3
    assert len(second.new_services) == 0


def test_scan_listening_services_ephemeral_port_change_is_not_a_new_service(tmp_path: Path, monkeypatch):
    """The whole point of identity_port(): Postman restarting on a
    different ephemeral port shouldn't look like a brand-new service."""
    import secure.listening.scanner as scanner_module

    first_stdout = _FAKE_STDOUT
    second_stdout = _FAKE_STDOUT.replace("127.0.0.1:49220", "127.0.0.1:51111")

    calls = {"n": 0}

    def fake_run(*a, **k):
        calls["n"] += 1
        stdout = first_stdout if calls["n"] == 1 else second_stdout
        return ShellResult(ok=True, stdout=stdout, stderr="", returncode=0)

    monkeypatch.setattr(scanner_module, "run", fake_run)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        first = scan_listening_services(db.conn)
        second = scan_listening_services(db.conn)
        services = list_listening_services(db.conn)

    assert len(first.new_services) == 3
    assert len(second.new_services) == 0  # Postman's new port isn't "new"
    assert len(services) == 3  # still 3 rows, not 4


def test_scan_listening_services_first_scan_has_no_previous_scan(tmp_path: Path, monkeypatch):
    import secure.listening.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module,
        "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_FAKE_STDOUT, stderr="", returncode=0),
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_listening_services(db.conn)

    assert result.has_previous_scan is False
    assert result.disappeared_services == []


def test_scan_listening_services_detects_disappeared_service(tmp_path: Path, monkeypatch):
    """The user's own ask: a service present last scan but gone now should be reported."""
    import secure.listening.scanner as scanner_module

    # Second scan: sshd stopped, everything else unchanged.
    second_stdout = "\n".join(
        line for line in _FAKE_STDOUT.splitlines() if "sshd" not in line
    ) + "\n"

    calls = {"n": 0}

    def fake_run(*a, **k):
        calls["n"] += 1
        stdout = _FAKE_STDOUT if calls["n"] == 1 else second_stdout
        return ShellResult(ok=True, stdout=stdout, stderr="", returncode=0)

    monkeypatch.setattr(scanner_module, "run", fake_run)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        first = scan_listening_services(db.conn)
        second = scan_listening_services(db.conn)

    assert first.has_previous_scan is False
    assert second.has_previous_scan is True
    assert len(second.disappeared_services) == 1
    assert second.disappeared_services[0].process_name == "sshd"
    # Nothing new appeared — sshd going away shouldn't also look like
    # an unrelated new-service alert.
    assert second.new_services == []


def test_scan_listening_services_nothing_disappears_when_unchanged(tmp_path: Path, monkeypatch):
    import secure.listening.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module,
        "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_FAKE_STDOUT, stderr="", returncode=0),
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        first = scan_listening_services(db.conn)
        second = scan_listening_services(db.conn)

    assert second.has_previous_scan is True
    assert second.disappeared_services == []


def test_scan_listening_services_lsof_unavailable(tmp_path: Path, monkeypatch):
    import secure.listening.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module,
        "run",
        lambda *a, **k: ShellResult(ok=False, stdout="", stderr="command not found", returncode=None),
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_listening_services(db.conn)
        events = list_recent_listening_events(db.conn, limit=50)

    assert result.lsof_available is False
    assert result.entries == []
    assert events == []
