"""
Tests for secure/connections/* (Active Connection Monitor).

Sample real-world-shaped `lsof -i -n -P` output is fed straight into
the pure parsing functions, so these don't need to run on a Mac or
invoke real `lsof`. scan_connections() itself is tested with the
shell call monkeypatched out, for the same reason (mirrors
test_inventory.py's approach to scan_network()).

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.connections._shell import ShellResult
from secure.connections.lsof_parser import (
    _split_host_port,
    _to_port,
    _unescape_lsof_text,
    parse_lsof_output,
)
from secure.connections.port_info import describe_port
from secure.connections.scanner import is_loopback, scan_connections
from secure.storage.database import Database
from secure.storage.models import list_recent_connection_events, list_remote_endpoints

# ---------- parse_lsof_output ----------

_SAMPLE_LSOF_OUTPUT = """\
COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Google     1234  erick   55u  IPv4 0x1111111111111111      0t0  TCP 192.168.1.23:54321->142.250.80.14:443 (ESTABLISHED)
sshd         99   root    3u  IPv4 0x2222222222222222      0t0  TCP *:22 (LISTEN)
mDNSRespo    80  _mdns    8u  IPv4 0x3333333333333333      0t0  UDP *:5353
launchd       1   root   21u  IPv6 0x4444444444444444      0t0  TCP [::1]:8080 (LISTEN)
Safari     5555  erick   40u  IPv4 0x5555555555555555      0t0  TCP 127.0.0.1:54322->127.0.0.1:5432 (ESTABLISHED)
"""


def test_parse_lsof_output_skips_header():
    entries = parse_lsof_output(_SAMPLE_LSOF_OUTPUT)
    assert len(entries) == 5


def test_parse_lsof_output_established_tcp_with_remote():
    entries = parse_lsof_output(_SAMPLE_LSOF_OUTPUT)
    entry = next(e for e in entries if e.process_name == "Google")
    assert entry.proto == "TCP"
    assert entry.local_addr == "192.168.1.23"
    assert entry.local_port == 54321
    assert entry.remote_addr == "142.250.80.14"
    assert entry.remote_port == 443
    assert entry.state == "ESTABLISHED"
    assert entry.pid == 1234


def test_parse_lsof_output_listening_socket_has_no_remote():
    entries = parse_lsof_output(_SAMPLE_LSOF_OUTPUT)
    entry = next(e for e in entries if e.process_name == "sshd")
    assert entry.proto == "TCP"
    assert entry.local_addr == "*"
    assert entry.local_port == 22
    assert entry.remote_addr is None
    assert entry.remote_port is None
    assert entry.state == "LISTEN"


def test_parse_lsof_output_udp_has_no_state():
    entries = parse_lsof_output(_SAMPLE_LSOF_OUTPUT)
    entry = next(e for e in entries if e.process_name == "mDNSRespo")
    assert entry.proto == "UDP"
    assert entry.state is None
    assert entry.remote_addr is None


def test_parse_lsof_output_bracketed_ipv6():
    entries = parse_lsof_output(_SAMPLE_LSOF_OUTPUT)
    entry = next(e for e in entries if e.process_name == "launchd")
    assert entry.local_addr == "::1"
    assert entry.local_port == 8080
    assert entry.state == "LISTEN"


def test_parse_lsof_output_loopback_established():
    entries = parse_lsof_output(_SAMPLE_LSOF_OUTPUT)
    entry = next(e for e in entries if e.process_name == "Safari")
    assert entry.local_addr == "127.0.0.1"
    assert entry.remote_addr == "127.0.0.1"
    assert entry.remote_port == 5432


def test_parse_lsof_output_ignores_garbage_lines():
    assert parse_lsof_output("not an lsof line\n\n   \n") == []


def test_parse_lsof_output_unescapes_command_name():
    line = (
        "Code\\x20H  2208  erick  30u  IPv4 0x6666666666666666      0t0  TCP "
        "192.168.1.23:53446->140.82.112.22:443 (ESTABLISHED)\n"
    )
    entries = parse_lsof_output(line)
    assert entries[0].process_name == "Code H"


# ---------- _unescape_lsof_text ----------


def test_unescape_lsof_text_space():
    assert _unescape_lsof_text("Code\\x20Helper") == "Code Helper"


def test_unescape_lsof_text_no_escapes_is_unchanged():
    assert _unescape_lsof_text("sshd") == "sshd"


def test_unescape_lsof_text_multiple_escapes():
    assert _unescape_lsof_text("a\\x20b\\x20c") == "a b c"


# ---------- _split_host_port / _to_port ----------


def test_split_host_port_wildcard():
    assert _split_host_port("*:22") == ("*", 22)


def test_split_host_port_ipv4_with_remote():
    assert _split_host_port("192.168.1.23:54321") == ("192.168.1.23", 54321)


def test_split_host_port_bracketed_ipv6():
    assert _split_host_port("[fe80::1]:5353") == ("fe80::1", 5353)


def test_split_host_port_empty_string():
    assert _split_host_port("") == (None, None)


def test_to_port_wildcard_is_none():
    assert _to_port("*") is None


def test_to_port_none_is_none():
    assert _to_port(None) is None


def test_to_port_valid_number():
    assert _to_port("443") == 443


# ---------- port_info ----------


def test_describe_port_known():
    assert describe_port(443) is not None
    assert "HTTPS" in describe_port(443)


def test_describe_port_unknown_is_none():
    assert describe_port(59999) is None


def test_describe_port_none_is_none():
    assert describe_port(None) is None


# ---------- is_loopback ----------


def test_is_loopback_ipv4():
    assert is_loopback("127.0.0.1") is True


def test_is_loopback_ipv6():
    assert is_loopback("::1") is True


def test_is_loopback_normal_address():
    assert is_loopback("142.250.80.14") is False


def test_is_loopback_none():
    assert is_loopback(None) is False


# ---------- scan_connections (end-to-end, lsof mocked) ----------

_FAKE_STDOUT = """\
COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Google     1234  erick   55u  IPv4 0x1111111111111111      0t0  TCP 192.168.1.23:54321->142.250.80.14:443 (ESTABLISHED)
sshd         99   root    3u  IPv4 0x2222222222222222      0t0  TCP *:22 (LISTEN)
"""


def test_scan_connections_records_events_and_flags_new_endpoint(tmp_path: Path, monkeypatch):
    import secure.connections.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module,
        "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_FAKE_STDOUT, stderr="", returncode=0),
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_connections(db.conn)
        events = list_recent_connection_events(db.conn, limit=50)
        endpoints = list_remote_endpoints(db.conn)

    assert result.lsof_available is True
    assert len(result.entries) == 2
    assert result.listening_count == 1
    assert result.outbound_count == 1
    assert len(events) == 2

    assert len(endpoints) == 1  # only the ESTABLISHED entry has a remote peer
    assert endpoints[0].remote_addr == "142.250.80.14"
    assert endpoints[0].remote_port == 443
    assert len(result.new_endpoints) == 1


def test_scan_connections_second_scan_has_no_new_endpoints(tmp_path: Path, monkeypatch):
    import secure.connections.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module,
        "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_FAKE_STDOUT, stderr="", returncode=0),
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        first = scan_connections(db.conn)
        second = scan_connections(db.conn)

    assert len(first.new_endpoints) == 1
    assert len(second.new_endpoints) == 0


def test_scan_connections_counts_permission_warnings(tmp_path: Path, monkeypatch):
    import secure.connections.scanner as scanner_module

    stderr = "lsof: WARNING: can't stat() nfs file system\n"
    monkeypatch.setattr(
        scanner_module,
        "run",
        lambda *a, **k: ShellResult(ok=True, stdout=_FAKE_STDOUT, stderr=stderr, returncode=0),
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_connections(db.conn)

    assert result.permission_warnings == 1


def test_scan_connections_calls_lsof_with_c0(tmp_path: Path, monkeypatch):
    """+c0 stops lsof truncating process names (e.g. "identitys" -> full name)."""
    import secure.connections.scanner as scanner_module

    captured = {}

    def fake_run(args, timeout=None):
        captured["args"] = args
        return ShellResult(ok=True, stdout=_FAKE_STDOUT, stderr="", returncode=0)

    monkeypatch.setattr(scanner_module, "run", fake_run)

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        scan_connections(db.conn)

    assert captured["args"] == ["lsof", "-i", "-n", "-P", "+c0"]


def test_scan_connections_lsof_unavailable(tmp_path: Path, monkeypatch):
    import secure.connections.scanner as scanner_module

    monkeypatch.setattr(
        scanner_module,
        "run",
        lambda *a, **k: ShellResult(ok=False, stdout="", stderr="command not found", returncode=None),
    )

    db_path = tmp_path / "test.db"
    with Database(db_path) as db:
        result = scan_connections(db.conn)
        events = list_recent_connection_events(db.conn, limit=50)

    assert result.lsof_available is False
    assert result.entries == []
    assert events == []
