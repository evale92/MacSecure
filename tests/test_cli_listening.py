"""
Tests for `secure/cli/listening.py`'s `cmd_listening_scan` — the exit
code `secure listening scan` hands its caller.

Why this file exists (J-0330): no test executed `cmd_listening_scan`.
Nothing in tests/ names it, and nothing drives `main()` with a
`listening` argument; `secure run-all` (secure/cli/root.py:328) calls
`scan_listening_services` directly and never reaches this handler. So
line 77's `return 1 if new_services or disappeared_services else 0`
was unasserted in both directions.

That exit code is a finding channel. 0 means "the scan ran and nothing
changed"; 1 means "look at this". Two ways it can lie, each pinned
below:

  * **A stuck dirty result.** tests/test_listening.py (J-0327) proves
    the scanner reports a disappearance once, not on every later scan.
    Nothing proved the CLI turns that back into 0. If the baseline
    stuck on an old run, every scan after any service stopped would
    exit 1 forever — as uninformative as a fabricated clean pass
    (SECURITY_INVARIANTS.md invariant 5, run in reverse).
  * **A disappearance that does not count.** A service that quietly
    stops listening must still make the scan exit 1, not just print a
    line nobody's script reads.

The four-scan sequence is one test because the transitions are the
claim: 1 (first scan, everything new), 0 (unchanged — the positive
control without which "exits 1" is satisfied by always returning 1),
1 (sshd stopped), 0 (sshd still stopped, which is no longer news).

The seam: the handler calls the real `scan_listening_services`, and
only `secure.listening.scanner.run` (the `lsof` call) is replaced. Each
test asserts the fake was called, so a wrong seam fails loudly instead
of running the real `lsof` against this machine.

Run with:  pytest tests/test_cli_listening.py
"""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path

import secure.listening.scanner as scanner_module
from secure import cli
from secure.cli import listening as cli_listening
from secure.config import load_config
from secure.listening._shell import ShellResult

_LSOF_STDOUT = """\
COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
sshd         99   root    3u  IPv4 0x1111111111111111      0t0  TCP *:22 (LISTEN)
Postman    1399  user    8u  IPv4 0x2222222222222222      0t0  TCP 127.0.0.1:49220 (LISTEN)
mDNSRespo    80  _mdns    5u  IPv4 0x3333333333333333      0t0  UDP *:5353
"""

_LSOF_STDOUT_WITHOUT_SSHD = "".join(
    line + "\n" for line in _LSOF_STDOUT.splitlines() if "sshd" not in line
)

_STOPPED_HEADER = "SERVICES THAT STOPPED LISTENING SINCE THE LAST SCAN"
_NONE_STOPPED = "No services stopped listening since the last scan."


def _bootstrap_to_tmp(monkeypatch, tmp_path: Path) -> None:
    """Point `_bootstrap()` at an isolated temp app_dir, never ~/.secure.
    Same approach as tests/test_cli_persistence.py."""
    monkeypatch.setattr(cli, "load_config", lambda: load_config(app_dir=tmp_path))


def _patch_lsof(monkeypatch, outputs: list) -> list:
    """Serve one ShellResult per scan, in order. Returns the call log."""
    assert hasattr(scanner_module, "run"), (
        "secure/listening/scanner.py no longer binds run at import; "
        "this test patches the wrong seam"
    )
    calls: list = []

    def fake_run(args, timeout=5.0):
        calls.append(args)
        return outputs[len(calls) - 1]

    monkeypatch.setattr(scanner_module, "run", fake_run)
    return calls


def _lsof(stdout: str) -> ShellResult:
    return ShellResult(ok=True, stdout=stdout, stderr="", returncode=0)


def _scan() -> tuple:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli_listening.cmd_listening_scan(argparse.Namespace())
    return rc, buf.getvalue()


def test_scan_exit_code_tracks_changes_and_clears_after_a_disappearance(
    tmp_path: Path, monkeypatch
):
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    calls = _patch_lsof(
        monkeypatch,
        [
            _lsof(_LSOF_STDOUT),
            _lsof(_LSOF_STDOUT),
            _lsof(_LSOF_STDOUT_WITHOUT_SSHD),
            _lsof(_LSOF_STDOUT_WITHOUT_SSHD),
        ],
    )

    first_rc, first_out = _scan()
    second_rc, second_out = _scan()
    third_rc, third_out = _scan()
    fourth_rc, fourth_out = _scan()

    assert len(calls) == 4, "the patched lsof run was not called once per scan"

    # Scan 1: every service is new, and there is nothing to compare
    # against, so neither disappearance line may appear.
    assert first_rc == 1
    assert "NEW LISTENING SERVICES DETECTED (3):" in first_out
    assert _STOPPED_HEADER not in first_out
    assert _NONE_STOPPED not in first_out

    # Scan 2: identical — the positive control for every `== 1` here.
    assert second_rc == 0
    assert "No new listening services detected." in second_out
    assert _NONE_STOPPED in second_out

    # Scan 3: sshd stopped. Nothing is new, so the disappearance alone
    # must carry the exit code.
    assert third_rc == 1
    assert "No new listening services detected." in third_out
    assert f"{_STOPPED_HEADER} (1):" in third_out
    assert "sshd" in third_out.split(_STOPPED_HEADER, 1)[1]

    # Scan 4: sshd is still gone, but it stopped before the previous
    # scan, not since it. A stuck baseline would exit 1 here forever.
    assert fourth_rc == 0
    assert _STOPPED_HEADER not in fourth_out
    assert _NONE_STOPPED in fourth_out


def test_scan_exits_one_when_lsof_could_not_run(tmp_path: Path, monkeypatch):
    """A scan that saw nothing because it could not look must not exit 0
    (AGENTS.md rule 7). The scan-2 assertion above is its positive
    control."""
    _bootstrap_to_tmp(monkeypatch, tmp_path)
    calls = _patch_lsof(
        monkeypatch,
        [ShellResult(ok=False, stdout="", stderr="command not found", returncode=None)],
    )

    rc, out = _scan()

    assert calls
    assert rc == 1
    assert "Could not run `lsof`" in out
    assert "No listening services were recorded this scan." in out
    # Neither affirmative negative may follow the admission that the
    # scan saw nothing.
    assert "Listening services seen" not in out
    assert "No new listening services detected." not in out
    assert _NONE_STOPPED not in out
