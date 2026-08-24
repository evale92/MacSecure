"""
connections/lsof_parser.py — turns `lsof -i -n -P` output into
ConnectionEntry objects.

Why lsof, and why these flags:
    -i    only show internet sockets (TCP/UDP) — not every open file
          on the system, which is what plain `lsof` would dump.
    -n    numeric addresses — skip lsof's own hostname resolution,
          which (same lesson as `arp -an` in secure/inventory/) can
          hang without a controlling terminal.
    -P    numeric ports — skip lsof translating e.g. 443 to "https",
          which just makes parsing harder for no benefit here.
    +c0   don't truncate the COMMAND column. lsof's default width
          (historically 9 characters) is why you'd otherwise see
          "identitys" instead of "identityservicesd" — 0 means "as
          wide as the longest name actually found."

lsof also escapes any space (or other whitespace/non-printable byte)
*inside* a process name as \\xHH (e.g. "Code Helper" -> "Code\\x20Helper")
so its own output stays one-whitespace-delimited-token-per-field —
otherwise a name with a space would look like an extra column. This
module undoes that escaping for the process name specifically, after
splitting the line into columns (see _unescape_lsof_text()) — purely
cosmetic, it doesn't affect anything else about the parse.

No sudo. Run as a normal user, lsof reports every socket it's allowed
to see — which in practice is this user's own processes, plus quite a
few belonging to other users/root that macOS still lets you see the
connection for (address/port/state) even if it can't. When it can't
see something, it either omits the line or prints a "WARNING: can't
stat() ..." line to stderr — see scanner.py's `permission_warnings`
for surfacing that count instead of silently hiding it.

A sample line looks like:
    Google    1234 erick   55u  IPv4 0x1234      0t0  TCP 192.168.1.23:54321->142.250.80.14:443 (ESTABLISHED)
    sshd        99 root     3u  IPv4 0x5678      0t0  TCP *:22 (LISTEN)
    mDNSRespo   80 _mdns    8u  IPv4 0x9abc      0t0  UDP *:5353

Column layout is COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME —
NODE is the protocol (TCP/UDP), NAME is everything else (the address,
and for TCP usually a "(STATE)" suffix; UDP sockets have no state).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _unescape_lsof_text(text: str) -> str:
    """Undo lsof's \\xHH escaping (e.g. "Code\\x20Helper" -> "Code Helper")."""
    return _ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)


@dataclass
class ConnectionEntry:
    proto: str  # "TCP" or "UDP"
    local_addr: Optional[str]
    local_port: Optional[int]
    remote_addr: Optional[str]  # None for a listening socket with no peer
    remote_port: Optional[int]
    state: Optional[str]  # e.g. "ESTABLISHED", "LISTEN" — usually None for UDP
    pid: int
    process_name: str


def parse_lsof_output(text: str) -> List[ConnectionEntry]:
    """Parse the full stdout of `lsof -i -n -P` into ConnectionEntry rows.

    Skips the header line and anything that doesn't look like a
    TCP/UDP row rather than raising — lsof's exact column widths have
    shifted across macOS versions before, and one unparseable line
    (or a stderr WARNING line that leaked into stdout) shouldn't lose
    every other row in the scan.
    """
    entries: List[ConnectionEntry] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("COMMAND"):
            continue
        entry = _parse_line(line)
        if entry is not None:
            entries.append(entry)
    return entries


def _parse_line(line: str) -> Optional[ConnectionEntry]:
    tokens = line.split()
    if len(tokens) < 9:
        return None

    command, pid_str, _user, _fd, _ftype, _device, _sizeoff, node = tokens[:8]
    name = " ".join(tokens[8:])

    if node not in ("TCP", "UDP"):
        return None

    try:
        pid = int(pid_str)
    except ValueError:
        return None

    addr_part = name
    state: Optional[str] = None
    if addr_part.endswith(")") and " (" in addr_part:
        addr_part, _, state_part = addr_part.rpartition(" (")
        state = state_part[:-1]  # drop the trailing ")"

    if "->" in addr_part:
        local_part, remote_part = addr_part.split("->", 1)
    else:
        local_part, remote_part = addr_part, None

    local_addr, local_port = _split_host_port(local_part)
    remote_addr, remote_port = (None, None)
    if remote_part:
        remote_addr, remote_port = _split_host_port(remote_part)

    return ConnectionEntry(
        proto=node,
        local_addr=local_addr,
        local_port=local_port,
        remote_addr=remote_addr,
        remote_port=remote_port,
        state=state,
        pid=pid,
        process_name=_unescape_lsof_text(command),
    )


def _split_host_port(part: str) -> Tuple[Optional[str], Optional[int]]:
    """Split "host:port" into (host, port).

    Handles bracketed IPv6 ("[::1]:80") and macOS lsof's wildcard
    address ("*:22"). Unbracketed IPv6 addresses (lsof doesn't always
    bracket them) are split on the last colon, which is correct for
    the port but best-effort for the address itself — same documented
    tradeoff as secure/inventory/vendor.py's OUI table: good enough to
    be useful, not guaranteed perfect on every edge case.
    """
    part = part.strip()
    if not part:
        return None, None

    if part.startswith("["):
        end = part.find("]")
        if end != -1:
            host = part[1:end] or None
            rest = part[end + 1 :]
            port = rest[1:] if rest.startswith(":") else None
            return host, _to_port(port)

    if ":" not in part:
        return part, None

    host, _, port = part.rpartition(":")
    return (host or None), _to_port(port)


def _to_port(port_str: Optional[str]) -> Optional[int]:
    if not port_str or port_str == "*":
        return None
    try:
        return int(port_str)
    except ValueError:
        return None
