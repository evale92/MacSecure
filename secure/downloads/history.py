"""downloads/history.py — read and flag quarantine events. See the package docstring."""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit

from secure.storage.models.macos_readonly import (
    MacDatabaseUnavailable,
    QuarantineEvent,
    read_quarantine_events,
)

QUARANTINE_DB = Path.home() / "Library" / "Preferences" / "com.apple.LaunchServices.QuarantineEventsV2"

COVERAGE_NOTE = (
    "Only apps that set the quarantine flag record downloads here (browsers, Mail, "
    "Messages, AirDrop, most chat apps). curl, wget, git, pip and anything run in "
    "Terminal never appear. Events with no URL at all are left out."
)

EXECUTABLE_SUFFIXES = (
    ".app", ".command", ".dmg", ".dylib", ".img", ".iso", ".jar", ".mpkg", ".osax",
    ".pkg", ".py", ".scpt", ".scptd", ".sh", ".terminal", ".tool", ".workflow",
)


@dataclass
class DownloadEvent:
    event: QuarantineEvent
    flags: "list[str]" = field(default_factory=list)


@dataclass
class DownloadReport:
    status: str                 # "OK" or "UNAVAILABLE"
    reason: str
    days: int
    events: "list[DownloadEvent]"
    truncated: bool

    @property
    def flagged(self) -> "list[DownloadEvent]":
        return [e for e in self.events if e.flags]


def _host_is_ip(url: str) -> bool:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return False
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def flags_for(event: QuarantineEvent) -> "list[str]":
    flags = []
    name = unquote(urlsplit(event.data_url).path if event.data_url else "").lower().rstrip("/")
    if name.endswith(EXECUTABLE_SUFFIXES):
        flags.append("executable_type")
    if any(_host_is_ip(u) for u in (event.data_url, event.origin_url) if u):
        flags.append("ip_literal_host")
    if any(u.lower().startswith("http://") for u in (event.data_url, event.origin_url) if u):
        flags.append("plain_http")
    return flags


def download_history(
    days: int = 30,
    limit: int = 500,
    database: Path = QUARANTINE_DB,
    now: "float | None" = None,
) -> DownloadReport:
    now = time.time() if now is None else now
    try:
        raw = read_quarantine_events(database, since_unix=now - days * 86400, limit=limit + 1, require_url=True)
    except MacDatabaseUnavailable as exc:
        return DownloadReport("UNAVAILABLE", str(exc), days, [], False)
    truncated = len(raw) > limit
    events = [DownloadEvent(e, flags_for(e)) for e in raw[:limit]]
    return DownloadReport("OK", "", days, events, truncated)
