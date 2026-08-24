"""
integrations/suricata/availability.py — determines whether Suricata's
EVE JSON output can actually be used right now, and — the phase's own
explicit requirement — whether Secure can honestly confirm PACKET
VISIBILITY, not just "the log file exists."

Four different honest outcomes, matching IntegrationHealth's four
statuses:

    unavailable — no EVE log configured, or the configured path doesn't
                  exist. Routine, not an error: Suricata is simply not
                  set up yet.
    error       — the log path exists but couldn't be read at all
                  (permissions, I/O error).
    degraded    — the log exists and is readable, but Secure cannot
                  currently CONFIRM packet visibility: no stats event
                  found yet, the most recent stats event is stale (the
                  log hasn't been updated recently — Suricata may not
                  be running), or — the specific case this phase calls
                  out by name — Suricata's own capture counters show
                  ZERO packets captured. A zero-packet count must never
                  be read as "clean" (nothing to alert on); it means
                  Secure genuinely doesn't know what's happening on the
                  network right now.
    ok          — the log is fresh AND Suricata's own stats confirm a
                  positive packet count.

macOS packet-visibility note: this integration assumes Suricata is
configured to monitor THIS Mac's own interface traffic (its own
inbound/outbound packets), the same host-centric scope every other
Secure module already has — not full-LAN promiscuous capture. Modern
macOS makes reliable promiscuous/monitor-mode capture of a switched
network's traffic impractical without a mirror port and often blocked
by the OS/Wi-Fi stack outright; even with elevated permissions, a
single Mac plugged into a switched network mostly only sees its own
traffic anyway. Secure never attempts to configure interfaces, request
elevated capture permissions, or manage Suricata's process lifecycle —
it only reads whatever eve.json the user's own independently-running
Suricata install already produces.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from secure.config import AppConfig
from secure.integrations.base import (
    STATUS_DEGRADED,
    STATUS_ERROR,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    IntegrationHealth,
)
from secure.integrations.suricata._eve import DEFAULT_MAX_LINES, read_eve_lines
from secure.integrations.suricata._shell import try_get_version
from secure.integrations.suricata._timeutil import parse_suricata_timestamp
from secure.integrations.suricata.parser import extract_latest_capture_stats

DEFAULT_STALE_AFTER_SECONDS = 600.0  # 10 minutes with no fresh stats event


def check_availability(
    cfg: AppConfig,
    max_lines: int = DEFAULT_MAX_LINES,
    stale_after_seconds: float = DEFAULT_STALE_AFTER_SECONDS,
) -> IntegrationHealth:
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    tool_version = try_get_version()

    path = cfg.suricata_eve_log_path_resolved()
    if path is None:
        return IntegrationHealth(
            status=STATUS_UNAVAILABLE,
            detail="No Suricata EVE JSON log path configured (AppConfig.suricata_eve_log_path).",
            collected_at=now,
            tool_version=tool_version,
        )
    if not path.is_file():
        return IntegrationHealth(
            status=STATUS_UNAVAILABLE,
            detail=f"Suricata EVE JSON log not found at {path}.",
            collected_at=now,
            tool_version=tool_version,
        )

    try:
        records, malformed = read_eve_lines(path, max_lines=max_lines)
    except OSError as exc:
        return IntegrationHealth(
            status=STATUS_ERROR,
            detail=f"Could not read Suricata EVE JSON log at {path}: {exc}",
            collected_at=now,
            tool_version=tool_version,
        )

    if not records:
        detail = f"EVE JSON log at {path} is empty"
        if malformed:
            detail += f" ({malformed} unparseable line(s) found)"
        detail += " — Suricata may not have started yet, or hasn't logged anything."
        return IntegrationHealth(
            status=STATUS_DEGRADED, detail=detail, collected_at=now, tool_version=tool_version
        )

    stats = extract_latest_capture_stats(records)
    if stats is None:
        return IntegrationHealth(
            status=STATUS_DEGRADED,
            detail=(
                f"EVE JSON log at {path} has entries but no stats event was found in the "
                "most recent lines read — packet-capture visibility cannot be confirmed yet. "
                "Suricata emits stats periodically; this should resolve on a later scan."
            ),
            collected_at=now,
            tool_version=tool_version,
        )

    stats_time = parse_suricata_timestamp(stats.get("timestamp"))
    if stats_time is not None:
        age_seconds = (now_dt - stats_time).total_seconds()
        if age_seconds > stale_after_seconds:
            return IntegrationHealth(
                status=STATUS_DEGRADED,
                detail=(
                    f"Suricata's most recent capture stats are from {stats['timestamp']} "
                    f"({age_seconds:.0f}s ago), more than {stale_after_seconds:.0f}s old — "
                    "Suricata may not be running, or this log has stopped being updated."
                ),
                collected_at=now,
                tool_version=tool_version,
            )

    kernel_packets = stats.get("kernel_packets")
    decoder_pkts = stats.get("decoder_pkts")
    total_packets = kernel_packets if kernel_packets is not None else decoder_pkts

    if total_packets is None:
        return IntegrationHealth(
            status=STATUS_DEGRADED,
            detail=(
                "Suricata's stats event doesn't expose a packet-count field this "
                "integration recognizes (checked stats.capture.kernel_packets and "
                "stats.decoder.pkts) — packet visibility could not be confirmed from "
                "the fields available for this capture method."
            ),
            collected_at=now,
            tool_version=tool_version,
        )

    if total_packets <= 0:
        return IntegrationHealth(
            status=STATUS_DEGRADED,
            detail=(
                "Suricata has captured ZERO packets so far — packet visibility is NOT "
                "established. This is not the same as 'no threats found': treat any "
                "absence of alerts while this status holds as unknown, not confirmed "
                "clean. Common causes: no traffic on the monitored interface, an "
                "interface/permission misconfiguration, or Suricata just having "
                "started."
            ),
            collected_at=now,
            tool_version=tool_version,
        )

    drops = stats.get("kernel_drops")
    drop_note = f", {drops} dropped by the kernel" if drops else ""
    return IntegrationHealth(
        status=STATUS_OK,
        detail=f"Suricata is capturing traffic ({total_packets} packets seen{drop_note}).",
        collected_at=now,
        tool_version=tool_version,
    )
