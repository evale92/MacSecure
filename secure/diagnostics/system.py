"""
diagnostics/system.py — Phase 30: live system health ("how heavily
loaded is this Mac right now?"). Never persisted — same "compute fresh,
nothing to cache" reasoning as hardware.py.

Every field is Optional, same discipline as hardware.py: a metric this
platform genuinely doesn't expose (no battery on a desktop Mac, no
thermal-pressure API, running somewhere other than macOS) is None with
its name in `unavailable`, never a fabricated number. Parsers below are
pure functions of the exact command text (`_parse_vm_stat`,
`_parse_swapusage`, `_parse_battery`, `_parse_thermal`) specifically so
they can be unit-tested against real captured macOS output without
needing a live Mac to run the test.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from secure.diagnostics._shell import run

_SWAPUSAGE_RE = re.compile(
    r"total\s*=\s*([\d.]+)([KMGT])\s+used\s*=\s*([\d.]+)([KMGT])\s+free\s*=\s*([\d.]+)([KMGT])",
    re.IGNORECASE,
)
_UNIT_MULTIPLIER = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}


@dataclass
class SystemHealth:
    collected_at: str
    load_avg_1m: "float | None"
    load_avg_5m: "float | None"
    load_avg_15m: "float | None"
    mem_total_bytes: "int | None"
    mem_free_bytes: "int | None"
    mem_pressure: "str | None"
    swap_total_bytes: "int | None"
    swap_used_bytes: "int | None"
    disk_total_bytes: "int | None"
    disk_free_bytes: "int | None"
    battery_state: "str | None"
    thermal_pressure: "str | None"
    unavailable: "list[str]" = field(default_factory=list)


def _load_average() -> "tuple[float, float, float] | None":
    try:
        return os.getloadavg()
    except (OSError, AttributeError):
        # AttributeError on platforms without getloadavg (rare); OSError
        # if the OS genuinely can't report it.
        return None


def _parse_vm_stat(text: str) -> "tuple[int, int] | None":
    """Returns (page_size_bytes, free_pages) from real `vm_stat` output,
    or None if the expected shape isn't there. Pure parser, no
    subprocess — see this module's own docstring for why.
    """
    header = re.search(r"page size of (\d+) bytes", text)
    free = re.search(r"Pages free:\s*([\d,]+)\.", text)
    if not header or not free:
        return None
    page_size = int(header.group(1))
    free_pages = int(free.group(1).replace(",", ""))
    return page_size, free_pages


def _parse_swapusage(text: str) -> "tuple[int, int] | None":
    """Returns (total_bytes, used_bytes) from real `sysctl vm.swapusage`
    output, e.g. "vm.swapusage: total = 2048.00M used = 512.00M free =
    1536.00M (encrypted)". Pure parser.
    """
    match = _SWAPUSAGE_RE.search(text)
    if not match:
        return None
    total_val, total_unit, used_val, used_unit, _free_val, _free_unit = match.groups()
    total_bytes = int(float(total_val) * _UNIT_MULTIPLIER[total_unit.upper()])
    used_bytes = int(float(used_val) * _UNIT_MULTIPLIER[used_unit.upper()])
    return total_bytes, used_bytes


def _parse_battery(text: str) -> "str | None":
    """Returns a short human-readable battery/AC state from real
    `pmset -g batt` output, or None if the output doesn't match any
    known shape. Distinguishes "no battery, this is a desktop Mac"
    (a real InternalBattery line reporting `present: false`, or no
    battery line at all alongside a valid power-source line) from a
    genuinely unreadable result. Pure parser.
    """
    source_match = re.search(r"Now drawing from\s+'([^']+)'", text)
    if not source_match:
        return None
    source = source_match.group(1)

    percent_match = re.search(r"(\d{1,3})%", text)
    if percent_match:
        return f"{source}, battery {percent_match.group(1)}%"
    if "present: false" in text or "InternalBattery" not in text:
        return f"{source} (no battery — desktop Mac)"
    return source


def _parse_thermal(text: str) -> "str | None":
    """Returns a short thermal-pressure label from real `pmset -g
    therm` output, or None if unreadable. Pure parser.
    """
    stripped = text.strip()
    if not stripped:
        return None
    if "no thermal warning" in stripped.lower():
        return "nominal"
    match = re.search(r"CPU_Scheduler_Limit\s*=\s*(\d+)", stripped)
    if match:
        limit = int(match.group(1))
        return "nominal" if limit >= 100 else f"throttled (scheduler limit {limit}%)"
    return stripped.splitlines()[0][:120]


def collect_system_health(disk_path: "Path | None" = None) -> SystemHealth:
    """One best-effort snapshot of everything requirement 2 asks for.
    Each source is independent — one being unavailable (e.g. this
    process running on non-macOS, or a genuinely battery-less Mac)
    never blocks the others.
    """
    unavailable: "list[str]" = []
    collected_at = datetime.now(timezone.utc).isoformat()

    load = _load_average()
    load_1m = load[0] if load else None
    load_5m = load[1] if load else None
    load_15m = load[2] if load else None
    if load is None:
        unavailable.append("load_average")

    mem_total_bytes = None
    sysctl_mem = run(["sysctl", "-n", "hw.memsize"], timeout=5.0)
    if sysctl_mem.ok and sysctl_mem.stdout.strip().isdigit():
        mem_total_bytes = int(sysctl_mem.stdout.strip())

    mem_free_bytes = None
    vm_stat_result = run(["vm_stat"], timeout=5.0)
    if vm_stat_result.ok:
        parsed = _parse_vm_stat(vm_stat_result.stdout)
        if parsed:
            page_size, free_pages = parsed
            mem_free_bytes = page_size * free_pages
    if mem_free_bytes is None:
        unavailable.append("mem_free_bytes")
    if mem_total_bytes is None:
        unavailable.append("mem_total_bytes")

    # memory_pressure's own -Q summary output varies a lot across macOS
    # versions and is often slow (it samples); deliberately not shelled
    # out to here — mem_pressure stays honestly unavailable rather than
    # adding a slow, flaky subprocess call just to populate one field.
    mem_pressure = None
    unavailable.append("mem_pressure")

    swap_total_bytes = None
    swap_used_bytes = None
    swap_result = run(["sysctl", "vm.swapusage"], timeout=5.0)
    if swap_result.ok:
        parsed_swap = _parse_swapusage(swap_result.stdout)
        if parsed_swap:
            swap_total_bytes, swap_used_bytes = parsed_swap
    if swap_total_bytes is None:
        unavailable.append("swap_usage")

    disk_total_bytes = None
    disk_free_bytes = None
    try:
        usage = shutil.disk_usage(disk_path or Path.home())
        disk_total_bytes, disk_free_bytes = usage.total, usage.free
    except OSError:
        unavailable.append("disk_usage")

    battery_state = None
    batt_result = run(["pmset", "-g", "batt"], timeout=5.0)
    if batt_result.ok:
        battery_state = _parse_battery(batt_result.stdout)
    if battery_state is None:
        unavailable.append("battery_state")

    thermal_pressure = None
    therm_result = run(["pmset", "-g", "therm"], timeout=5.0)
    if therm_result.ok:
        thermal_pressure = _parse_thermal(therm_result.stdout)
    if thermal_pressure is None:
        unavailable.append("thermal_pressure")

    return SystemHealth(
        collected_at=collected_at,
        load_avg_1m=load_1m,
        load_avg_5m=load_5m,
        load_avg_15m=load_15m,
        mem_total_bytes=mem_total_bytes,
        mem_free_bytes=mem_free_bytes,
        mem_pressure=mem_pressure,
        swap_total_bytes=swap_total_bytes,
        swap_used_bytes=swap_used_bytes,
        disk_total_bytes=disk_total_bytes,
        disk_free_bytes=disk_free_bytes,
        battery_state=battery_state,
        thermal_pressure=thermal_pressure,
        unavailable=unavailable,
    )
