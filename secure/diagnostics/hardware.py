"""
diagnostics/hardware.py — Phase 30: static hardware/environment facts
("what Mac is this?"). Never persisted (see database.py's schema
comment for Phase 30) — computed fresh on every call, cheap enough
that there's nothing to cache.

Every field is Optional. A field that couldn't be measured on this
platform is None and its name appears in `unavailable` — never
fabricated, never silently defaulted to 0/"unknown" without saying so.
This mirrors secure/integrations/base.py's own "never a fifth silently
fine state" discipline, applied to hardware facts instead of
integration health.

Deliberately does NOT try to make advertised CPU clock speed meaningful
(per this phase's own governing instruction) — `cpu_brand` is reported
verbatim as a label, never parsed for a GHz number, and no field here
claims to summarize "how fast" this Mac is. secure/diagnostics/system.py
is where measurable load/utilization lives instead.
"""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass, field

from secure import __version__ as SECURE_VERSION
from secure.diagnostics._shell import run


@dataclass
class HardwareSpecs:
    mac_model: "str | None"
    architecture: str
    cpu_brand: "str | None"
    logical_cores: "int | None"
    physical_cores: "int | None"
    total_ram_bytes: "int | None"
    macos_version: "str | None"
    python_version: str
    secure_version: str
    unavailable: "list[str]" = field(default_factory=list)


def _sysctl(name: str) -> "str | None":
    result = run(["sysctl", "-n", name], timeout=5.0)
    if not result.ok:
        return None
    value = result.stdout.strip()
    return value or None


def _sysctl_int(name: str) -> "int | None":
    value = _sysctl(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def collect_hardware_specs() -> HardwareSpecs:
    """One best-effort read of everything requirement 1 asks for.
    Every sysctl call is independent — one failing (e.g. this process
    running on a non-macOS platform, or a key not existing on this
    hardware) never blocks the others; it just adds that one field's
    name to `unavailable`.
    """
    unavailable: "list[str]" = []

    mac_model = _sysctl("hw.model")
    if mac_model is None:
        unavailable.append("mac_model")

    cpu_brand = _sysctl("machdep.cpu.brand_string")
    if cpu_brand is None:
        unavailable.append("cpu_brand")

    logical_cores = _sysctl_int("hw.ncpu")
    if logical_cores is None:
        # os.cpu_count() is a portable stdlib fallback for the same
        # concept — still a real measurement, not a guess.
        import os
        logical_cores = os.cpu_count()
    if logical_cores is None:
        unavailable.append("logical_cores")

    physical_cores = _sysctl_int("hw.physicalcpu")
    if physical_cores is None:
        unavailable.append("physical_cores")

    total_ram_bytes = _sysctl_int("hw.memsize")
    if total_ram_bytes is None:
        unavailable.append("total_ram_bytes")

    mac_ver = platform.mac_ver()[0]
    macos_version = mac_ver or None
    if macos_version is None:
        unavailable.append("macos_version")

    return HardwareSpecs(
        mac_model=mac_model,
        architecture=platform.machine(),
        cpu_brand=cpu_brand,
        logical_cores=logical_cores,
        physical_cores=physical_cores,
        total_ram_bytes=total_ram_bytes,
        macos_version=macos_version,
        python_version=sys.version.split()[0],
        secure_version=SECURE_VERSION,
        unavailable=unavailable,
    )
