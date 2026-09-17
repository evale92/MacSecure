"""
checks/boot_security.py — firmware version and boot security policy.

Reads `/usr/sbin/system_profiler -json SPHardwareDataType SPiBridgeDataType`
(read-only, no sudo). On Apple silicon the iBridge section reports the
LocalPolicy: Secure Boot level, whether third-party kexts are allowed,
whether MDM may manage kexts, and the Signed System Volume and SIP flags.
Reduced or Permissive Security, allowed third-party kexts or a disabled
SSV each widen what can persist below the OS, so they are a WARNING. Intel
Macs report no iBridge policy; that is stated, not treated as full security.
Changing any of this needs Recovery mode and `bputil`/`csrutil`, which this
app never runs.
"""

from __future__ import annotations

import json

from secure.checks._shell import run
from secure.checks.models import CheckResult, CheckStatus

NAME = "Firmware and boot security"


def _evaluate(stdout: str) -> CheckResult:
    try:
        data = json.loads(stdout)
        hardware = (data.get("SPHardwareDataType") or [{}])[0]
        bridge = (data.get("SPiBridgeDataType") or [{}])[0]
    except (ValueError, AttributeError, IndexError, TypeError):
        return CheckResult(NAME, CheckStatus.WARNING, "Could not read system_profiler output.", "Run `system_profiler SPHardwareDataType SPiBridgeDataType` yourself in Terminal to check manually.")
    firmware = hardware.get("boot_rom_version")
    if not firmware:
        return CheckResult(NAME, CheckStatus.WARNING, "system_profiler reported no firmware version.", "Run `system_profiler SPHardwareDataType SPiBridgeDataType` yourself in Terminal to check manually.")
    loader = hardware.get("os_loader_version", "unknown")
    level = bridge.get("ibridge_secure_boot")
    if not level:
        return CheckResult(NAME, CheckStatus.WARNING,
                           f"Firmware {firmware}, OS loader {loader}. No Secure Boot policy reported "
                           "(Intel Mac or unreadable), so boot security was not verified.", "Run `system_profiler SPHardwareDataType SPiBridgeDataType` yourself in Terminal to check manually.")
    concerns = []
    if level != "Full Security":
        concerns.append(f"Secure Boot is '{level}'")
    if str(bridge.get("ibridge_sb_other_kext", "No")).lower() != "no":
        concerns.append("third-party kernel extensions are allowed")
    if str(bridge.get("ibridge_sb_manual_mdm", "No")).lower() != "no":
        concerns.append("user-approved MDM may manage kernel extensions")
    if str(bridge.get("ibridge_sb_ssv", "Enabled")).lower() != "enabled":
        concerns.append("Signed System Volume is not enabled")
    message = f"Firmware {firmware}, OS loader {loader}, Secure Boot: {level}."
    if concerns:
        return CheckResult(NAME, CheckStatus.WARNING, message + " " + "; ".join(concerns) + ".",
                           "Unless you changed this deliberately, restore Full Security in Recovery mode "
                           "(Startup Security Utility). This app never changes it for you.")
    return CheckResult(NAME, CheckStatus.PASS, message, "")


def check_boot_security() -> CheckResult:
    result = run(["/usr/sbin/system_profiler", "-json", "SPHardwareDataType", "SPiBridgeDataType"], timeout=30.0)
    if result.returncode is None or not result.ok:
        return CheckResult(NAME, CheckStatus.WARNING,
                           f"Could not run system_profiler ({(result.stderr or 'exit ' + str(result.returncode)).strip()}).", "Run `system_profiler SPHardwareDataType SPiBridgeDataType` yourself in Terminal to check manually.")
    return _evaluate(result.stdout)
