"""
MITRE ATT&CK reference — pure data.

A small, honestly-scoped table of technique IDs/names used to give scenarios
realistic identifiers. Not a live fetcher; data copied from MITRE ATT&CK's
public docs as of implementation and not guaranteed current.

Relocated from validate/ to foundation tier for Phase 50 intelligence reuse.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str
    reference_note: str


T1547_011 = Technique(
    technique_id="T1547.011",
    name="Boot or Logon Autostart Execution: Plist Modification",
    tactic="Persistence",
    reference_note="A LaunchAgent/LaunchDaemon plist registering a program to run automatically.",
)

T1036_005 = Technique(
    technique_id="T1036.005",
    name="Masquerading: Match Legitimate Name or Location",
    tactic="Defense Evasion",
    reference_note="A file placed in, or renamed to resemble, a legitimate-looking location.",
)

T1204_002 = Technique(
    technique_id="T1204.002",
    name="User Execution: Malicious File",
    tactic="Execution",
    reference_note="An unsigned or ad-hoc-signed executable run from an unusual location.",
)

T1571 = Technique(
    technique_id="T1571",
    name="Non-Standard Port",
    tactic="Command and Control",
    reference_note="A service listening on a port not conventionally associated with it.",
)

T1071_001 = Technique(
    technique_id="T1071.001",
    name="Application Layer Protocol: Web Protocols",
    tactic="Command and Control",
    reference_note="An outbound connection to a previously-unseen remote destination.",
)

T1562_001 = Technique(
    technique_id="T1562.001",
    name="Impair Defenses: Disable or Modify Tools",
    tactic="Defense Evasion",
    reference_note="Used here to model a sensor/tool becoming unavailable, not an attack payload.",
)

REGISTRY = {
    t.technique_id: t
    for t in (T1547_011, T1036_005, T1204_002, T1571, T1071_001, T1562_001)
}
