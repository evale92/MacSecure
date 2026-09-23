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

# Phase 51: Extended Playbooks techniques
T1112 = Technique(
    technique_id="T1112",
    name="Modify Registry",
    tactic="Defense Evasion",
    reference_note="Registry entries modified for persistence or to disable defenses.",
)

T1003_001 = Technique(
    technique_id="T1003.001",
    name="OS Credential Dumping: LSASS Memory",
    tactic="Credential Access",
    reference_note="Process attempts to access LSASS memory for credential extraction.",
)

T1021_003 = Technique(
    technique_id="T1021.003",
    name="Remote Services: Distributed Component Object Model",
    tactic="Lateral Movement",
    reference_note="DCOM exploitation for lateral movement across network.",
)

T1505_004 = Technique(
    technique_id="T1505.004",
    name="Server Software Component: IIS Components",
    tactic="Persistence",
    reference_note="Webshell uploaded and executed on web server.",
)

T1074 = Technique(
    technique_id="T1074",
    name="Data Staged",
    tactic="Collection",
    reference_note="Files collected and staged for exfiltration.",
)

T1020 = Technique(
    technique_id="T1020",
    name="Automated Exfiltration",
    tactic="Exfiltration",
    reference_note="Connection to exfiltration destination for automated data transfer.",
)

REGISTRY = {
    t.technique_id: t
    for t in (T1547_011, T1036_005, T1204_002, T1571, T1071_001, T1562_001, T1112, T1003_001, T1021_003, T1505_004, T1074, T1020)
}
