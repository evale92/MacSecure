"""MITRE mapper — map findings to ATT&CK techniques (Phase 50.2)."""

from __future__ import annotations

from secure.intelligence.models import MitreMapping, CONF_CONFIRMED, CONF_LIKELY, CONF_POSSIBLE
from secure.knowledge.attck import REGISTRY


FINDING_TO_TECHNIQUE = {
    "persistence.unsigned_executable": {
        "technique_id": "T1204.002",
        "confidence": CONF_CONFIRMED,
        "rationale": "Unsigned executable executed from unusual location matches User Execution.",
    },
    "persistence.launchagent": {
        "technique_id": "T1547.011",
        "confidence": CONF_CONFIRMED,
        "rationale": "LaunchAgent/LaunchDaemon persistence mechanism.",
    },
    "persistence.launchdaemon": {
        "technique_id": "T1547.011",
        "confidence": CONF_CONFIRMED,
        "rationale": "LaunchDaemon persistence mechanism.",
    },
    "persistence.unauthorized_launchagent": {
        "technique_id": "T1547.011",
        "confidence": CONF_LIKELY,
        "rationale": "Unexpected LaunchAgent indicates potential persistence.",
    },
    "persistence.unauthorized_launchdaemon": {
        "technique_id": "T1547.011",
        "confidence": CONF_LIKELY,
        "rationale": "Unexpected LaunchDaemon indicates potential persistence.",
    },
    "persistence.modified_agent": {
        "technique_id": "T1547.011",
        "confidence": CONF_LIKELY,
        "rationale": "Modified LaunchAgent suggests persistence modification.",
    },
    "evasion.masquerading": {
        "technique_id": "T1036.005",
        "confidence": CONF_LIKELY,
        "rationale": "File placed in legitimate-looking location.",
    },
    "file_change.launchagent": {
        "technique_id": "T1547.011",
        "confidence": CONF_POSSIBLE,
        "rationale": "File change in LaunchAgent directory.",
    },
    "network.unusual_port": {
        "technique_id": "T1571",
        "confidence": CONF_LIKELY,
        "rationale": "Service listening on non-standard port.",
    },
    "network.c2_communication": {
        "technique_id": "T1071.001",
        "confidence": CONF_LIKELY,
        "rationale": "Outbound connection to unknown remote destination.",
    },
    "network.c2_exfiltration": {
        "technique_id": "T1071.001",
        "confidence": CONF_CONFIRMED,
        "rationale": "Data exfiltration via HTTP/HTTPS.",
    },
    "defense_evasion.tool_disabled": {
        "technique_id": "T1562.001",
        "confidence": CONF_LIKELY,
        "rationale": "Security tool or sensor became unavailable.",
    },
}


class MitreMapper:
    """Map findings to MITRE ATT&CK techniques."""

    def __init__(self):
        """Initialize mapper with finding→technique rules."""
        self.rules = FINDING_TO_TECHNIQUE
        self._validate_rules()

    def _validate_rules(self) -> None:
        """Verify all technique IDs in rules exist in REGISTRY."""
        for finding_type, mapping in self.rules.items():
            technique_id = mapping["technique_id"]
            if technique_id not in REGISTRY:
                raise ValueError(f"Technique {technique_id} (from {finding_type}) not in REGISTRY")

    def map_finding(
        self,
        finding_id: str,
        finding_type: str,
    ) -> list[MitreMapping]:
        """Map a finding to MITRE techniques. Returns empty if no match."""
        rule = self.rules.get(finding_type)
        if not rule:
            return []

        technique_id = rule["technique_id"]
        technique = REGISTRY.get(technique_id)
        if not technique:
            return []

        mapping = MitreMapping(
            finding_id=finding_id,
            finding_type=finding_type,
            technique_id=technique_id,
            technique_name=technique.name,
            tactic=technique.tactic,
            confidence=rule["confidence"],
            rationale=rule["rationale"],
        )

        return [mapping]
