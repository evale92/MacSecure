"""Tests for MITRE mapper (Phase 50.2)."""

import pytest

from secure.intelligence.mitre_mapper import MitreMapper, FINDING_TO_TECHNIQUE
from secure.intelligence.models import CONF_CONFIRMED, CONF_LIKELY, CONF_POSSIBLE
from secure.knowledge.attck import REGISTRY


def test_mapper_initializes():
    """Mapper initializes and validates rules."""
    mapper = MitreMapper()
    assert mapper is not None
    assert len(mapper.rules) > 0


def test_mapper_validates_all_techniques_exist():
    """Mapper initialization fails if a technique doesn't exist in REGISTRY."""
    mapper = MitreMapper()
    for finding_type, rule in mapper.rules.items():
        technique_id = rule["technique_id"]
        assert technique_id in REGISTRY, f"Technique {technique_id} not in REGISTRY"


def test_map_unsigned_executable():
    """Unsigned executable maps to User Execution technique."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("f1", "persistence.unsigned_executable")
    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1204.002"
    assert mappings[0].confidence == CONF_CONFIRMED
    assert mappings[0].tactic == "Execution"


def test_map_launchagent():
    """LaunchAgent maps to Boot/Logon Autostart Execution."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("f1", "persistence.launchagent")
    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1547.011"
    assert mappings[0].tactic == "Persistence"


def test_map_launchdaemon():
    """LaunchDaemon maps to same technique as LaunchAgent."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("f1", "persistence.launchdaemon")
    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1547.011"
    assert mappings[0].tactic == "Persistence"


def test_map_c2_exfiltration():
    """C2 exfiltration maps to Application Layer Protocol."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("f1", "network.c2_exfiltration")
    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1071.001"
    assert mappings[0].confidence == CONF_CONFIRMED
    assert mappings[0].tactic == "Command and Control"


def test_map_unknown_finding_returns_empty():
    """Unknown finding type returns empty list."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("f1", "unknown.finding_type")
    assert len(mappings) == 0


def test_map_empty_finding_type_returns_empty():
    """Empty finding type returns empty list."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("f1", "")
    assert len(mappings) == 0


def test_mapping_preserves_finding_id():
    """Finding ID is preserved in mapping."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("finding_xyz", "persistence.launchagent")
    assert len(mappings) == 1
    assert mappings[0].finding_id == "finding_xyz"


def test_mapping_preserves_finding_type():
    """Finding type is preserved in mapping."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("f1", "persistence.launchagent")
    assert len(mappings) == 1
    assert mappings[0].finding_type == "persistence.launchagent"


def test_mapping_includes_technique_name():
    """Technique name from REGISTRY is included."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("f1", "persistence.launchagent")
    assert len(mappings) == 1
    assert "Plist Modification" in mappings[0].technique_name


def test_mapping_includes_rationale():
    """Mapping includes human-readable rationale."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("f1", "persistence.launchagent")
    assert len(mappings) == 1
    assert len(mappings[0].rationale) > 0


def test_confidence_levels_vary():
    """Different findings have different confidence levels."""
    mapper = MitreMapper()

    confirmed = mapper.map_finding("f1", "persistence.unsigned_executable")
    likely = mapper.map_finding("f2", "persistence.unauthorized_launchagent")
    possible = mapper.map_finding("f3", "file_change.launchagent")

    assert len(confirmed) == 1
    assert len(likely) == 1
    assert len(possible) == 1

    assert confirmed[0].confidence == CONF_CONFIRMED
    assert likely[0].confidence == CONF_LIKELY
    assert possible[0].confidence == CONF_POSSIBLE


def test_all_mapped_techniques_exist_in_registry():
    """Every technique in FINDING_TO_TECHNIQUE exists in REGISTRY."""
    for finding_type, rule in FINDING_TO_TECHNIQUE.items():
        technique_id = rule["technique_id"]
        assert technique_id in REGISTRY, f"Technique {technique_id} not in REGISTRY"


def test_mapping_source_defaults_to_builtin():
    """Mapping source defaults to 'builtin'."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("f1", "persistence.launchagent")
    assert len(mappings) == 1
    assert mappings[0].source == "builtin"


def test_unusual_port_maps_correctly():
    """Unusual port detection maps to Non-Standard Port technique."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("f1", "network.unusual_port")
    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1571"
    assert mappings[0].tactic == "Command and Control"


def test_masquerading_maps_correctly():
    """Masquerading detection maps to Masquerading technique."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("f1", "evasion.masquerading")
    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1036.005"
    assert mappings[0].tactic == "Defense Evasion"


def test_tool_disabled_maps_correctly():
    """Tool disabled maps to Impair Defenses technique."""
    mapper = MitreMapper()
    mappings = mapper.map_finding("f1", "defense_evasion.tool_disabled")
    assert len(mappings) == 1
    assert mappings[0].technique_id == "T1562.001"
    assert mappings[0].tactic == "Defense Evasion"
