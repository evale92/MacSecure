"""
Tests for Phase 48 remediation catalog.
"""

import pytest

from secure.remediation.catalog import (
    load_catalog,
    get_action,
    list_actions,
)
from secure.remediation.models import (
    RiskLevel,
    VerificationType,
    RemediationAction,
)


class TestCatalogLoading:
    """Test catalog loading and access."""

    def test_load_catalog_returns_dict(self):
        """load_catalog returns a dict of actions."""
        catalog = load_catalog()
        assert isinstance(catalog, dict)
        assert len(catalog) >= 12  # Phase 48 ships at least 12

    def test_load_catalog_returns_copy(self):
        """load_catalog returns a copy, not the original."""
        c1 = load_catalog()
        c2 = load_catalog()
        assert c1 is not c2
        assert c1 == c2

    def test_get_action_firewall_enable(self):
        """Can retrieve firewall.enable action."""
        action = get_action("firewall.enable")
        assert action is not None
        assert action.id == "firewall.enable"
        assert action.name == "Enable macOS firewall"
        assert action.risk_level == RiskLevel.LOW

    def test_get_action_service_disable(self):
        """Can retrieve service.disable-launchagent action."""
        action = get_action("service.disable-launchagent")
        assert action is not None
        assert action.risk_level == RiskLevel.MEDIUM

    def test_get_action_nonexistent_returns_none(self):
        """get_action returns None for nonexistent action."""
        action = get_action("nonexistent.action")
        assert action is None


class TestActionProperties:
    """Test properties of loaded actions."""

    def test_all_actions_have_required_fields(self):
        """All actions have required fields."""
        catalog = load_catalog()
        required = ["id", "name", "description", "risk_level", "action_type"]

        for action_id, action in catalog.items():
            assert action.id == action_id
            for field in required:
                assert getattr(action, field) is not None

    def test_all_actions_have_verification(self):
        """All actions have a verification method."""
        catalog = load_catalog()
        for action in catalog.values():
            assert action.verification is not None
            assert action.verification.type in VerificationType

    def test_firewall_actions_exist(self):
        """Firewall actions are in catalog."""
        actions = list_actions(action_type="firewall")
        action_ids = [a.id for a in actions]
        assert "firewall.enable" in action_ids
        assert "firewall.block-inbound" in action_ids

    def test_ssh_actions_exist(self):
        """SSH actions are in catalog."""
        actions = list_actions(action_type="ssh")
        action_ids = [a.id for a in actions]
        assert "ssh.disable-root-login" in action_ids
        assert "ssh.disable-password-auth" in action_ids

    def test_service_actions_exist(self):
        """Service actions are in catalog."""
        actions = list_actions(action_type="service")
        action_ids = [a.id for a in actions]
        assert "service.disable-launchagent" in action_ids
        assert "service.disable-launchdaemon" in action_ids


class TestListActions:
    """Test list_actions filtering."""

    def test_list_all_actions(self):
        """list_actions with no filter returns all."""
        actions = list_actions(enabled_only=False)
        assert len(actions) >= 12

    def test_list_low_risk_only(self):
        """Can filter by risk level."""
        actions = list_actions(risk_level="low")
        assert all(a.risk_level == RiskLevel.LOW for a in actions)
        assert len(actions) >= 5  # Phase 48 has at least 5 low-risk

    def test_list_medium_risk_only(self):
        """Can filter to medium-risk actions."""
        actions = list_actions(risk_level="medium")
        assert all(a.risk_level == RiskLevel.MEDIUM for a in actions)
        assert len(actions) >= 4

    def test_list_high_risk_only(self):
        """Can filter to high-risk actions."""
        actions = list_actions(risk_level="high")
        assert all(a.risk_level == RiskLevel.HIGH for a in actions)
        assert len(actions) >= 1

    def test_list_by_action_type(self):
        """Can filter by action type."""
        firewall_actions = list_actions(action_type="firewall")
        assert all(a.action_type == "firewall" for a in firewall_actions)

        ssh_actions = list_actions(action_type="ssh")
        assert all(a.action_type == "ssh" for a in ssh_actions)

    def test_list_combined_filters(self):
        """Can use multiple filters together."""
        actions = list_actions(
            risk_level="low",
            action_type="firewall",
        )
        assert all(a.risk_level == RiskLevel.LOW for a in actions)
        assert all(a.action_type == "firewall" for a in actions)

    def test_list_sorted_by_id(self):
        """list_actions returns results sorted by ID."""
        actions = list_actions()
        ids = [a.id for a in actions]
        assert ids == sorted(ids)


class TestRiskLevels:
    """Test risk level distribution."""

    def test_low_risk_actions_have_auto_executable_verification(self):
        """Low-risk actions should be quick to verify."""
        actions = list_actions(risk_level="low")
        # Most should be CONFIG_CHECK or MANUAL, not SCAN_COMPARISON
        for action in actions:
            assert action.verification.type in [
                VerificationType.CONFIG_CHECK,
                VerificationType.MANUAL,
                VerificationType.PROCESS_CHECK,
                VerificationType.FILE_CHECK,
            ]

    def test_high_risk_actions_require_careful_verification(self):
        """High-risk actions should require careful verification."""
        actions = list_actions(risk_level="high")
        assert len(actions) >= 1
        # High-risk should have explicit verification
        for action in actions:
            assert action.verification is not None


class TestExamplesAndReferences:
    """Test that actions have documentation."""

    def test_actions_have_mitre_references(self):
        """Critical actions reference MITRE ATT&CK."""
        critical_actions = [
            get_action("ssh.disable-root-login"),
            get_action("firewall.enable"),
            get_action("network.isolate-destination"),
        ]
        for action in critical_actions:
            assert len(action.references) >= 1

    def test_persistence_actions_referenced(self):
        """Service-disable actions have examples."""
        action = get_action("service.disable-launchagent")
        assert len(action.examples) >= 1
        assert "persistence" in action.examples[0].lower()


class TestRemediationActionCreation:
    """Test creating new RemediationAction instances."""

    def test_create_custom_action(self):
        """Can create a custom remediation action."""
        action = RemediationAction(
            id="test.custom",
            name="Test Custom Action",
            description="A test action",
            risk_level=RiskLevel.LOW,
            action_type="test",
        )
        assert action.id == "test.custom"
        assert action.risk_level == RiskLevel.LOW
        assert action.enabled is True

    def test_action_with_prerequisites(self):
        """Actions can have prerequisites."""
        action = RemediationAction(
            id="test.with-prereqs",
            name="Action with prerequisites",
            description="Requires other actions",
            risk_level=RiskLevel.MEDIUM,
            action_type="test",
            prerequisites=["firewall.enable", "ssh.disable-root-login"],
        )
        assert len(action.prerequisites) == 2
        assert "firewall.enable" in action.prerequisites


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
