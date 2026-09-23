"""Tests for Phase 51: Extended Playbook Library."""

import pytest
from secure.remediation.playbooks import PlaybookEngine
from secure.remediation.models import RiskLevel


class TestPhase51Playbooks:
    """Verify all Phase 51 playbooks load and are properly configured."""

    def test_persistence_registry_playbook_exists(self):
        """Registry persistence playbook is defined."""
        engine = PlaybookEngine()
        playbook = engine.get_playbook("incident.persistence-registry")
        assert playbook is not None
        assert playbook.name == "Windows Registry Persistence Response"
        assert playbook.severity == RiskLevel.HIGH
        assert playbook.first_shipped_in == "51"

    def test_persistence_registry_has_finding_types(self):
        """Registry playbook includes relevant finding types."""
        engine = PlaybookEngine()
        playbook = engine.get_playbook("incident.persistence-registry")
        expected_types = ["persistence.registry-run-key", "persistence.registry-runonce", "file_change.registry"]
        for ft in expected_types:
            assert ft in playbook.trigger.finding_types

    def test_persistence_registry_has_threshold(self):
        """Registry playbook has anomaly threshold."""
        engine = PlaybookEngine()
        playbook = engine.get_playbook("incident.persistence-registry")
        assert playbook.trigger.anomaly_threshold == 65.0

    def test_lsass_dump_playbook_exists(self):
        """LSASS dump playbook is defined."""
        engine = PlaybookEngine()
        playbook = engine.get_playbook("incident.lsass-dump")
        assert playbook is not None
        assert playbook.name == "LSASS Memory Dump Attack Response"
        assert playbook.severity == RiskLevel.HIGH
        assert playbook.first_shipped_in == "51"

    def test_lsass_dump_has_steps(self):
        """LSASS playbook has 4 steps."""
        engine = PlaybookEngine()
        playbook = engine.get_playbook("incident.lsass-dump")
        assert len(playbook.steps) == 4
        assert playbook.steps[0].remediation_id == "process.kill-suspicious"

    def test_dcom_lateral_movement_playbook_exists(self):
        """DCOM lateral movement playbook is defined."""
        engine = PlaybookEngine()
        playbook = engine.get_playbook("incident.dcom-lateral-movement")
        assert playbook is not None
        assert "DCOM" in playbook.name
        assert playbook.severity == RiskLevel.HIGH

    def test_webshell_execution_playbook_exists(self):
        """Webshell execution playbook is defined."""
        engine = PlaybookEngine()
        playbook = engine.get_playbook("incident.webshell-execution")
        assert playbook is not None
        assert "Webshell" in playbook.name
        assert playbook.trigger.anomaly_threshold == 80.0

    def test_data_staging_playbook_exists(self):
        """Data staging playbook is defined."""
        engine = PlaybookEngine()
        playbook = engine.get_playbook("incident.data-staging")
        assert playbook is not None
        assert "Data Staging" in playbook.name
        assert len(playbook.steps) == 4

    def test_all_phase_51_playbooks_enabled(self):
        """All Phase 51 playbooks are enabled by default."""
        engine = PlaybookEngine()
        phase_51_playbooks = [
            "incident.persistence-registry",
            "incident.lsass-dump",
            "incident.dcom-lateral-movement",
            "incident.webshell-execution",
            "incident.data-staging",
        ]
        for pb_id in phase_51_playbooks:
            playbook = engine.get_playbook(pb_id)
            assert playbook.enabled is True, f"{pb_id} should be enabled"

    def test_phase_51_playbooks_in_list(self):
        """Phase 51 playbooks appear in playbook list."""
        engine = PlaybookEngine()
        all_playbooks = engine.list_playbooks()
        playbook_ids = [p.id for p in all_playbooks]

        phase_51_ids = [
            "incident.persistence-registry",
            "incident.lsass-dump",
            "incident.dcom-lateral-movement",
            "incident.webshell-execution",
            "incident.data-staging",
        ]
        for pb_id in phase_51_ids:
            assert pb_id in playbook_ids, f"{pb_id} should be in playbook list"

    def test_total_playbooks_count(self):
        """Now have 10 total playbooks (5 original + 5 Phase 51)."""
        engine = PlaybookEngine()
        all_playbooks = engine.list_playbooks()
        assert len(all_playbooks) == 10, f"Expected 10 playbooks, got {len(all_playbooks)}"


class TestPhase51PlaybookDiscovery:
    """Verify playbooks are discoverable by their triggers."""

    def test_find_registry_playbook_by_finding(self):
        """Registry playbook found by registry finding."""
        engine = PlaybookEngine()
        playbooks = engine.find_applicable_playbooks(
            finding_types=["persistence.registry-run-key"],
            anomaly_score=75.0,
        )
        assert len(playbooks) > 0
        assert any(p.id == "incident.persistence-registry" for p in playbooks)

    def test_lsass_playbook_requires_high_anomaly(self):
        """LSASS playbook requires anomaly_score >= 75."""
        engine = PlaybookEngine()
        playbooks_low = engine.find_applicable_playbooks(
            finding_types=["process.suspicious-lsass-access"],
            anomaly_score=70.0,
        )
        playbooks_high = engine.find_applicable_playbooks(
            finding_types=["process.suspicious-lsass-access"],
            anomaly_score=80.0,
        )
        assert not any(p.id == "incident.lsass-dump" for p in playbooks_low)
        assert any(p.id == "incident.lsass-dump" for p in playbooks_high)

    def test_webshell_highest_threshold(self):
        """Webshell playbook has highest threshold (80)."""
        engine = PlaybookEngine()
        playbook = engine.get_playbook("incident.webshell-execution")
        assert playbook.trigger.anomaly_threshold == 80.0


class TestPhase51Actions:
    """Verify new remediation actions are properly registered."""

    def test_registry_clear_action_defined(self):
        """registry.clear-persistence action exists."""
        from secure.remediation.catalog import get_action
        action = get_action("registry.clear-persistence")
        assert action is not None
        assert action.risk_level == RiskLevel.HIGH

    def test_process_kill_action_defined(self):
        """process.kill-suspicious action exists."""
        from secure.remediation.catalog import get_action
        action = get_action("process.kill-suspicious")
        assert action is not None
        assert action.first_shipped_in == "51"

    def test_block_dcom_action_defined(self):
        """process.block-dcom action exists."""
        from secure.remediation.catalog import get_action
        action = get_action("process.block-dcom")
        assert action is not None

    def test_quarantine_webshell_action_defined(self):
        """file.quarantine-webshell action exists."""
        from secure.remediation.catalog import get_action
        action = get_action("file.quarantine-webshell")
        assert action is not None

    def test_block_exfil_action_defined(self):
        """network.block-exfil-destinations action exists."""
        from secure.remediation.catalog import get_action
        action = get_action("network.block-exfil-destinations")
        assert action is not None


class TestPhase51ApprovalPolicies:
    """Verify approval policies for new actions."""

    def test_all_phase_51_actions_have_policies(self):
        """All Phase 51 actions have approval policies."""
        from secure.remediation.approval import ApprovalEngine
        engine = ApprovalEngine()

        phase_51_actions = [
            "registry.clear-persistence",
            "process.kill-suspicious",
            "process.block-dcom",
            "file.quarantine-webshell",
            "network.block-exfil-destinations",
        ]
        for action_id in phase_51_actions:
            policy = engine.get_policy(action_id)
            assert policy is not None, f"No policy for {action_id}"

    def test_phase_51_actions_require_approval(self):
        """All Phase 51 actions require approval (HIGH risk)."""
        from secure.remediation.approval import ApprovalEngine
        engine = ApprovalEngine()

        phase_51_actions = [
            "registry.clear-persistence",
            "process.kill-suspicious",
            "process.block-dcom",
            "file.quarantine-webshell",
            "network.block-exfil-destinations",
        ]
        for action_id in phase_51_actions:
            policy = engine.get_policy(action_id)
            assert policy.approval_required is True, f"{action_id} should require approval"
            assert policy.risk_level == RiskLevel.HIGH


class TestPhase51MitreMappings:
    """Verify MITRE technique mappings for Phase 51 findings."""

    def test_registry_findings_mapped(self):
        """Registry findings map to T1112."""
        from secure.intelligence.mitre_mapper import MitreMapper
        mapper = MitreMapper()

        mappings = mapper.map_finding("f1", "persistence.registry-run-key")
        assert len(mappings) == 1
        assert mappings[0].technique_id == "T1112"

    def test_lsass_findings_mapped(self):
        """LSASS findings map to T1003.001."""
        from secure.intelligence.mitre_mapper import MitreMapper
        mapper = MitreMapper()

        mappings = mapper.map_finding("f1", "process.suspicious-lsass-access")
        assert len(mappings) == 1
        assert mappings[0].technique_id == "T1003.001"

    def test_dcom_findings_mapped(self):
        """DCOM findings map to T1021.003."""
        from secure.intelligence.mitre_mapper import MitreMapper
        mapper = MitreMapper()

        mappings = mapper.map_finding("f1", "network.dcom-lateral-movement")
        assert len(mappings) == 1
        assert mappings[0].technique_id == "T1021.003"

    def test_webshell_findings_mapped(self):
        """Webshell findings map to T1505.004."""
        from secure.intelligence.mitre_mapper import MitreMapper
        mapper = MitreMapper()

        mappings = mapper.map_finding("f1", "file.webshell-execution")
        assert len(mappings) == 1
        assert mappings[0].technique_id == "T1505.004"

    def test_data_staging_findings_mapped(self):
        """Data staging findings map to T1074."""
        from secure.intelligence.mitre_mapper import MitreMapper
        mapper = MitreMapper()

        mappings = mapper.map_finding("f1", "network.data-staging")
        assert len(mappings) == 1
        assert mappings[0].technique_id == "T1074"
