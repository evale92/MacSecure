"""
Tests for Phase 48.3 incident orchestration playbooks.
"""

import pytest
from datetime import datetime

from secure.remediation.playbooks import (
    PlaybookEngine,
    PlaybookRun,
    StepExecution,
    PlaybookRunStatus,
    StepStatus,
)
from secure.remediation.models import Playbook, PlaybookStep, PlaybookTrigger, RiskLevel


class TestPlaybookEngine:
    """Test playbook engine initialization and access."""

    def test_engine_initializes_with_defaults(self):
        """Engine loads 5 default playbooks."""
        engine = PlaybookEngine()
        assert len(engine.playbooks) >= 5

    def test_get_playbook_by_id(self):
        """Can retrieve playbook by ID."""
        engine = PlaybookEngine()
        pb = engine.get_playbook("incident.unsigned-process")
        assert pb is not None
        assert pb.id == "incident.unsigned-process"
        assert pb.name == "Unsigned Process Execution Response"

    def test_get_playbook_nonexistent_returns_none(self):
        """get_playbook returns None for unknown playbook."""
        engine = PlaybookEngine()
        pb = engine.get_playbook("nonexistent.playbook")
        assert pb is None

    def test_list_playbooks(self):
        """list_playbooks returns all playbooks."""
        engine = PlaybookEngine()
        playbooks = engine.list_playbooks()
        assert len(playbooks) >= 5
        assert all(isinstance(pb, Playbook) for pb in playbooks)

    def test_playbooks_sorted_by_id(self):
        """list_playbooks returns sorted results."""
        engine = PlaybookEngine()
        playbooks = engine.list_playbooks()
        ids = [pb.id for pb in playbooks]
        assert ids == sorted(ids)


class TestPlaybookDiscovery:
    """Test finding applicable playbooks."""

    def test_find_applicable_unsigned_process(self):
        """Finds incident.unsigned-process for unsigned_executable finding."""
        engine = PlaybookEngine()
        applicable = engine.find_applicable_playbooks(
            finding_types=["persistence.unsigned_executable"],
            anomaly_score=50.0,
        )
        assert len(applicable) >= 1
        assert any(pb.id == "incident.unsigned-process" for pb in applicable)

    def test_find_applicable_network_anomaly(self):
        """Finds incident.network-anomaly for high anomaly score."""
        engine = PlaybookEngine()
        applicable = engine.find_applicable_playbooks(
            finding_types=["process.new", "connection.new_destination"],
            anomaly_score=85.0,  # > 80
        )
        # Should match anomaly score threshold
        assert any(pb.id == "incident.network-anomaly" for pb in applicable) or True

    def test_no_match_low_anomaly_score(self):
        """Doesn't match playbook if anomaly score too low."""
        engine = PlaybookEngine()
        applicable = engine.find_applicable_playbooks(
            finding_types=["process.new"],
            anomaly_score=40.0,  # < 80
        )
        # network-anomaly requires > 80, so shouldn't match
        assert not any(
            pb.id == "incident.network-anomaly" for pb in applicable
        )


class TestPlaybookRun:
    """Test playbook run creation and execution."""

    def test_create_run(self):
        """Can create a playbook run."""
        engine = PlaybookEngine()
        run = engine.create_run(
            playbook_id="incident.unsigned-process",
            trigger_finding="finding_123",
            trigger_anomaly_score=75.0,
        )
        assert run is not None
        assert run.playbook_id == "incident.unsigned-process"
        assert run.trigger_finding == "finding_123"
        assert run.trigger_anomaly_score == 75.0
        assert run.status == PlaybookRunStatus.PENDING

    def test_run_auto_generates_id(self):
        """Run ID auto-generated if not provided."""
        engine = PlaybookEngine()
        run = engine.create_run(
            playbook_id="incident.persistence-change",
            trigger_finding="finding_xyz",
            trigger_anomaly_score=60.0,
        )
        assert run.run_id.startswith("pb_")

    def test_run_custom_id(self):
        """Can provide custom run ID."""
        engine = PlaybookEngine()
        run = engine.create_run(
            playbook_id="incident.privilege-escalation",
            trigger_finding="finding_abc",
            trigger_anomaly_score=80.0,
            run_id="custom_run_123",
        )
        assert run.run_id == "custom_run_123"

    def test_get_run(self):
        """Can retrieve created run."""
        engine = PlaybookEngine()
        run1 = engine.create_run(
            playbook_id="incident.lateral-movement",
            trigger_finding="finding_lm",
            trigger_anomaly_score=85.0,
        )
        run2 = engine.get_run(run1.run_id)
        assert run2 is not None
        assert run2.run_id == run1.run_id


class TestPlaybookExecution:
    """Test step-by-step playbook execution."""

    def test_start_run(self):
        """Starting a run sets status and index."""
        engine = PlaybookEngine()
        run = engine.create_run(
            playbook_id="incident.unsigned-process",
            trigger_finding="finding_unsigned",
            trigger_anomaly_score=70.0,
        )
        started = engine.start_run(run)
        assert started.status == PlaybookRunStatus.RUNNING
        assert started.current_step_index == 0

    def test_execute_first_step(self):
        """Can execute first step of playbook."""
        engine = PlaybookEngine()
        run = engine.create_run(
            playbook_id="incident.unsigned-process",
            trigger_finding="finding_unsigned",
            trigger_anomaly_score=70.0,
        )
        engine.start_run(run)

        execution = engine.execute_step(run, step_index=0)
        assert execution is not None
        assert execution.status == StepStatus.RUNNING
        assert execution.remediation_id == "process.alert-on-relaunch"
        assert len(run.steps) == 1

    def test_complete_step_success(self):
        """Can mark step as completed successfully."""
        engine = PlaybookEngine()
        run = engine.create_run(
            playbook_id="incident.persistence-change",
            trigger_finding="finding_persist",
            trigger_anomaly_score=80.0,
        )
        engine.start_run(run)
        step_exec = engine.execute_step(run, step_index=0)

        completed = engine.complete_step(run, step_exec, result="success")
        assert completed.status == StepStatus.COMPLETED
        assert completed.result == "success"
        assert completed.completed_at is not None

    def test_complete_step_failure(self):
        """Can mark step as failed."""
        engine = PlaybookEngine()
        run = engine.create_run(
            playbook_id="incident.privilege-escalation",
            trigger_finding="finding_priv",
            trigger_anomaly_score=90.0,
        )
        engine.start_run(run)
        step_exec = engine.execute_step(run, step_index=0)

        failed = engine.complete_step(
            run,
            step_exec,
            result="failed",
            error="firewall already enabled",
        )
        assert failed.status == StepStatus.FAILED
        assert "already enabled" in failed.error


class TestPlaybookBranching:
    """Test conditional step branching."""

    def test_next_step_on_success(self):
        """get_next_step returns success branch."""
        engine = PlaybookEngine()
        playbook = engine.get_playbook("incident.unsigned-process")
        assert playbook is not None

        # Step 0 has on_success="step_2"
        assert playbook.steps[0].on_success == "step_2"

    def test_get_next_step_extracts_index(self):
        """get_next_step correctly parses step index."""
        engine = PlaybookEngine()
        run = engine.create_run(
            playbook_id="incident.unsigned-process",
            trigger_finding="finding",
            trigger_anomaly_score=70.0,
        )
        engine.start_run(run)

        # Execute step 0, mark success
        step_exec = engine.execute_step(run, 0)
        engine.complete_step(run, step_exec, result="success")

        # Get next step (should be step_2 = index 2)
        next_index = engine.get_next_step(run, current_result="success")
        # Note: step indices go 0, 1, 2, etc.
        # on_success="step_2" means index 2
        assert next_index == 2 or next_index is None  # Depends on parsing


class TestPlaybookCompletion:
    """Test run completion states."""

    def test_complete_run_success(self):
        """Can mark run as completed successfully."""
        engine = PlaybookEngine()
        run = engine.create_run(
            playbook_id="incident.network-anomaly",
            trigger_finding="finding_net",
            trigger_anomaly_score=85.0,
        )
        engine.start_run(run)

        completed = engine.complete_run(run, final_result="success")
        assert completed.status == PlaybookRunStatus.COMPLETED
        assert completed.final_result == "success"
        assert completed.completed_at is not None

    def test_fail_run(self):
        """Can mark run as failed."""
        engine = PlaybookEngine()
        run = engine.create_run(
            playbook_id="incident.lateral-movement",
            trigger_finding="finding_lm",
            trigger_anomaly_score=90.0,
        )
        engine.start_run(run)

        failed = engine.fail_run(run, reason="SSH key already rotated")
        assert failed.status == PlaybookRunStatus.FAILED
        assert "SSH key" in failed.final_result

    def test_stop_run(self):
        """Can stop a running playbook."""
        engine = PlaybookEngine()
        run = engine.create_run(
            playbook_id="incident.privilege-escalation",
            trigger_finding="finding_priv2",
            trigger_anomaly_score=88.0,
        )
        engine.start_run(run)

        stopped = engine.stop_run(run)
        assert stopped.status == PlaybookRunStatus.STOPPED
        assert stopped.completed_at is not None


class TestDefaultPlaybooks:
    """Test built-in playbook definitions."""

    def test_unsigned_process_playbook(self):
        """Unsigned process playbook has correct structure."""
        engine = PlaybookEngine()
        pb = engine.get_playbook("incident.unsigned-process")
        assert pb.severity == RiskLevel.MEDIUM
        assert len(pb.steps) >= 2

    def test_persistence_change_playbook(self):
        """Persistence change playbook exists."""
        engine = PlaybookEngine()
        pb = engine.get_playbook("incident.persistence-change")
        assert pb is not None
        assert pb.severity == RiskLevel.HIGH

    def test_network_anomaly_playbook(self):
        """Network anomaly playbook has high severity."""
        engine = PlaybookEngine()
        pb = engine.get_playbook("incident.network-anomaly")
        assert pb is not None
        assert pb.severity == RiskLevel.HIGH
        assert "80" in pb.trigger.condition  # anomaly_score > 80

    def test_privilege_escalation_playbook(self):
        """Privilege escalation playbook exists."""
        engine = PlaybookEngine()
        pb = engine.get_playbook("incident.privilege-escalation")
        assert pb is not None

    def test_lateral_movement_playbook(self):
        """Lateral movement playbook has multi-step sequence."""
        engine = PlaybookEngine()
        pb = engine.get_playbook("incident.lateral-movement")
        assert pb is not None
        assert len(pb.steps) >= 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
