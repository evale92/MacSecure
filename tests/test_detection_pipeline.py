"""
Phase 54: Detection Pipeline Integration Tests.

Tests the complete flow: baseline anomalies → correlation → alert decision.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from secure.detection_pipeline.orchestrator import (
    DetectionPipeline,
    AnomalyEventSummary,
    run_detection_pipeline,
)
from secure.storage.database import Database, init_schema
from secure.storage.models.baseline import add_anomaly_event


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """Create temporary database."""
    return tmp_path / "test.db"


@pytest.fixture
def db(db_path: Path):
    """Create and initialize database."""
    with Database(db_path) as database:
        init_schema(database.conn)
        yield database


class TestDetectionPipeline:
    """Tests for detection pipeline orchestration."""

    def test_fetch_recent_anomalies_empty(self, db: Database):
        """Test fetching anomalies when none exist."""
        pipeline = DetectionPipeline(db.conn)
        anomalies = pipeline.fetch_recent_anomalies(minutes=5)
        assert len(anomalies) == 0

    def test_fetch_recent_anomalies_single(self, db: Database):
        """Test fetching a single recent anomaly."""
        now = datetime.now(timezone.utc)
        event, _ = add_anomaly_event(
            db.conn,
            run_id="run1",
            entity_type="process",
            entity_key="/usr/bin/curl",
            feature_name="signing_status",
            observed_value="unsigned",
            observed_at=now.isoformat(),
            expected_summary="Process was expected to be signed.",
            score_breakdown={"behavior_change": 20},
            anomaly_score=20,
            anomaly_tier="low",
            maturity_state_at_time="established",
            eligible_weight_total_at_time=5.0,
            eligible_distinct_days_at_time=5,
            source_table="processes",
            source_id=1,
        )

        pipeline = DetectionPipeline(db.conn)
        anomalies = pipeline.fetch_recent_anomalies(minutes=5)

        assert len(anomalies) == 1
        assert anomalies[0].entity_type == "process"
        assert anomalies[0].entity_path == "/usr/bin/curl"
        assert anomalies[0].anomaly_tier == "low"
        assert anomalies[0].raw_score == 20

    def test_fetch_recent_anomalies_filters_by_time(self, db: Database):
        """Test that only recent anomalies are returned."""
        old_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        add_anomaly_event(
            db.conn,
            run_id="run1",
            entity_type="process",
            entity_key="/old/process",
            feature_name="signing_status",
            observed_value="unsigned",
            observed_at=old_time.isoformat(),
            expected_summary="Old process.",
            score_breakdown={"behavior_change": 20},
            anomaly_score=20,
            anomaly_tier="low",
            maturity_state_at_time="established",
            eligible_weight_total_at_time=5.0,
            eligible_distinct_days_at_time=5,
            source_table="processes",
            source_id=1,
        )

        recent_time = datetime.now(timezone.utc) - timedelta(minutes=2)
        add_anomaly_event(
            db.conn,
            run_id="run2",
            entity_type="process",
            entity_key="/recent/process",
            feature_name="signing_status",
            observed_value="unsigned",
            observed_at=recent_time.isoformat(),
            expected_summary="Recent process.",
            score_breakdown={"behavior_change": 20},
            anomaly_score=20,
            anomaly_tier="low",
            maturity_state_at_time="established",
            eligible_weight_total_at_time=5.0,
            eligible_distinct_days_at_time=5,
            source_table="processes",
            source_id=2,
        )

        pipeline = DetectionPipeline(db.conn)
        anomalies = pipeline.fetch_recent_anomalies(minutes=5)

        assert len(anomalies) == 1
        assert anomalies[0].entity_path == "/recent/process"

    def test_run_detection_pipeline_single(self, db: Database):
        """Test running the full detection pipeline."""
        now = datetime.now(timezone.utc)
        add_anomaly_event(
            db.conn,
            run_id="run1",
            entity_type="process",
            entity_key="/usr/bin/curl",
            feature_name="signing_status",
            observed_value="unsigned",
            observed_at=now.isoformat(),
            expected_summary="Process was expected to be signed.",
            score_breakdown={"behavior_change": 20},
            anomaly_score=20,
            anomaly_tier="low",
            maturity_state_at_time="established",
            eligible_weight_total_at_time=5.0,
            eligible_distinct_days_at_time=5,
            source_table="processes",
            source_id=1,
        )

        results = run_detection_pipeline(db.conn, lookback_minutes=5)

        assert len(results) == 1
        assert results[0].anomaly_summary.entity_path == "/usr/bin/curl"
        assert results[0].error is None

    def test_run_detection_pipeline_no_anomalies(self, db: Database):
        """Test running pipeline with no recent anomalies."""
        results = run_detection_pipeline(db.conn, lookback_minutes=5)
        assert len(results) == 0

    def test_anomaly_event_summary(self):
        """Test AnomalyEventSummary dataclass."""
        now = datetime.now(timezone.utc)
        summary = AnomalyEventSummary(
            event_id=1,
            run_id="run1",
            entity_type="process",
            entity_path="/usr/bin/curl",
            feature_name="signing_status",
            feature_value="unsigned",
            observed_at=now,
            anomaly_tier="low",
            raw_score=20,
            expected_summary="Expected signed.",
            score_breakdown={"behavior_change": 20},
            device_id="laptop-001",
        )

        assert summary.event_id == 1
        assert summary.entity_type == "process"
        assert summary.device_id == "laptop-001"

    def test_process_anomaly_error_handling(self, db: Database):
        """Test that anomaly processing captures errors gracefully."""
        now = datetime.now(timezone.utc)
        summary = AnomalyEventSummary(
            event_id=999,  # Non-existent ID
            run_id="run1",
            entity_type="process",
            entity_path="/usr/bin/curl",
            feature_name="signing_status",
            feature_value="unsigned",
            observed_at=now,
            anomaly_tier="low",
            raw_score=20,
            expected_summary="Expected signed.",
            score_breakdown={"behavior_change": 20},
        )

        pipeline = DetectionPipeline(db.conn)
        result = pipeline.process_anomaly(summary, {})

        # Should have an error but not crash
        assert result.anomaly_summary.entity_path == "/usr/bin/curl"


class TestDetectionPipelineCLI:
    """Tests for detection pipeline CLI."""

    def test_cli_run_no_anomalies(self, db: Database, capsys):
        """Test CLI output when no anomalies exist."""
        from secure.cli.detection_pipeline import DetectionPipelineCLI

        def mock_get_db():
            return db

        cli = DetectionPipelineCLI()
        cli._get_db = mock_get_db

        result = cli.cmd_run(lookback_minutes=5, json_output=False)
        assert result == 0

        captured = capsys.readouterr()
        assert "Total processed: 0" in captured.out

    def test_cli_run_with_anomalies(self, db: Database, capsys):
        """Test CLI output with anomalies."""
        from secure.cli.detection_pipeline import DetectionPipelineCLI

        now = datetime.now(timezone.utc)
        add_anomaly_event(
            db.conn,
            run_id="run1",
            entity_type="process",
            entity_key="/usr/bin/curl",
            feature_name="signing_status",
            observed_value="unsigned",
            observed_at=now.isoformat(),
            expected_summary="Process was expected to be signed.",
            score_breakdown={"behavior_change": 20},
            anomaly_score=20,
            anomaly_tier="low",
            maturity_state_at_time="established",
            eligible_weight_total_at_time=5.0,
            eligible_distinct_days_at_time=5,
            source_table="processes",
            source_id=1,
        )

        def mock_get_db():
            return db

        cli = DetectionPipelineCLI()
        cli._get_db = mock_get_db

        result = cli.cmd_run(lookback_minutes=5, json_output=False)
        assert result == 0

        captured = capsys.readouterr()
        assert "Detection pipeline results:" in captured.out

    def test_cli_run_json_output(self, db: Database, capsys):
        """Test CLI JSON output."""
        from secure.cli.detection_pipeline import DetectionPipelineCLI
        import json

        now = datetime.now(timezone.utc)
        add_anomaly_event(
            db.conn,
            run_id="run1",
            entity_type="process",
            entity_key="/usr/bin/curl",
            feature_name="signing_status",
            observed_value="unsigned",
            observed_at=now.isoformat(),
            expected_summary="Process was expected to be signed.",
            score_breakdown={"behavior_change": 20},
            anomaly_score=20,
            anomaly_tier="low",
            maturity_state_at_time="established",
            eligible_weight_total_at_time=5.0,
            eligible_distinct_days_at_time=5,
            source_table="processes",
            source_id=1,
        )

        def mock_get_db():
            return db

        cli = DetectionPipelineCLI()
        cli._get_db = mock_get_db

        result = cli.cmd_run(lookback_minutes=5, json_output=True)
        assert result == 0

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "total" in output
        assert "processed" in output
        assert "events" in output
