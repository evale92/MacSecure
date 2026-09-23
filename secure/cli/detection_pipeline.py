"""
Detection Pipeline CLI — Phase 54.

Commands for running and monitoring the detection pipeline.
"""

import json
import sqlite3
from typing import Optional

from secure.detection_pipeline.orchestrator import run_detection_pipeline
from secure.storage.database import Database


def _bootstrap():
    """Bootstrap config (same as other CLI modules)."""
    from secure.config import load_config
    return load_config()


class DetectionPipelineCLI:
    """CLI for detection pipeline operations."""

    def __init__(self):
        self.db = None

    def _get_db(self) -> Database:
        """Get database connection."""
        if not self.db:
            cfg = _bootstrap()
            self.db = Database(cfg.database_path())
        return self.db

    def cmd_run(self, lookback_minutes: int = 5, json_output: bool = False) -> int:
        """Run the detection pipeline on recent anomalies."""
        try:
            cfg = _bootstrap()
            with Database(cfg.database_path()) as db:
                results = run_detection_pipeline(db.conn, lookback_minutes=lookback_minutes)

                if json_output:
                    output = {
                        "total": len(results),
                        "processed": sum(1 for r in results if r.error is None),
                        "errors": sum(1 for r in results if r.error is not None),
                        "events": [
                            {
                                "anomaly_id": r.anomaly_summary.event_id,
                                "entity_type": r.anomaly_summary.entity_type,
                                "entity_path": r.anomaly_summary.entity_path,
                                "anomaly_tier": r.anomaly_summary.anomaly_tier,
                                "verdict": r.alert_decision.get("verdict") if r.alert_decision else None,
                                "final_severity": r.alert_decision.get("final_severity") if r.alert_decision else None,
                                "correlation_id": r.correlation_id,
                                "error": r.error,
                            }
                            for r in results
                        ]
                    }
                    print(json.dumps(output, indent=2, default=str))
                else:
                    print(f"Detection pipeline results:")
                    print(f"  Total processed: {len(results)}")
                    print(f"  Successful: {sum(1 for r in results if r.error is None)}")
                    print(f"  Errors: {sum(1 for r in results if r.error is not None)}")

                    for result in results:
                        if result.error:
                            print(f"  ✗ {result.anomaly_summary.entity_path}: {result.error}")
                        else:
                            verdict = result.alert_decision.get("verdict") if result.alert_decision else "UNKNOWN"
                            severity = result.alert_decision.get("final_severity") if result.alert_decision else "UNKNOWN"
                            print(f"  ✓ {result.anomaly_summary.entity_path}: {verdict} ({severity})")

            return 0

        except Exception as e:
            print(f"Error running detection pipeline: {e}")
            return 2
