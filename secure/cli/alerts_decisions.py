"""CLI commands for alert decisions (Phase 53).

Queries and reports on alert decision history, suppression verdicts, and escalation reasoning.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Optional

from secure.alerting.store import AlertDecisionStore


class AlertDecisionsCLI:
    """Command-line interface for alert decisions."""

    def __init__(self):
        self.store = AlertDecisionStore()

    def cmd_recent(self, limit: int = 20) -> None:
        """Print recent alert decisions."""
        decisions = self.store.get_recent_decisions(limit=limit)
        if not decisions:
            print("No recent decisions.")
            return

        print(f"\n{'ID':<8} {'Source':<20} {'Base':<8} {'Final':<8} {'Verdict':<20}")
        print("-" * 70)
        for decision in decisions:
            print(
                f"{decision.source_id:<8} {decision.source_table:<20} "
                f"{decision.base_severity:<8} {decision.final_severity:<8} "
                f"{decision.verdict:<20}"
            )

    def get_recent(self, limit: int = 20) -> dict:
        """Return recent decisions as dict (for JSON output)."""
        decisions = self.store.get_recent_decisions(limit=limit)
        return {
            "total": len(decisions),
            "decisions": [
                {
                    "source_table": d.source_table,
                    "source_id": d.source_id,
                    "base_severity": d.base_severity,
                    "verdict": d.verdict,
                    "final_severity": d.final_severity,
                    "reasoning": d.reasoning,
                }
                for d in decisions
            ],
        }

    def cmd_counts(self) -> None:
        """Print decision verdict counts."""
        counts = self.store.count_by_verdict()
        print("\nAlert Decision Verdicts:")
        print("-" * 40)
        for verdict, count in sorted(counts.items()):
            print(f"  {verdict:<25} {count:>10}")

    def get_counts(self) -> dict:
        """Return verdict counts as dict (for JSON output)."""
        return {"verdicts": self.store.count_by_verdict()}

    def cmd_detail(self, source_table: str, source_id: int) -> None:
        """Print detailed decision for a specific event."""
        decision = self.store.get_decision_by_source(source_table, source_id)
        if not decision:
            print(f"No decision found for {source_table}:{source_id}")
            return

        print(f"\nDecision: {source_table}:{source_id}")
        print("-" * 50)
        print(f"Base Severity:  {decision.base_severity}")
        print(f"Final Severity: {decision.final_severity}")
        print(f"Verdict:        {decision.verdict}")
        print(f"\nReasoning:")
        for reason in decision.reasoning:
            print(f"  - {reason}")

    def get_detail(self, source_table: str, source_id: int) -> dict:
        """Return decision detail as dict (for JSON output)."""
        decision = self.store.get_decision_by_source(source_table, source_id)
        if not decision:
            return {"error": f"Not found: {source_table}:{source_id}"}

        return {
            "source_table": decision.source_table,
            "source_id": decision.source_id,
            "base_severity": decision.base_severity,
            "final_severity": decision.final_severity,
            "verdict": decision.verdict,
            "reasoning": decision.reasoning,
        }

    def cmd_stats(self, days: int = 7) -> None:
        """Print decision statistics for the past N days."""
        counts = self.store.count_by_verdict()
        total = sum(counts.values())

        print(f"\nAlert Decision Statistics (last {days} days):")
        print("-" * 50)
        print(f"Total Decisions:       {total}")
        for verdict, count in sorted(counts.items()):
            pct = (count / total * 100) if total > 0 else 0
            print(f"  {verdict:<25} {count:>6} ({pct:>5.1f}%)")

    def get_stats(self, days: int = 7) -> dict:
        """Return statistics as dict (for JSON output)."""
        counts = self.store.count_by_verdict()
        total = sum(counts.values())
        return {
            "days": days,
            "total": total,
            "verdicts": counts,
            "percentages": {
                verdict: (count / total * 100) if total > 0 else 0
                for verdict, count in counts.items()
            },
        }
