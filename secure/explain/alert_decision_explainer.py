"""Explain alert decision outcomes to users.

Formats alert decisions with human-readable suppression/escalation reasoning.
"""

from __future__ import annotations

from typing import List

from secure.alerting.decide import AlertDecision


class AlertDecisionExplainer:
    """Format and explain alert decisions."""

    @staticmethod
    def explain_verdict(decision: AlertDecision) -> str:
        """
        Generate a human-readable explanation of the decision verdict.

        Args:
            decision: AlertDecision instance.

        Returns:
            Plain English explanation.
        """
        verdict_map = {
            "ACTIVE": "This alert was not suppressed and remains active.",
            "SUPPRESSED_EXPECTED": "This alert was fully suppressed as an expected change.",
            "DOWNGRADED_EXPECTED": "This alert severity was capped due to an expected change window.",
        }
        return verdict_map.get(decision.verdict, f"Unknown verdict: {decision.verdict}")

    @staticmethod
    def explain_escalation(decision: AlertDecision) -> str:
        """
        Generate explanation of escalation factors (if any).

        Args:
            decision: AlertDecision instance.

        Returns:
            Plain English explanation of escalation signals.
        """
        escalation_reasons = [r for r in decision.reasoning if r.startswith("Escalation:")]
        if not escalation_reasons:
            return "No escalation signals applied."

        explanation = "Escalation signals:\n"
        for reason in escalation_reasons:
            explanation += f"  • {reason}\n"
        return explanation

    @staticmethod
    def explain_suppression(decision: AlertDecision) -> str:
        """
        Generate explanation of suppression logic (if any).

        Args:
            decision: AlertDecision instance.

        Returns:
            Plain English explanation of suppression decision.
        """
        suppression_reasons = [r for r in decision.reasoning if r.startswith("Suppression:")]
        if not suppression_reasons:
            return "No suppression rules matched."

        explanation = "Suppression rules:\n"
        for reason in suppression_reasons:
            explanation += f"  • {reason}\n"
        return explanation

    @staticmethod
    def format_decision(decision: AlertDecision, detailed: bool = False) -> str:
        """
        Format a complete decision explanation.

        Args:
            decision: AlertDecision instance.
            detailed: if True, include reasoning details; if False, summary only.

        Returns:
            Formatted explanation string.
        """
        lines = []

        lines.append(f"Alert Decision: {decision.source_table}#{decision.source_id}")
        lines.append("-" * 60)
        lines.append(f"Base Severity:  {decision.base_severity}")
        lines.append(f"Final Severity: {decision.final_severity}")
        lines.append(f"Verdict:        {decision.verdict}")
        lines.append("")

        if detailed:
            lines.append("Verdict Explanation:")
            lines.append(f"  {AlertDecisionExplainer.explain_verdict(decision)}")
            lines.append("")

            lines.append("Suppression Logic:")
            suppression_text = AlertDecisionExplainer.explain_suppression(decision)
            for line in suppression_text.split("\n"):
                if line:
                    lines.append(f"  {line}")
            lines.append("")

            lines.append("Escalation Logic:")
            escalation_text = AlertDecisionExplainer.explain_escalation(decision)
            for line in escalation_text.split("\n"):
                if line:
                    lines.append(f"  {line}")
        else:
            # Summary mode: just list the reasons
            lines.append("Reasoning:")
            for reason in decision.reasoning:
                lines.append(f"  • {reason}")

        return "\n".join(lines)

    @staticmethod
    def to_dict(decision: AlertDecision) -> dict:
        """
        Convert decision to structured explanation dict (for JSON/API).

        Args:
            decision: AlertDecision instance.

        Returns:
            Dict with explanation fields.
        """
        return {
            "source": {
                "table": decision.source_table,
                "id": decision.source_id,
            },
            "severity": {
                "base": decision.base_severity,
                "final": decision.final_severity,
            },
            "verdict": decision.verdict,
            "verdict_explanation": AlertDecisionExplainer.explain_verdict(decision),
            "suppression": AlertDecisionExplainer.explain_suppression(decision),
            "escalation": AlertDecisionExplainer.explain_escalation(decision),
            "reasoning": decision.reasoning,
        }
