"""Alerting — Phase 53 alert decision system.

Composes Phase 48-51 context and applies suppression + escalation logic to findings.
PURE decision functions in suppression.py, escalation.py, decide.py accept context as values.
compose.py (the only impure file) assembles AlertContext from remediation/multi_device/intelligence.
"""

from secure.alerting.context import (
    AlertContext,
    DeviceContext,
    ExpectedChange,
    LearningContext,
    ResponseContext,
)
from secure.alerting.decide import AlertDecision, decide_alert
from secure.alerting.escalation import weigh as escalate_severity
from secure.alerting.suppression import SuppressionVerdict, classify as classify_suppression

__all__ = [
    "AlertContext",
    "AlertDecision",
    "DeviceContext",
    "ExpectedChange",
    "LearningContext",
    "ResponseContext",
    "SuppressionVerdict",
    "classify_suppression",
    "decide_alert",
    "escalate_severity",
]
