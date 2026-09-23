"""Intelligence models — immutable dataclasses for threat enrichment (Phase 50+)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

MATCH_EXACT = "exact"
MATCH_RANGE = "range"
MATCH_PRODUCT_ONLY = "product"
MATCH_NONE = "none"

CONF_CONFIRMED = "confirmed"
CONF_LIKELY = "likely"
CONF_POSSIBLE = "possible"

PROPOSE_RAISE = "raise"
PROPOSE_LOWER = "lower"
PROPOSE_HOLD = "hold"


@dataclass(frozen=True)
class CvssScore:
    """A CVSS base score as published. Not recomputed by Secure."""
    version: str
    base_score: float
    vector: str
    severity: str


@dataclass(frozen=True)
class CveMatch:
    """One finding, one CVE. Enrichment only — never a Secure severity."""
    finding_id: str
    finding_type: str
    cve_id: str
    match_type: str
    matched_on: str
    cvss: Optional[CvssScore] = None
    published: str = ""
    source: str = ""
    notes: str = ""


@dataclass(frozen=True)
class MitreMapping:
    """Finding to MITRE ATT&CK technique mapping."""
    finding_id: str
    finding_type: str
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str
    rationale: str
    source: str = "builtin"


@dataclass(frozen=True)
class EfficacySummary:
    """Honest aggregate for one action. Denominator is ALL measured outcomes."""
    action_id: str
    measured: int
    effective: int
    ineffective: int
    inconclusive: int
    success_rate: float
    success_rate_lower: float
    avg_findings_reduced: float
    avg_time_to_effect: float


@dataclass(frozen=True)
class ThresholdProposal:
    """A RECOMMENDATION. Nothing in Phase 50 applies one."""
    playbook_id: str
    parameter: str
    current_value: float
    proposed_value: float
    direction: str
    samples: int
    evidence: str
    confidence_lower: float
    applied: bool = False
