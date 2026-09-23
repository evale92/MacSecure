"""Intelligence CLI — thin interface to CVE, MITRE, and learning (Phase 50.4).

Sits in the interface layer; calls pure intelligence functions.
"""

from __future__ import annotations

from typing import Optional

from secure.intelligence.cve_integrator import CveIntegrator
from secure.intelligence.mitre_mapper import MitreMapper
from secure.intelligence.learning import LearningEngine


def cve_lookup(
    finding_id: str,
    finding_type: str,
    product: str,
    version: str,
    cve_db_path: str = "",
) -> dict:
    """Look up CVEs for a finding. Returns {status, matches: []}."""
    if not cve_db_path:
        return {"status": "unavailable", "matches": []}

    integrator = CveIntegrator(cve_db_path)
    if not integrator.available:
        return {"status": "unavailable", "matches": []}

    matches = integrator.match_finding(finding_id, finding_type, product, version)
    return {
        "status": "ok" if matches else "no_match",
        "matches": [
            {
                "cve_id": m.cve_id,
                "match_type": m.match_type,
                "matched_on": m.matched_on,
                "severity": m.cvss.severity if m.cvss else None,
                "cvss_score": m.cvss.base_score if m.cvss else None,
                "published": m.published,
            }
            for m in matches
        ],
    }


def mitre_lookup(
    finding_id: str,
    finding_type: str,
) -> dict:
    """Map finding to MITRE techniques. Returns {status, mappings: []}."""
    mapper = MitreMapper()
    mappings = mapper.map_finding(finding_id, finding_type)

    return {
        "status": "ok" if mappings else "unmapped",
        "mappings": [
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "confidence": m.confidence,
                "rationale": m.rationale,
            }
            for m in mappings
        ],
    }


def generate_threshold_proposal(
    playbook_id: str,
    current_threshold: float,
    outcomes: list,
    shadow_scores: Optional[list[float]] = None,
) -> dict:
    """Generate playbook threshold proposal. Returns {status, proposal: {...}}."""
    engine = LearningEngine()

    if not outcomes:
        return {
            "status": "no_outcomes",
            "proposal": None,
            "message": "No outcome history available",
        }

    action_id = outcomes[0].action_id if outcomes else ""
    efficacy = engine.analyze_action_efficacy(action_id, outcomes)

    proposal = engine.propose_threshold_adjustment(
        playbook_id=playbook_id,
        current_threshold=current_threshold,
        efficacy=efficacy,
        shadow_scores=shadow_scores,
    )

    return {
        "status": "ok",
        "proposal": {
            "playbook_id": proposal.playbook_id,
            "current_value": proposal.current_value,
            "proposed_value": proposal.proposed_value,
            "direction": proposal.direction,
            "samples": proposal.samples,
            "evidence": proposal.evidence,
            "confidence_lower": proposal.confidence_lower,
            "applied": proposal.applied,
        },
    }
