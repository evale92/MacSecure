"""Intelligence — threat intelligence enrichment (Phase 50+).

CVE integrator, MITRE mapper, and learning loop sit at the `threatintel` tier
for pure functions, with learning.py sitting above remediation (called only
from CLI, reads outcomes table, never imports remediation code).

Enrichment only — never ground truth for Secure's severity/confidence.
"""

from secure.intelligence.models import CveMatch, CvssScore, MitreMapping
from secure.intelligence.cve_integrator import CveIntegrator
from secure.intelligence.mitre_mapper import MitreMapper

__all__ = ["CveMatch", "CvssScore", "MitreMapping", "CveIntegrator", "MitreMapper"]
