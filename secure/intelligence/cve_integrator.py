"""CVE integrator — match findings to known CVEs with CVSS scoring (Phase 50+)."""

from __future__ import annotations

import json
from typing import Optional

from secure.intelligence.models import CveMatch, CvssScore, MATCH_EXACT, MATCH_RANGE, MATCH_PRODUCT_ONLY, MATCH_NONE


def _parse_version_tuple(version_str: str) -> Optional[tuple]:
    """Parse a version string into a comparable tuple. Returns None if unparseable."""
    try:
        parts = []
        for part in version_str.split("."):
            if part.isdigit():
                parts.append(int(part))
            else:
                return None
        return tuple(parts)
    except Exception:
        return None


def _version_in_range(version: str, min_version: str, max_version: str) -> bool:
    """Check if version falls within an inclusive range."""
    v = _parse_version_tuple(version)
    v_min = _parse_version_tuple(min_version)
    v_max = _parse_version_tuple(max_version)

    if v is None or v_min is None or v_max is None:
        return False

    return v_min <= v <= v_max


class CveIntegrator:
    """Match findings to CVEs and enrich with CVSS data."""

    def __init__(self, cve_db_path: str = ""):
        """Initialize with optional path to CVE database JSON."""
        self.cve_db_path = cve_db_path
        self.cves: dict = {}
        self.available = cve_db_path != ""

        if self.available:
            self._load_database()

    def _load_database(self) -> None:
        """Load CVE database from JSON file."""
        try:
            with open(self.cve_db_path) as f:
                data = json.load(f)
                self.cves = {cve["cve_id"]: cve for cve in data.get("cves", [])}
        except Exception:
            self.available = False
            self.cves = {}

    def match_finding(
        self,
        finding_id: str,
        finding_type: str,
        product: str,
        version: str,
    ) -> list[CveMatch]:
        """Find CVEs matching a product/version."""
        if not self.available:
            return []

        matches = []

        for cve_id, cve_entry in self.cves.items():
            cve_product = cve_entry.get("product", "")
            affected_versions = cve_entry.get("affected_versions", [])

            if cve_product.lower() != product.lower():
                continue

            # Determine match type
            match_type = MATCH_NONE
            matched_on = ""

            if not version:
                match_type = MATCH_PRODUCT_ONLY
                matched_on = product
            else:
                for affected in affected_versions:
                    if isinstance(affected, str):
                        if version == affected and _parse_version_tuple(affected) is not None:
                            match_type = MATCH_EXACT
                            matched_on = version
                            break
                    elif isinstance(affected, dict):
                        min_v = affected.get("min")
                        max_v = affected.get("max")
                        if min_v and max_v and _version_in_range(version, min_v, max_v):
                            match_type = MATCH_RANGE
                            matched_on = f"{min_v}-{max_v}"
                            break

            if match_type == MATCH_NONE:
                continue

            cvss_data = cve_entry.get("cvss")
            cvss = None
            if cvss_data:
                cvss = CvssScore(
                    version=cvss_data.get("version", ""),
                    base_score=cvss_data.get("base_score", 0.0),
                    vector=cvss_data.get("vector", ""),
                    severity=cvss_data.get("severity", ""),
                )

            match = CveMatch(
                finding_id=finding_id,
                finding_type=finding_type,
                cve_id=cve_id,
                match_type=match_type,
                matched_on=matched_on,
                cvss=cvss,
                published=cve_entry.get("published", ""),
                source=self.cve_db_path.split("/")[-1] if self.cve_db_path else "",
            )
            matches.append(match)

        return matches
