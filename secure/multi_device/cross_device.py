"""
Cross-device correlation — find patterns across multiple devices.

Phase 49 correlates findings across devices to detect coordinated
attacks, widespread malware, or supply chain compromises.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional


@dataclass
class CorrelatedFinding:
    """A finding that appears on multiple devices."""
    correlation_id: str
    finding_type: str                 # e.g., "persistence.unsigned_executable"

    device_count: int                 # How many devices have this finding
    device_ids: list = field(default_factory=list)

    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)

    # Risk assessment
    anomaly_score: float = 0.0
    correlation_strength: float = 0.0  # 0-100, likelihood it's a coordinated attack

    # Enrichment
    suspected_vector: str = ""        # e.g., "supply_chain", "coordinated_attack", "local_exploit"
    similar_samples: list = field(default_factory=list)

    # Remediation tracking
    remediation_playbook_id: Optional[str] = None
    affected_devices_needing_action: list = field(default_factory=list)

    # Context
    notes: str = ""
    priority: str = "medium"          # low, medium, high, critical


class CrossDeviceFindingCorrelator:
    """Correlates findings across multiple devices."""

    def __init__(self):
        """Initialize correlator."""
        self.correlated_findings: dict[str, CorrelatedFinding] = {}
        self.device_findings: dict[str, dict] = {}  # device_id -> {finding_type -> [findings]}

    def add_device_findings(
        self,
        device_id: str,
        findings: list[dict],
    ) -> None:
        """Add findings from a device to the correlator."""
        if device_id not in self.device_findings:
            self.device_findings[device_id] = {}

        for finding in findings:
            finding_type = finding.get("finding_type", "unknown")
            if finding_type not in self.device_findings[device_id]:
                self.device_findings[device_id][finding_type] = []

            self.device_findings[device_id][finding_type].append(finding)

    def correlate_findings(
        self,
        min_device_count: int = 2,
        time_window_hours: int = 24,
    ) -> list[CorrelatedFinding]:
        """Find findings that appear on multiple devices."""
        correlated = []
        finding_distribution = {}

        # Count devices with each finding type
        for device_id, findings_by_type in self.device_findings.items():
            for finding_type, findings in findings_by_type.items():
                if finding_type not in finding_distribution:
                    finding_distribution[finding_type] = {
                        "device_ids": set(),
                        "findings": [],
                    }

                finding_distribution[finding_type]["device_ids"].add(device_id)
                finding_distribution[finding_type]["findings"].extend(findings)

        # Create correlated findings for types appearing on multiple devices
        for finding_type, data in finding_distribution.items():
            device_ids = list(data["device_ids"])
            findings = data["findings"]

            if len(device_ids) >= min_device_count:
                # Calculate timestamps
                timestamps = [
                    f.get("timestamp", datetime.utcnow())
                    for f in findings
                    if isinstance(f.get("timestamp"), datetime)
                ]

                first_seen = min(timestamps) if timestamps else datetime.utcnow()
                last_seen = max(timestamps) if timestamps else datetime.utcnow()

                # Check if within time window
                time_span = (last_seen - first_seen).total_seconds() / 3600
                if time_span > time_window_hours:
                    continue

                correlation_id = f"cf_{finding_type}_{len(device_ids)}d"
                correlated_finding = CorrelatedFinding(
                    correlation_id=correlation_id,
                    finding_type=finding_type,
                    device_count=len(device_ids),
                    device_ids=device_ids,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    anomaly_score=self._calculate_anomaly_score(
                        finding_type, len(device_ids)
                    ),
                    correlation_strength=self._calculate_correlation_strength(
                        len(device_ids), time_span
                    ),
                    suspected_vector=self._classify_vector(
                        finding_type, len(device_ids), time_span
                    ),
                )

                correlated.append(correlated_finding)
                self.correlated_findings[correlation_id] = correlated_finding

        return correlated

    @staticmethod
    def _calculate_anomaly_score(finding_type: str, device_count: int) -> float:
        """Calculate anomaly score based on type and device count."""
        # Multi-device findings are more anomalous
        base_scores = {
            "persistence.": 75.0,
            "process.privilege": 80.0,
            "network.c2": 90.0,
            "file.signed": 60.0,
        }

        base_score = next(
            (v for k, v in base_scores.items() if k in finding_type),
            50.0
        )

        # Boost for device count (exponential)
        device_multiplier = min(device_count * 1.2, 2.0)
        return min(base_score * device_multiplier, 100.0)

    @staticmethod
    def _calculate_correlation_strength(device_count: int, hours_span: float) -> float:
        """Calculate how likely this is a coordinated event."""
        # More devices + tighter timeframe = higher coordination likelihood
        device_factor = min(device_count / 5.0, 1.0) * 70
        time_factor = max(1.0 - (hours_span / 24.0), 0.0) * 30
        return min(device_factor + time_factor, 100.0)

    @staticmethod
    def _classify_vector(finding_type: str, device_count: int, hours_span: float) -> str:
        """Classify the likely attack vector."""
        if device_count >= 3 and hours_span < 1:
            return "supply_chain"  # Fast, widespread
        elif device_count >= 2 and hours_span < 12:
            return "coordinated_attack"  # Targeted, synchronized
        elif "network.c2" in finding_type and device_count >= 2:
            return "botnet"
        elif "privilege" in finding_type and device_count >= 2:
            return "privilege_escalation_kit"
        else:
            return "local_exploit"

    def get_correlated_finding(self, correlation_id: str) -> CorrelatedFinding:
        """Get a correlated finding by ID."""
        return self.correlated_findings.get(correlation_id)

    def list_correlated_findings(
        self,
        priority: str = None,
        device_count_min: int = 2,
    ) -> list[CorrelatedFinding]:
        """List correlated findings."""
        result = list(self.correlated_findings.values())

        if priority:
            result = [f for f in result if f.priority == priority]

        result = [f for f in result if f.device_count >= device_count_min]

        return sorted(result, key=lambda f: f.correlation_strength, reverse=True)

    def enrich_finding(
        self,
        correlation_id: str,
        suspected_vector: str = None,
        similar_samples: list = None,
        notes: str = None,
    ) -> CorrelatedFinding:
        """Enrich a correlated finding with additional context."""
        finding = self.get_correlated_finding(correlation_id)
        if finding is None:
            return None

        if suspected_vector:
            finding.suspected_vector = suspected_vector

        if similar_samples:
            finding.similar_samples = similar_samples

        if notes:
            finding.notes = notes

        return finding

    def assign_remediation_playbook(
        self,
        correlation_id: str,
        playbook_id: str,
        affected_devices: list[str] = None,
    ) -> CorrelatedFinding:
        """Assign a remediation playbook to a correlated finding."""
        finding = self.get_correlated_finding(correlation_id)
        if finding is None:
            return None

        finding.remediation_playbook_id = playbook_id
        finding.affected_devices_needing_action = affected_devices or finding.device_ids
        return finding

    def clear_device_findings(self, device_id: str) -> None:
        """Clear cached findings for a device (e.g., after device reset)."""
        if device_id in self.device_findings:
            del self.device_findings[device_id]

    def detect_poisoned_devices(self) -> list[dict]:
        """
        Detect devices that may be compromised and poisoning correlation.

        Heuristics:
        1. Device reports unique findings (not seen on any other device)
        2. Device has outlier finding frequency (reports 10x more/less than peers)
        3. Device reports findings that don't correlate with others (isolated reports)

        Returns list of {device_id, risk_score, reason} dicts.
        """
        if len(self.device_findings) < 2:
            return []  # Need at least 2 devices to detect anomalies

        poisoned_devices = []
        device_ids = list(self.device_findings.keys())

        # Calculate stats per device
        device_stats = {}
        for device_id, findings_by_type in self.device_findings.items():
            total_findings = sum(len(f) for f in findings_by_type.values())
            unique_types = len(findings_by_type)
            device_stats[device_id] = {
                "total_findings": total_findings,
                "unique_types": unique_types,
                "finding_types": set(findings_by_type.keys()),
            }

        # Calculate average findings per device
        avg_findings = sum(s["total_findings"] for s in device_stats.values()) / len(device_ids)
        avg_types = sum(s["unique_types"] for s in device_stats.values()) / len(device_ids)

        # Check each device for poison indicators
        for device_id, stats in device_stats.items():
            risk_score = 0.0
            reasons = []

            # Heuristic 1: Unique findings (only this device reports them)
            unique_findings = stats["finding_types"].copy()
            for other_id, other_stats in device_stats.items():
                if other_id != device_id:
                    unique_findings -= other_stats["finding_types"]

            if len(unique_findings) > 0:
                unique_pct = len(unique_findings) / max(1, stats["unique_types"])
                if unique_pct > 0.5:  # >50% of findings are unique to this device
                    risk_score += 30.0
                    reasons.append(f"{len(unique_findings)} finding types unique to this device")

            # Heuristic 2: Outlier frequency
            if avg_findings > 0:
                freq_ratio = stats["total_findings"] / avg_findings
                if freq_ratio > 5.0:  # Reports 5x more than average
                    risk_score += 25.0
                    reasons.append(f"Reports {freq_ratio:.1f}x average findings (possible logging attack)")
                elif freq_ratio < 0.2:  # Reports 5x less than average
                    risk_score += 15.0
                    reasons.append(f"Reports {freq_ratio:.1f}x average findings (possible sensor compromise)")

            # Heuristic 3: Isolated reports (findings not correlated with any other device)
            isolated_count = 0
            for finding_type in stats["finding_types"]:
                type_device_count = sum(
                    1 for other_stats in device_stats.values()
                    if finding_type in other_stats["finding_types"]
                )
                if type_device_count == 1:  # Only this device has this type
                    isolated_count += 1

            if isolated_count > 0 and stats["unique_types"] > 0:
                isolated_pct = isolated_count / stats["unique_types"]
                if isolated_pct > 0.7:  # >70% of findings are isolated
                    risk_score += 20.0
                    reasons.append(f"{isolated_count} isolated findings (not correlated with other devices)")

            # Report if risk is above threshold
            if risk_score >= 30.0:
                poisoned_devices.append({
                    "device_id": device_id,
                    "risk_score": risk_score,
                    "reasons": reasons,
                    "recommendation": "Investigate device for compromise; consider isolating from correlation pool"
                })

        return sorted(poisoned_devices, key=lambda x: x["risk_score"], reverse=True)
