"""AlertContext — immutable parameter passing for alert decision logic.

Phase 53: Context injection seam for Phase 48-51 information.
This dataclass flows downward (as values, not imports) to pure decision functions.
compose.py is the only file that assembles it from remediation/multi_device/intelligence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import FrozenSet, Mapping, Optional, Tuple


@dataclass(frozen=True)
class ExpectedChange:
    """Declarative expected-change window for false-positive suppression."""
    kind: str                          # "os_update" | "app_install" | "user_declared"
    started_at: datetime
    ends_at: datetime
    entity_types: FrozenSet[str]       # baseline/entities.py constants (process_key, persistence_key, etc.)
    path_prefixes: Tuple[str, ...]     # e.g. ("/Library/Updates",)
    source: str                        # provenance: who asserted this? ("system:software_update", "user:admin", etc.)


@dataclass(frozen=True)
class DeviceContext:
    """Phase 49 device information, passed down as values."""
    device_id: str
    role: str                          # PRIMARY | SECONDARY | SHARED | ADMIN
    health: str                        # healthy | degraded | unknown
    sync_state: str                    # synced | stale | unknown
    peer_device_count: int             # how many peers saw same finding type


@dataclass(frozen=True)
class ResponseContext:
    """Phase 48/51 remediation context, passed down as values."""
    max_risk_level: str                # LOW | MEDIUM | HIGH (highest across matching actions)
    playbook_id: Optional[str] = None
    playbook_severity: Optional[str] = None  # critical | high | medium | low


@dataclass(frozen=True)
class LearningContext:
    """Phase 50 learning outcomes and threshold tuning, passed down as values."""
    threshold_overrides: Mapping[str, float] = field(default_factory=dict)  # feature_name -> tier cutoff
    fp_rate_by_feature: Mapping[str, float] = field(default_factory=dict)   # from marked false positives
    sample_counts: Mapping[str, int] = field(default_factory=dict)           # observations per feature


@dataclass(frozen=True)
class AlertContext:
    """Complete alert decision context. Immutable, all fields have safe defaults."""
    device: Optional[DeviceContext] = None
    response: Optional[ResponseContext] = None
    learning: LearningContext = field(default_factory=LearningContext)
    expected_changes: Tuple[ExpectedChange, ...] = ()

    @classmethod
    def empty(cls) -> "AlertContext":
        """Return a context with all safe defaults. Decision logic produces sane output even with this."""
        return cls()
