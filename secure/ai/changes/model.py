"""
secure/ai/changes/model.py — pure helpers: the canonical revision-hash
computation and a small dataclass describing a proposed change's
content fields. No I/O, no database access — see workflow.py for the
functions that actually persist anything.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


@dataclass
class ProposedChangeContent:
    title: str
    proposed_change: str
    reason: str
    affected_component: str
    risks: str

    def to_dict(self) -> dict:
        return {
            "title": self.title, "proposed_change": self.proposed_change, "reason": self.reason,
            "affected_component": self.affected_component, "risks": self.risks,
        }


def compute_revision_hash(content: ProposedChangeContent) -> str:
    """A deterministic hash of exactly the fields a human is approving.
    Same content -> same hash, always, on any machine, in any process —
    this is what `approve_change()` re-checks the caller's hash
    against, so approval can never silently drift onto content someone
    hasn't actually seen.
    """
    canonical = json.dumps(content.to_dict(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
