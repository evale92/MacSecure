"""
secure/dfir/suggest.py — Phase 24 Stage 4: read-only collection
candidates. Never executes anything, never recommends a specific
Velociraptor artifact name — see this module's own "what this does NOT
do" note below for why. The concrete mechanism behind the instruction's
"do not trigger broad forensic collection automatically from
low-confidence findings": a severity/confidence gate that decides which
findings are even WORTH surfacing as candidates for an operator to
consider, before any `secure dfir collect` command is ever typed.

Reuses Phase 23's `investigate()`/`explain_observation()`
(secure/investigate/view.py) directly rather than a second alert-
scanning pass of its own — every finding this module considers is
exactly the same finding, with exactly the same severity/confidence,
that `secure investigate show` would already display for this entity.
No detection logic lives here; this module only decides which
already-computed findings clear a bar.

What this does NOT do: pick a specific Velociraptor artifact name for
a candidate. Secure has no built-in catalog of "the right artifact for
a persistence finding" to draw from — inventing one here would mean
either hardcoding real Velociraptor artifact names this codebase can't
verify are current/correct (no live install available — see
secure/dfir/velociraptor/__init__.py's own honesty note), or silently
recommending something outside the operator's own
`AppConfig.dfir_artifact_allowlist`. Consistent with "Secure decides
WHEN and WHY to look, the external tool owns WHAT it does" (the same
split secure/integrations/yarax/targets.py already established for
scan targets vs. rule content), this module answers "is this finding
worth considering a collection for" — the operator supplies WHICH
allowlisted artifact to actually run, at `secure dfir collect` time.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import List, Set, Tuple

from secure.evidence.model import ObservationRef
from secure.explain.vocab import CONFIRMED, LIKELY
from secure.investigate.entity import EntityRef
from secure.investigate.view import explain_observation, investigate

# The gate itself: a finding must be at least HIGH severity AND at
# least LIKELY confidence to surface as a candidate at all. Both axes
# matter independently — a CRITICAL-severity finding Secure is only
# UNCERTAIN about is exactly the "low-confidence finding" the
# instruction says must never auto-trigger anything, and a CONFIRMED
# but LOW-severity finding isn't worth a forensic collection either.
_MIN_SEVERITIES = ("high", "critical")
_MIN_CONFIDENCES = (LIKELY, CONFIRMED)


@dataclass(frozen=True)
class CollectionCandidate:
    """One finding, already on record, that clears the severity/
    confidence bar for "worth considering a targeted collection about."
    Carries the exact ObservationRef so a caller can pass
    `--source-table`/`--source-id` straight through to
    `secure dfir collect` for provenance, never re-deriving it.
    """

    source_table: str
    source_id: int
    severity: str
    confidence: str
    summary: str
    reason: str


def suggest_collections(conn: sqlite3.Connection, entity: EntityRef) -> List[CollectionCandidate]:
    """Every alert-shaped observation reachable from `entity` (its own
    anchors plus everything Phase 23's related-evidence view reaches)
    that clears the severity/confidence gate above. Returns `[]` for an
    entity not on record, or one with no qualifying findings — an empty
    list is a completely ordinary, expected result, not a degraded one.
    """
    view = investigate(conn, entity)
    if not view.exists:
        return []

    all_refs: List[ObservationRef] = list(view.anchors)
    for group in view.related.groups:
        all_refs.extend(group.observations)

    candidates: List[CollectionCandidate] = []
    seen: Set[Tuple[str, int]] = set()
    for ref in all_refs:
        key = (ref.source_table, ref.source_id)
        if key in seen:
            continue
        seen.add(key)

        explanation = explain_observation(conn, ref)
        if explanation is None:
            continue
        if explanation.severity not in _MIN_SEVERITIES:
            continue
        if explanation.confidence not in _MIN_CONFIDENCES:
            continue

        candidates.append(
            CollectionCandidate(
                source_table=ref.source_table,
                source_id=ref.source_id,
                severity=explanation.severity,
                confidence=explanation.confidence,
                summary=explanation.summary,
                reason=f"{explanation.severity.upper()} severity, {explanation.confidence} confidence "
                f"finding on {entity} — a targeted collection may help confirm what's happening.",
            )
        )

    return candidates
