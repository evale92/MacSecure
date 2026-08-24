"""
correlate/analysis.py — pure logic: turning a list of Signals into
time-clusters, scoring each cluster, deciding its severity, and
explaining the result in plain English. No subprocess calls, no
database access — every function here is directly testable with
hand-built Signal objects, no real Mac or seeded database required.

The scoring model, in one place (see each function's docstring for the
detail): a cluster's score is the sum of its individual signals'
strength weights, PLUS a corroboration bonus that scales with how many
distinct modules are involved, PLUS a flat bonus if the module
combination itself is considered security-meaningful (not every pair
of modules co-occurring means anything — a new BLE peripheral and a
new LAN device happening near each other in time is ambient noise; a
new process and a new outbound connection happening near each other is
a real pattern). A hard cap then prevents an all-WEAK cluster from ever
reaching HIGH or CRITICAL, regardless of score, no matter how many weak
signals piled up.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Optional

from secure.correlate.strength import MEDIUM, STRONG, WEAK, WEIGHT

if TYPE_CHECKING:
    from secure.correlate.signals import Signal

DEFAULT_WINDOW_SECONDS = 60.0

INFORMATIONAL = "informational"
LOW = "low"
MEDIUM_SEVERITY = "medium"
HIGH = "high"
CRITICAL = "critical"

# critical is deliberately reachable ONLY through correlation — no
# single module's own alert severity ever uses this word, so seeing it
# always means "multiple independent subsystems agree," never a
# relabeled single-source finding.
_SEVERITY_ORDER = [INFORMATIONAL, LOW, MEDIUM_SEVERITY, HIGH, CRITICAL]

# Module pairs treated as independently security-meaningful when they
# co-occur — contributes a flat bonus in correlation_score() regardless
# of how strong any individual member is. Deliberately NOT every
# possible pair: {"ble", "inventory"} (a nearby BLE peripheral plus a
# new LAN device) is ambient environmental noise with no inherent
# security relationship between the two subsystems, so it earns no
# bonus — this is what keeps "new BLE peripheral + new LAN device"
# (informational/low) meaningfully lower than "new signed process + new
# remote endpoint" (low/medium) even though both examples are two WEAK
# signals from two modules; see the user's own worked examples.
#
# Phase 11 (File Integrity Monitoring) note: {"file_integrity",
# "persistence"} is DELIBERATELY NOT in this set, even though a
# LaunchAgent/LaunchDaemon change is exactly the kind of thing both
# modules can legitimately report on at once. Including it would let
# the SAME underlying real-world event (one plist edit) earn a
# "these are two independently corroborating subsystems" bonus purely
# because two different modules happened to observe two different
# facets of it — persistence's semantic interpretation and file
# integrity's byte-level proof aren't independent evidence the way,
# say, a new process and a new outbound connection are. Both signals
# are still collected and still contribute their own raw signal
# weight (see signals.py's _collect_file_integrity() docstring for the
# full reasoning) — they just don't earn this flat bonus for pairing
# with EACH OTHER specifically. file_integrity DOES pair meaningfully
# with process/connections/listening below, since those really are
# independent subsystems.
MEANINGFUL_MODULE_PAIRS = {
    frozenset({"process", "connections"}),
    frozenset({"process", "persistence"}),
    frozenset({"persistence", "connections"}),
    frozenset({"process", "listening"}),
    frozenset({"listening", "connections"}),
    frozenset({"wifi", "arpwatch"}),
    frozenset({"arpwatch", "inventory"}),
    frozenset({"bluetooth", "persistence"}),
    frozenset({"file_integrity", "process"}),
    frozenset({"file_integrity", "connections"}),
    frozenset({"file_integrity", "listening"}),
    # Phase 15: unlike {"file_integrity", "persistence"} above, an
    # "integrations" signal pairing with "listening"/"persistence" is
    # NOT the same underlying fact restated by a second module — by
    # construction, an integrations signal only exists at all when
    # osquery and Secure's native collector DISAGREED about something
    # (see secure/integrations/osquery/crosscheck.py and
    # signals.py's _collect_integrations()). A disagreement co-occurring
    # with the corresponding native module's own activity is genuinely
    # independent evidence, not double-counted restatement, so it's
    # treated as meaningful here rather than excluded the way
    # file_integrity/persistence deliberately is.
    frozenset({"integrations", "listening"}),
    frozenset({"integrations", "persistence"}),
    # Phase 16: a YARA-X match is, by construction, ALSO never emitted
    # for "nothing found" (see signals.py's _collect_integrations()
    # docstring) — so an integrations signal co-occurring with a
    # file_integrity signal is genuinely independent evidence (a file
    # changed AND separately matched a content-detection rule), not the
    # same fact restated twice. This is exactly the scenario Phase 16's
    # own targeting design produces on purpose (scan_fim_alerts() feeds
    # YARA-X the very files File Integrity Monitoring just flagged), so
    # this pair is expected to fire together often and should count.
    frozenset({"integrations", "file_integrity"}),
    # Phase 17: a Sigma match is, by construction, also never emitted
    # for "no match" or "not evaluable" (see signals.py's
    # _collect_integrations() docstring — only integration_alerts rows,
    # which only genuine matches produce, are ever read here). Sigma's
    # only two supported categories are process_creation and
    # network_connection (see secure/integrations/sigma/capability.py),
    # so a Sigma match co-occurring with Secure's own native "process"
    # or "connections" module activity is genuinely independent
    # evidence — the same osquery telemetry a Sigma rule condition
    # matched against, corroborated separately by Secure's own native
    # collector noticing the same real-world process/connection — not a
    # single fact restated twice.
    frozenset({"integrations", "process"}),
    frozenset({"integrations", "connections"}),
}


def cluster_signals(
    signals: "list[Signal]", window_seconds: float = DEFAULT_WINDOW_SECONDS
) -> "list[list[Signal]]":
    """Group signals into clusters using rolling single-linkage
    chaining: a signal joins the CURRENT cluster if it's within
    `window_seconds` of the LAST signal already in that cluster (not
    the first) — a slow-building burst where each new signal is close
    to the one before it, even if the first and last end up farther
    apart than the window, is still one continuous cluster. `signals`
    must already be sorted oldest-first (collect_signals() guarantees
    this).
    """
    if not signals:
        return []

    clusters: "list[list[Signal]]" = [[signals[0]]]
    for signal in signals[1:]:
        current = clusters[-1]
        gap = (signal.timestamp - current[-1].timestamp).total_seconds()
        if gap <= window_seconds:
            current.append(signal)
        else:
            clusters.append([signal])
    return clusters


def distinct_modules(cluster: "list[Signal]") -> "set[str]":
    return {signal.module for signal in cluster}


def has_meaningful_combo(cluster: "list[Signal]") -> bool:
    """True if the cluster's module set contains at least one pair
    from MEANINGFUL_MODULE_PAIRS — whether the COMBINATION itself is
    security-relevant, independent of how strong any one member is.
    """
    modules = distinct_modules(cluster)
    if len(modules) < 2:
        return False
    return any(pair <= modules for pair in MEANINGFUL_MODULE_PAIRS)


def max_strength(cluster: "list[Signal]") -> str:
    """The single strongest signal in the cluster — STRONG > MEDIUM > WEAK."""
    if any(s.strength == STRONG for s in cluster):
        return STRONG
    if any(s.strength == MEDIUM for s in cluster):
        return MEDIUM
    return WEAK


def correlation_score(cluster: "list[Signal]") -> int:
    """Weighted score for one cross-module cluster:

        raw signal weight   (weak=1, medium=2, strong=3, summed across
                              every member)
      + corroboration bonus (2 points per distinct module BEYOND the
                              first — more independent, unrelated
                              subsystems agreeing is stronger evidence,
                              scaled directly rather than a single flat
                              "cross-module" bonus, so 3+ modules score
                              meaningfully higher than 2)
      + combination bonus   (a flat +4 if the module set contains a
                              security-meaningful pair, regardless of
                              how many such pairs are present or how
                              strong any individual member is — this is
                              the "is the combination itself meaningful"
                              factor, distinct from signal strength)
    """
    raw = sum(WEIGHT[s.strength] for s in cluster)
    modules = distinct_modules(cluster)
    corroboration_bonus = 2 * (len(modules) - 1)
    combo_bonus = 4 if has_meaningful_combo(cluster) else 0
    return raw + corroboration_bonus + combo_bonus


def severity_for_score(score: int) -> str:
    if score <= 2:
        return INFORMATIONAL
    if score <= 5:
        return LOW
    if score <= 9:
        return MEDIUM_SEVERITY
    if score <= 13:
        return HIGH
    return CRITICAL


def apply_weak_signal_cap(severity: str, cluster: "list[Signal]") -> str:
    """Never let an all-WEAK cluster reach HIGH or CRITICAL, no matter
    how many weak signals piled up or how many modules they span — per
    explicit instruction. MEDIUM remains reachable for an all-weak
    cluster (only HIGH/CRITICAL are off-limits); any cluster containing
    so much as one MEDIUM or STRONG signal is completely unaffected by
    this cap.
    """
    if max_strength(cluster) != WEAK:
        return severity
    if _SEVERITY_ORDER.index(severity) > _SEVERITY_ORDER.index(MEDIUM_SEVERITY):
        return MEDIUM_SEVERITY
    return severity


def fingerprint_for_cluster(cluster: "list[Signal]") -> str:
    """Stable hash of a cluster's exact member rows — the UNIQUE key
    correlation_alerts is keyed on, so re-running `secure correlate`
    (including as part of `secure run-all`) over overlapping history
    never re-alerts on the same cluster. Order-independent (sorted
    before hashing) since the same underlying rows should fingerprint
    identically regardless of query/collection order.
    """
    parts = sorted(f"{s.source_table}:{s.source_id}" for s in cluster)
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def build_explanation(
    cluster: "list[Signal]",
    raw_score: int,
    final_score: int,
    severity: str,
    context_notes: Optional[str],
) -> str:
    """Plain-English breakdown of how this cluster reached `severity`
    — stored alongside the alert so the result is explainable, not just
    a bare number. Always ends by naming this as temporal coincidence,
    not proof of a single cause.
    """
    modules = sorted(distinct_modules(cluster))
    span_seconds = (cluster[-1].timestamp - cluster[0].timestamp).total_seconds()

    lines = [
        f"{len(cluster)} signal(s) across {len(modules)} module(s) "
        f"({', '.join(modules)}) within {span_seconds:.0f}s:"
    ]
    for signal in cluster:
        label = f" '{signal.label}'" if signal.label else ""
        lines.append(
            f"  - [{signal.strength.upper()}] {signal.module}.{signal.kind}: "
            f"{signal.identifier}{label}"
        )

    if has_meaningful_combo(cluster):
        lines.append("This module combination is considered security-meaningful.")

    score_line = f"Score {raw_score}"
    if final_score != raw_score:
        score_line += f" (reduced to {final_score} — see context notes below)"
    score_line += f" -> {severity.upper()}."
    lines.append(score_line)

    if context_notes:
        lines.append(f"Context: {context_notes}")

    lines.append(
        "This reflects multiple independent subsystems reporting activity close "
        "together in time — it is coincidence in time, not proof of a single cause "
        "or of malicious activity. Review each underlying finding individually."
    )
    return "\n".join(lines)
