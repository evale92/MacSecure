"""Correlation alert explainer.

Reuses secure.correlate.analysis's existing distinct_modules /
max_strength / has_meaningful_combo / MEANINGFUL_MODULE_PAIRS
DIRECTLY (imported, not reimplemented) by adapting a
CorrelationAlertRecord's stored `members` (a list of plain dicts —
see secure/correlate/signals.py's Signal.as_dict()) into lightweight
objects those functions already expect (`.module`/`.strength`). This
is presentation/explanation only: it never recomputes score or
severity, and never changes which module combinations are considered
meaningful — that stays defined exactly once, in
secure/correlate/analysis.py.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Dict, FrozenSet, List

from secure.correlate.analysis import MEANINGFUL_MODULE_PAIRS, distinct_modules, has_meaningful_combo, max_strength
from secure.explain import vocab
from secure.explain.explanation import EvidenceItem, Explanation, generic_explanation, resolve_action

# Documentation of the EXISTING MEANINGFUL_MODULE_PAIRS set defined in
# secure/correlate/analysis.py — this is not a second rule table and
# does not decide which pairs are meaningful (that decision is made
# once, there). tests/test_explain.py asserts every pair currently in
# MEANINGFUL_MODULE_PAIRS has an entry here, so the two can't silently
# drift; a pair without a rationale falls back to
# _GENERIC_PAIR_RATIONALE rather than failing at runtime.
PAIR_RATIONALE: Dict[FrozenSet[str], str] = {
    frozenset({"process", "connections"}): "A new process appearing alongside a new outbound connection is a classic pattern for malware establishing command-and-control or exfiltrating data.",
    frozenset({"process", "persistence"}): "A new process backed by a new startup entry suggests software installing itself to survive a restart, not just running once.",
    frozenset({"persistence", "connections"}): "A new startup item alongside a new outbound connection suggests persistence paired with active network use — together stronger evidence than either alone.",
    frozenset({"process", "listening"}): "A new process opening a new listening port suggests software setting up to accept incoming connections.",
    frozenset({"listening", "connections"}): "A new listening port alongside new outbound activity suggests two-way network exposure appearing together.",
    frozenset({"wifi", "arpwatch"}): "A suspicious Wi-Fi network appearing alongside ARP table changes is consistent with a network-level interception attempt.",
    frozenset({"arpwatch", "inventory"}): "An ARP table change alongside a newly-seen device suggests the change coincides with new hardware appearing on the network.",
    frozenset({"bluetooth", "persistence"}): "A new Bluetooth pairing alongside a new startup item is consistent with companion software installing itself when a device connects.",
    frozenset({"file_integrity", "process"}): "A file changing alongside a new process suggests the process may be responsible for — or a result of — that change.",
    frozenset({"file_integrity", "connections"}): "A file changing alongside new outbound network activity suggests the change may be fetching or exfiltrating data.",
    frozenset({"file_integrity", "listening"}): "A file changing alongside a new listening port suggests the change may be setting up to accept incoming connections.",
    frozenset({"integrations", "listening"}): "An osquery/native listening-port disagreement alongside Secure's own listening activity suggests the two sources are seeing genuinely different states of the same machine, not just restating one observation twice.",
    frozenset({"integrations", "persistence"}): "An osquery/native persistence disagreement alongside a startup-item change suggests a second, independent engine sees something Secure's own persistence scan doesn't (or vice versa) right as persistence itself is changing.",
    frozenset({"integrations", "file_integrity"}): "A file changing alongside a YARA-X content match on that same activity is two independent kinds of evidence — byte-level change detection and content-pattern matching — agreeing something about this file is worth a closer look, not one observation restated twice.",
    frozenset({"integrations", "process"}): "A Sigma rule match alongside a new native process is two independent engines observing activity around the same process-creation event — the rule's condition and Secure's own native process detection agreeing, not one observation restated twice.",
    frozenset({"integrations", "connections"}): "A Sigma rule match alongside a new outbound connection is two independent engines observing activity around the same network-connection event — the rule's condition and Secure's own native connection detection agreeing, not one observation restated twice.",
}

_GENERIC_PAIR_RATIONALE = (
    "This module combination is treated as security-meaningful in "
    "secure/correlate/analysis.py, but does not yet have a specific, "
    "documented rationale here — see docs/EXPLAINABILITY.md."
)

# A cluster is considered "dominated by one source" when a single
# module accounts for at least this share of all raw observations
# (and more than one module is present at all — a single-module
# cluster isn't "concentrated," it's just... one module). This is a
# presentation threshold only; it never changes score or severity.
_CONCENTRATION_THRESHOLD = 0.6


@dataclass(frozen=True)
class _MemberSignal:
    """Adapts one `members` dict into the minimal shape
    secure.correlate.analysis's cluster functions expect — a
    reshaping shim, not new logic. Reusing the real functions here
    (instead of re-deriving distinct-module/strength logic) is what
    keeps this module from becoming a second scoring implementation.
    """

    module: str
    strength: str


def _adapt(members: List[dict]) -> List[_MemberSignal]:
    return [_MemberSignal(module=m.get("module") or "?", strength=m.get("strength") or "weak") for m in members]


def _matched_pairs(modules: set) -> List[frozenset]:
    return [pair for pair in MEANINGFUL_MODULE_PAIRS if pair <= modules]


def _describe_member(m: dict) -> str:
    module = m.get("module") or "?"
    kind = m.get("kind") or "?"
    identifier = m.get("identifier") or "?"
    label = m.get("label")
    label_text = f" '{label}'" if label else ""
    return f"{module}.{kind}: {identifier}{label_text}"


def explain_correlation_alert(record) -> Explanation:
    members = record.members or []
    if not members:
        return generic_explanation(
            source_table="correlation_alerts",
            severity=record.severity,
            message=record.explanation or "A correlation cluster was recorded with no member signal detail available.",
            subject=f"{record.module_count} module(s)",
        )

    signals = _adapt(members)
    modules = distinct_modules(signals)
    behaviors = {(m.get("module") or "?", m.get("kind") or "?") for m in members}
    raw_count = len(members)

    # ---- evidence concentration: raw count must not read as corroboration ----
    module_counts = Counter(m.get("module") or "?" for m in members)
    largest_module, largest_count = module_counts.most_common(1)[0]
    largest_share = (largest_count / raw_count) if raw_count else 0.0
    concentrated = largest_share >= _CONCENTRATION_THRESHOLD and len(modules) > 1

    meaningful = has_meaningful_combo(signals)
    matched_pairs = _matched_pairs(modules) if meaningful else []

    strongest_tier = max_strength(signals)
    strongest_members = [m for m in members if m.get("strength") == strongest_tier]

    # ---- confidence: derived only from fields already on this record ----
    # (context_notes, module concentration, meaningful-combo status) —
    # never from severity, and never overriding it.
    if record.context_notes:
        confidence = vocab.UNCERTAIN
        confidence_reason = (
            "This cluster coincides with a known benign-context pattern (see "
            "Context below) — the observations are real, but that context "
            "makes a benign explanation plausible."
        )
    elif concentrated:
        confidence = vocab.UNCERTAIN
        confidence_reason = (
            f"{largest_count} of {raw_count} observations ({largest_share:.0%}) "
            f"come from a single module ('{largest_module}') — this cluster is "
            "not as independently corroborated as its raw observation count "
            "alone would suggest."
        )
    elif meaningful and len(modules) >= 2:
        confidence = vocab.LIKELY
        confidence_reason = (
            f"{len(modules)} distinct modules contributed, including a module "
            "combination already documented as security-meaningful (see "
            "Evidence below)."
        )
    else:
        confidence = vocab.UNCERTAIN
        confidence_reason = (
            "Multiple signals were observed close together in time, but not "
            "in a module combination Secure specifically treats as meaningful."
        )

    # ---- uncertainty ----
    uncertainty = [
        "Correlation reflects multiple observations occurring close together "
        "in time — it is coincidence in time, not proof of a single cause or "
        "of malicious activity. Review each underlying finding individually.",
    ]
    if record.context_notes:
        uncertainty.append(record.context_notes)

    # ---- evidence ----
    evidence = [
        EvidenceItem(
            f"{raw_count} raw observation(s) across {len(modules)} distinct "
            f"module(s), within a {record.window_seconds:.0f}s window.",
            vocab.DERIVED_FACT,
        ),
        EvidenceItem(f"{len(behaviors)} distinct behavior(s) (module+kind combinations).", vocab.DERIVED_FACT),
    ]
    if concentrated:
        evidence.append(
            EvidenceItem(
                f"Largest contributor: {largest_module} — {largest_count} "
                f"signal(s) ({largest_share:.0%} of all observations).",
                vocab.DERIVED_FACT,
            )
        )
        evidence.append(
            EvidenceItem(
                "The raw observation count is heavily concentrated in one "
                "module and should not be interpreted as that many "
                "independent sources of corroboration.",
                vocab.SECURE_INTERPRETATION,
            )
        )
    if strongest_members:
        shown = [_describe_member(m) for m in strongest_members[:5]]
        more = f" (+{len(strongest_members) - 5} more)" if len(strongest_members) > 5 else ""
        evidence.append(
            EvidenceItem(f"Strongest signal(s) [{strongest_tier.upper()}]: {'; '.join(shown)}{more}", vocab.DIRECT_OBSERVATION)
        )
    for pair in matched_pairs:
        rationale = PAIR_RATIONALE.get(pair, _GENERIC_PAIR_RATIONALE)
        evidence.append(EvidenceItem(f"{'/'.join(sorted(pair))}: {rationale}", vocab.SECURE_INTERPRETATION))

    correlated_events = tuple(_describe_member(m) for m in members)

    significance = (
        "Multiple modules reported activity close together in time, in a "
        "combination Secure treats as potentially meaningful."
        if meaningful
        else "Multiple signals were observed close together in time."
    )

    if record.severity in ("high", "critical") and confidence in (vocab.LIKELY, vocab.CONFIRMED):
        action_key = vocab.INVESTIGATE_NOW
    else:
        action_key = vocab.CLASSIFY
    action, action_text = resolve_action(action_key)

    summary = (
        f"{raw_count} observation(s) across {len(modules)} module(s) "
        f"({', '.join(sorted(modules))}) within {record.window_seconds:.0f}s "
        "were correlated together."
    )

    return Explanation(
        summary=summary,
        severity=record.severity,
        confidence=confidence,
        confidence_reason=confidence_reason,
        significance=significance,
        recommended_action=action,
        recommended_action_text=action_text,
        evidence=tuple(evidence),
        correlated_events=correlated_events,
        uncertainty_status=vocab.UNCERTAINTY_KNOWN,
        uncertainty=tuple(uncertainty),
    )
