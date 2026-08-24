"""Correlation CHAIN alert explainer (Phase 22 Stage 4).

Unlike correlation_explainer.py (which recomputes very little — most of
a CorrelationAlertRecord's interpretation is derived here, from raw
member/strength data), a CorrelationChainAlertRecord already carries
its own confidence, severity, uncertainty_notes, and a full multi-line
explanation string — all computed once, deterministically, by
secure/correlate/chains.py's score_chain(). This explainer's job is
narrower: reshape those ALREADY-COMPUTED fields into the shared
Explanation model every other source table uses, so a chain alert
looks and behaves like any other finding in the Alerts table (Level
1/2/3 progressive disclosure — see docs/DESIGN_SYSTEM.md) without a
second scoring pass. It never recomputes confidence, severity, or
concentration — those stay owned exactly once, in chains.py.
"""

from __future__ import annotations

from secure.explain import vocab
from secure.explain.explanation import EvidenceItem, Explanation, generic_explanation, resolve_action


def _describe_member(m: dict) -> str:
    module = m.get("module") or "?"
    source = m.get("source") or module
    table = m.get("source_table") or "?"
    source_id = m.get("source_id")
    group_id = m.get("group_id")
    return f"{module}/{source} ({table}:{source_id}, fact #{group_id})"


def explain_chain_alert(record) -> Explanation:
    members = record.members or []
    if not members:
        return generic_explanation(
            source_table="correlation_chain_alerts",
            severity=record.severity,
            message=record.explanation or "A correlation chain was recorded with no member detail available.",
            subject=f"{record.module_count} module(s)",
        )

    confidence = record.confidence
    confidence_reason = (
        f"{record.independent_fact_count} independent fact(s) after Phase 21 lineage deduplication, "
        f"across {record.module_count} module(s) and {record.meaningful_relationship_count} meaningful "
        f"cross-source relationship(s); evidence concentration {record.concentration:.0%}."
    )

    uncertainty = list(record.uncertainty_notes) if record.uncertainty_notes else [
        "A chain of linked evidence is not proof of a single malicious cause — "
        "it shows that specific stored rows are related, not why."
    ]

    evidence = [
        EvidenceItem(
            f"{record.raw_observation_count} raw observation(s) collapsed into "
            f"{record.independent_fact_count} independent fact(s) — duplicate/confirming "
            "observations of the same underlying event do not each count as separate "
            "corroboration.",
            vocab.DERIVED_FACT,
        ),
        EvidenceItem(
            f"{record.meaningful_relationship_count} meaningful cross-source relationship(s) "
            "(derived_evidence links crossing independent facts from different modules).",
            vocab.DERIVED_FACT,
        ),
    ]
    if record.concentration >= 0.6 and record.module_count > 1:
        evidence.append(
            EvidenceItem(
                f"Evidence concentration is {record.concentration:.0%} — most of this chain's "
                "independent facts come from a single module; treat the apparent corroboration "
                "with caution.",
                vocab.SECURE_INTERPRETATION,
            )
        )
    shown = [_describe_member(m) for m in members[:8]]
    more = f" (+{len(members) - 8} more)" if len(members) > 8 else ""
    evidence.append(
        EvidenceItem(f"Chain members: {'; '.join(shown)}{more}", vocab.DIRECT_OBSERVATION)
    )
    evidence.append(EvidenceItem(record.explanation, vocab.DERIVED_FACT))

    correlated_events = tuple(_describe_member(m) for m in members)

    significance = (
        "This is a genuine multi-step evidence chain — specific stored rows are linked by "
        "asserted parent/derived or confirmation relationships, not merely observed close "
        "together in time."
        if record.meaningful_relationship_count > 0
        else "These facts are directly linked by asserted evidence relationships, though no "
        "cross-module causal step was found among them."
    )

    if record.severity in ("high", "critical") and confidence in (vocab.LIKELY, vocab.CONFIRMED):
        action_key = vocab.INVESTIGATE_NOW
    else:
        action_key = vocab.CLASSIFY
    action, action_text = resolve_action(action_key)

    summary = (
        f"{record.independent_fact_count} independent fact(s) across {record.module_count} "
        f"module(s), linked by {record.meaningful_relationship_count} meaningful relationship(s), "
        "were assembled into an evidence chain."
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
