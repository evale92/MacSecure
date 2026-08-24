"""
explain/integration_explainer.py — explainer for integration_alerts
rows (Phase 15: osquery cross-check discrepancies; Phase 16: YARA-X
rule matches; Phase 17: Sigma rule matches; Phase 18: Suricata IDS
alerts). One shared table, four very different kinds of finding —
dispatched internally by `record.integration`, the same way
dispatch.py itself dispatches by source_table, just one level deeper
since all four integrations currently share one table.

Follows every rule in secure/explain/__init__.py: severity is always a
verbatim passthrough from the record; nothing here recomputes it.
Confidence answers "how sure is Secure the REPORTED FACT is real,"
never "how sure is Secure this is malicious" — see vocab.py's
CONFIRMED definition. This distinction matters most for the yarax,
sigma, and suricata branches: Phase 16's explicit instruction is "do
not automatically classify every YARA match as malware," Phase 17's is
"keep rule matches separate from final Secure severity/confidence
decisions," and Phase 18's is "do not reproduce Suricata detection
logic inside Secure" — CONFIRMED in all three branches means only "the
pattern/rule/signature match itself is not in doubt," exactly
mirroring how explain_file_integrity_alert() already uses CONFIRMED
for "the hash changed" without that meaning "this is tampering."
"""

from __future__ import annotations

from secure.explain import vocab
from secure.explain.explanation import EvidenceItem, Explanation, resolve_action


def _finish(
    record,
    *,
    summary: str,
    significance: str,
    uncertainty: tuple,
    action_key: str,
    confidence: str = vocab.CONFIRMED,
    confidence_reason: str,
    uncertainty_status: str = vocab.UNCERTAINTY_KNOWN,
) -> Explanation:
    action, action_text = resolve_action(action_key)
    return Explanation(
        summary=summary,
        severity=record.severity,
        confidence=confidence,
        confidence_reason=confidence_reason,
        significance=significance,
        recommended_action=action,
        recommended_action_text=action_text,
        evidence=(EvidenceItem(record.message, vocab.DIRECT_OBSERVATION),),
        correlated_events=(),
        uncertainty_status=uncertainty_status,
        uncertainty=uncertainty,
    )


def _explain_osquery_alert(record) -> Explanation:
    subject = record.label or record.identity_key

    if record.discrepancy == "osquery_only":
        significance = (
            "osquery, an independent cross-check engine, observed this but Secure's "
            "own native scan did not. This is exactly the scenario running a second, "
            "independent collector exists to catch — either Secure's own scan missed "
            "something, or the two scans simply ran at different moments."
        )
        uncertainty = (
            "Scan-timing or scope differences between Secure's native scan and this "
            "osquery pass commonly explain a one-sided result like this.",
            "It can also mean Secure's own collector genuinely missed something this "
            "cross-check caught.",
        )
        action_key = vocab.REVIEW_PERSISTENCE if record.kind == "persistence" else vocab.INVESTIGATE_NOW
    else:  # native_only
        significance = (
            "Secure's own native scan already tracks this; this osquery pass simply "
            "did not independently confirm it. Already visible and actionable through "
            "that native collector's own alert, not a new finding on its own."
        )
        uncertainty = (
            "osquery not confirming something Secure's native scan already knows about "
            "is ordinary scan-timing noise in the large majority of cases.",
        )
        action_key = vocab.RESCAN

    return _finish(
        record,
        summary=f"osquery cross-check {record.discrepancy.replace('_', ' ')}: {subject}",
        significance=significance,
        uncertainty=uncertainty,
        action_key=action_key,
        confidence_reason=(
            "The discrepancy itself — which source(s) reported this — is a direct "
            "comparison between two independently stored scan results, not inferred."
        ),
    )


def _explain_yarax_alert(record) -> Explanation:
    subject = record.label or record.identity_key

    return _finish(
        record,
        summary=f"YARA-X rule match: '{subject}'",
        significance=(
            "A YARA-X content-pattern rule matched this file. This reports that the "
            "file has characteristics the rule's author chose to look for — it does "
            "not, by itself, mean the file is malicious. File Integrity Monitoring "
            "answers 'what changed'; YARA-X answers 'what characteristics does this "
            "file match' — this is that second, independent kind of evidence."
        ),
        uncertainty=(
            "Many legitimate files legitimately match rules aimed at packers, "
            "obfuscation techniques, or other broad heuristics — a match is not a "
            "malware verdict.",
            "Severity here reflects the matching rule's own declared metadata (or "
            "Secure's non-committal default when a rule declares none) — it is not "
            "an independent judgment about this specific file.",
        ),
        action_key=vocab.INSPECT_FILE,
        confidence_reason=(
            "That this specific rule matched this specific file's content is a "
            "direct result of the scan — not in doubt. Whether that match indicates "
            "anything concerning is a separate question this confidence level does "
            "not answer; see the uncertainty notes."
        ),
    )


def _explain_sigma_alert(record) -> Explanation:
    subject = record.label or record.identity_key
    category = record.kind  # "process_creation" or "network_connection" — see capability.py

    action_key = (
        vocab.REVIEW_NETWORK_DESTINATION if category == "network_connection" else vocab.INSPECT_PROCESS
    )

    return _finish(
        record,
        summary=f"Sigma rule match ({category}): '{subject}'",
        significance=(
            "A Sigma detection rule's condition was satisfied by telemetry Secure "
            "collected through osquery. This reports that the rule's logic matched — "
            "it does not, by itself, mean this activity is malicious. Secure only "
            "evaluates a Sigma rule at all when it has genuinely confirmed the "
            "telemetry that rule needs; a rule Secure lacks telemetry for is reported "
            "NOT EVALUABLE elsewhere and never silently treated as clean."
        ),
        uncertainty=(
            "Many legitimate activities can satisfy a broad detection rule's "
            "condition — a match is not an intrusion verdict on its own.",
            "Severity here reflects the matching rule's own declared level (or "
            "Secure's non-committal default when a rule declares none) — it is not "
            "an independent judgment about this specific activity, and is kept "
            "separate from Secure's own confidence in the underlying telemetry.",
        ),
        action_key=action_key,
        confidence_reason=(
            "That this specific rule's condition matched this specific telemetry is "
            "a direct result of the evaluation — not in doubt. Whether that match "
            "indicates anything concerning is a separate question this confidence "
            "level does not answer; see the uncertainty notes."
        ),
    )


def _explain_suricata_alert(record) -> Explanation:
    subject = record.label or record.identity_key
    action_key = vocab.REVIEW_NETWORK_DESTINATION

    # scanner.py already embeds an explicit correlation sentence in
    # record.message (either a real "correlated with connection #N,
    # attributed to X" or the honest "no matching native connection ...
    # process attribution is not established" — see
    # secure/integrations/suricata/correlate.py's describe_correlation()).
    # Whether that sentence describes a real match matters for how
    # confidently this explanation can talk about process attribution,
    # so it's checked here rather than re-deriving it independently.
    attribution_established = "process attribution is not established" not in (record.message or "")

    return _finish(
        record,
        summary=f"Suricata IDS alert: '{subject}'",
        significance=(
            "Suricata's own detection engine matched network traffic against one of its "
            "signatures. Secure does not evaluate network traffic against Suricata's rules "
            "itself and does not second-guess this match — it only normalizes and reports "
            "it. " + (
                "A specific process was identified as involved, based on a genuine "
                "identity-and-timing match against Secure's own native connection "
                "observations."
                if attribution_established
                else "No specific process could be identified for this alert — Secure only "
                "reports process attribution when a genuine identity-and-timing match "
                "against its own native connection observations is found, never a guess."
            )
        ),
        uncertainty=(
            "A Suricata signature match reports that traffic satisfied a detection rule — "
            "it is not, by itself, a confirmed compromise or malicious-intent determination.",
            "Process attribution (when present) is a best-effort correlation within a "
            "bounded time window against Secure's own periodic connection scans, not a "
            "kernel-level guarantee that this exact process generated this exact traffic.",
        ),
        action_key=action_key,
        confidence_reason=(
            "That this specific signature matched this specific traffic is Suricata's own "
            "direct finding, not inferred by Secure — not in doubt. Whether that traffic "
            "reflects an actual compromise, and (when unattributed) which process was "
            "responsible, are separate questions this confidence level does not answer; "
            "see the uncertainty notes."
        ),
    )


def explain_integration_alert(record) -> Explanation:
    if record.integration == "yarax":
        return _explain_yarax_alert(record)
    if record.integration == "sigma":
        return _explain_sigma_alert(record)
    if record.integration == "suricata":
        return _explain_suricata_alert(record)
    if record.integration == "osquery":
        return _explain_osquery_alert(record)
    # Unrecognized future integration: never guess at its semantics —
    # dispatch.py's own generic_explanation() fallback (via raising
    # here) is the honest choice, same as an unrecognized source_table.
    raise ValueError(f"No explainer branch for integration {record.integration!r}")
