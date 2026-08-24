"""
correlate/strength.py — pure classification of one signal's individual
"strength" tier, independent of anything about clustering or scoring
(that's analysis.py's job). No subprocess calls, no database access —
just string-in, string-out logic, so every rule here is directly
testable without a real Mac or a seeded database.

Three tiers, used consistently across every module's signals:

    STRONG — on its own, already a real, specific finding (an
             unexpected pairing, a gateway MAC change, a confirmed
             unsigned executable, ...).
    MEDIUM — a real but softer signal (a first connection by an
             untrusted-but-already-known device, a signed-but-new
             persistence entry, ...).
    WEAK   — ordinary background churn that's only interesting in
             combination with something else (a new LAN device, a new
             BLE peripheral, a new signed process, ...).

This is a DIFFERENT axis than each source module's own severity
string. A module's own severity answers "how worried should you be
about this on its own"; strength answers "how much should this count
toward a CROSS-module correlation score." The two often agree but
don't have to — see classify_arp_alert_strength()'s ip_conflict case,
which the correlation engine treats as stronger evidence than
arpwatch's own "medium" severity does, per the user's explicit
correlation-severity request.

Reuses secure/persistence/codesign.py's and analysis.py's constants
and is_unusual_location() directly (imported, not duplicated) — the
"process" signal dimension is about the exact same signing/location
facts persistence.py already computes, just weighed differently here.
"""

from __future__ import annotations

from typing import Optional

from secure.persistence.analysis import is_unusual_location
from secure.persistence.codesign import SIGNED_ADHOC, SIGNED_APPLE, SIGNED_DEVELOPER, UNSIGNED

WEAK = "weak"
MEDIUM = "medium"
STRONG = "strong"

# Used by analysis.py's correlation_score() to turn a strength tier
# into a number. Kept here, next to the tier constants themselves, so
# the two can never drift out of sync.
WEIGHT = {WEAK: 1, MEDIUM: 2, STRONG: 3}

_UNSIGNED_LIKE = (UNSIGNED, SIGNED_ADHOC)
_SIGNED = (SIGNED_APPLE, SIGNED_DEVELOPER)


def classify_process_strength(signing_status: Optional[str], executable_path: Optional[str]) -> str:
    """A newly-seen process's strength: STRONG if confirmed unsigned or
    ad-hoc signed (regardless of where it runs from — "new unsigned
    process" is a flat STRONG signal per the user's classification),
    MEDIUM if codesign couldn't determine a status at all (genuinely
    ambiguous — not a confirmed negative, but not confidently clean
    either) or if it's signed but running from an unusual location,
    WEAK if it's signed and running from an ordinary location ("new
    signed process" — the ordinary case, only interesting combined with
    something else).
    """
    if signing_status in _UNSIGNED_LIKE:
        return STRONG
    if signing_status not in _SIGNED:
        return MEDIUM  # codesign never ran / unknown — ambiguous, not confirmed clean
    if is_unusual_location(executable_path):
        return MEDIUM
    return WEAK


def classify_persistence_alert_strength(severity: str) -> str:
    """A persistence_alerts row's strength — these only ever come
    stamped "medium" or "high" (see
    secure/persistence/analysis.py's persistence_entry_alert_severity()
    and is_signing_downgrade(), which never emit anything else), but
    this stays defensive rather than assuming that never changes.
    """
    if severity == "high":
        return STRONG
    if severity == "medium":
        return MEDIUM
    return MEDIUM


def classify_listening_strength(bind_scope: str) -> str:
    """A brand-new listening service: STRONG if it's exposed beyond
    this Mac ("new exposed listening service"), MEDIUM if it's
    localhost-only. listening_services doesn't record a signing status
    for the owning process, so "known/signed process" from the user's
    MEDIUM bullet is approximated here by bind scope alone — a
    documented simplification, not a precise signing check.
    """
    return STRONG if bind_scope == "network" else MEDIUM


def classify_arp_alert_strength(kind: str) -> str:
    """An arpwatch alert's strength. Deliberately NOT the same as
    arpwatch's own stored severity for `ip_conflict` (medium there) —
    the user's correlation classification explicitly lists "IP/MAC
    conflict" as a STRONG signal in its own right, so this overrides
    it for correlation purposes specifically.
    """
    if kind in ("gateway_mac_changed", "ip_conflict"):
        return STRONG
    if kind == "mac_changed":
        return MEDIUM  # "important network configuration change"
    return MEDIUM


def classify_bluetooth_alert_strength(kind: str) -> str:
    """A bluetooth_alerts row's strength."""
    if kind == "new_pairing":
        return STRONG
    if kind == "first_connection":
        return MEDIUM
    if kind == "persistent_unknown":
        return WEAK
    return MEDIUM


def classify_file_integrity_strength(severity: str) -> str:
    """A file_integrity_alerts row's strength — these are only ever
    stamped "medium" or "high" (see secure/fileintegrity/scanner.py:
    LOW-severity findings stay in file_change_events history and never
    reach the alerts table at all, so there's nothing weaker than
    MEDIUM to classify here).
    """
    return STRONG if severity == "high" else MEDIUM


def classify_integration_alert_strength(discrepancy: str) -> str:
    """An integration_alerts row's strength (Phase 15). Only genuine
    native/osquery DISCREPANCIES ever reach integration_alerts in the
    first place — see secure/integrations/osquery/crosscheck.py's module
    docstring — so there is no "both sources agree" case to classify
    here at all; that case simply never produces a row.

    'osquery_only' (osquery independently saw something Secure's own
    native scan didn't) is STRONG — an independent second engine finding
    something the primary collector missed is a real, specific finding
    in its own right, the same bar classify_process_strength() and
    classify_arp_alert_strength() hold their own STRONG cases to.
    'native_only' (Secure's native scan saw it, osquery didn't confirm
    it this pass) is WEAK — already tracked and already alertable
    through that native collector's own alert path; osquery simply not
    confirming it this time is ordinary scan-timing noise, not new
    evidence of anything.
    """
    return STRONG if discrepancy == "osquery_only" else WEAK


def classify_yarax_finding_strength(severity: str) -> str:
    """An integration_alerts row from the yarax integration (Phase 16)
    — a YARA-X rule match, not a native/osquery cross-check discrepancy
    (see classify_integration_alert_strength() above for osquery's own,
    differently-keyed rule; signals.py dispatches to the right one by
    the row's `integration` column). Strength follows the match's own
    computed severity (secure/integrations/yarax/analysis.py's
    classify_yara_match_severity(), itself derived only from the
    matching rule's own declared metadata) directly: high->STRONG,
    medium->MEDIUM, low->WEAK.

    Deliberately NOT a blanket STRONG for every match: per Phase 16's
    explicit "do not automatically classify every YARA match as
    malware" instruction, a generic/no-declared-severity rule match
    (which classify_yara_match_severity() defaults to MEDIUM, not HIGH)
    must not automatically dominate a correlation cluster's score the
    way a STRONG signal does — that would effectively re-introduce the
    "match = malware" assumption one layer up, at the scoring level,
    even after analysis.py deliberately avoided asserting it directly.
    """
    if severity == "high":
        return STRONG
    if severity == "low":
        return WEAK
    return MEDIUM


def classify_suricata_finding_strength(severity: str) -> str:
    """An integration_alerts row from the suricata integration
    (Phase 18) — a Suricata IDS signature match, keyed by severity the
    same way classify_yarax_finding_strength()/classify_sigma_finding_
    strength() are (severity comes from secure/integrations/suricata/
    analysis.py's classify_suricata_severity(), itself a direct
    translation of Suricata's own rule-priority scale, never a Secure-
    invented judgment): high->STRONG, medium->MEDIUM, low->WEAK.

    Not a blanket STRONG for every alert, for the same reason as the
    other two integrations: Suricata's own severity scale defaults LOW
    priority rules (and anything unclassified) to Secure's LOW/WEAK
    tier rather than letting an unclassified or low-priority signature
    match dominate a correlation cluster's score as though it were
    confirmed serious.
    """
    if severity == "high":
        return STRONG
    if severity == "low":
        return WEAK
    return MEDIUM


def classify_sigma_finding_strength(severity: str) -> str:
    """An integration_alerts row from the sigma integration (Phase 17)
    — a Sigma rule match against osquery telemetry, keyed by severity
    the exact same way classify_yarax_finding_strength() is (severity
    comes from secure/integrations/sigma/analysis.py's
    classify_sigma_match_severity(), itself derived only from the
    matching rule's own declared `level`, never assumed): high->STRONG,
    medium->MEDIUM, low->WEAK.

    Deliberately NOT a blanket STRONG for every match, mirroring
    yarax's own reasoning: Phase 17's "keep rule matches separate from
    final Secure severity/confidence decisions" would be undone one
    layer up if a rule with no declared (or unrecognized) severity —
    which classify_sigma_match_severity() defaults to LOW, never
    higher — were still allowed to dominate a correlation cluster's
    score as though it were a STRONG signal.
    """
    if severity == "high":
        return STRONG
    if severity == "low":
        return WEAK
    return MEDIUM
