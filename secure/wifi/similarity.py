"""
wifi/similarity.py — pure string-similarity logic for spotting a
suspicious lookalike SSID (an "evil twin" broadcasting a name that's
almost, but not quite, one you already trust).

Deliberately conservative, per the same "avoid false alarms" spirit as
secure/arpwatch/analysis.py: very short SSIDs are skipped entirely
(edit distance on a 3-character name is nearly meaningless — almost
anything is "close" to it), and the default distance threshold is
small (2 characters) so two genuinely unrelated short-ish names don't
get flagged against each other by coincidence.
"""

from __future__ import annotations

from typing import List

_MIN_SSID_LENGTH_TO_COMPARE = 4


def levenshtein_distance(a: str, b: str) -> int:
    """Standard edit distance (insertions/deletions/substitutions)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i] + [0] * len(b)
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            current_row[j] = min(
                previous_row[j] + 1,  # deletion
                current_row[j - 1] + 1,  # insertion
                previous_row[j - 1] + cost,  # substitution
            )
        previous_row = current_row
    return previous_row[-1]


def find_similar_known_ssids(
    ssid: str, known_ssids: List[str], max_distance: int = 2
) -> List[str]:
    """Return every known (trusted) SSID that closely resembles `ssid`
    without matching it exactly. Skips comparisons involving a name
    shorter than 4 characters on either side.
    """
    if len(ssid) < _MIN_SSID_LENGTH_TO_COMPARE:
        return []

    similar = []
    for known in known_ssids:
        if known == ssid or len(known) < _MIN_SSID_LENGTH_TO_COMPARE:
            continue
        if levenshtein_distance(ssid, known) <= max_distance:
            similar.append(known)
    return similar
