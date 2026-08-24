"""
secure/threatintel/indicators.py — pure classification/validation/
privacy logic for the three indicator types Phase 20 asks for (IPs,
domains, file hashes). No I/O, no database, no network — directly
testable with plain strings.

Two separate jobs, deliberately kept apart:

    1. classify_indicator() — "what KIND of thing is this string, and
       is it even shaped like a real indicator" — pure syntax, no
       opinion about whether it's safe to look up anywhere.
    2. is_sendable_to_network_provider() — "would looking this up
       externally leak something private about THIS network" — Phase
       20's own explicit "avoid unnecessary external disclosure of
       private/local information" instruction. This is intentionally
       a SEPARATE, conservative, best-effort check: a local-only
       provider (see providers/local_feed.py) never needs it, since it
       makes no outbound call at all; only providers whose
       ProviderIdentity.network is True are gated by it (see enrich.py).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

IP = "ip"
DOMAIN = "domain"
HASH = "hash"

INDICATOR_TYPES = (IP, DOMAIN, HASH)

_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Deliberately conservative: requires a dot-separated label structure
# with an alphabetic-only final label (a TLD), so plain IPs and
# version-like strings ("7.0.3") never masquerade as a domain. Not a
# full RFC-1035 validator — good enough to decide "is this shaped like
# a domain," not to guarantee registrability.
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

# Local-only suffixes/labels that are never worth sending to a network
# provider even though they're shaped like a domain — mDNS/NetBIOS-
# style local names, not real internet domains. Best-effort, not
# exhaustive; see is_sendable_to_network_provider()'s own docstring.
_LOCAL_DOMAIN_SUFFIXES = (
    ".local", ".internal", ".lan", ".home", ".localdomain", ".corp", ".test",
)


def classify_indicator(value: str) -> "Optional[str]":
    """Return IP / DOMAIN / HASH for a string shaped like one of those,
    or None if it isn't recognizable as any of the three — never
    guesses; a caller should treat None as "not a usable indicator,"
    not silently fall back to any one type.
    """
    if not value or not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return None

    try:
        ipaddress.ip_address(value)
        return IP
    except ValueError:
        pass

    if _HEX_RE.match(value) and len(value) in _HASH_LENGTHS:
        return HASH

    if _DOMAIN_RE.match(value):
        return DOMAIN

    return None


def hash_algorithm(value: str) -> "Optional[str]":
    """md5/sha1/sha256 by length, or None — only meaningful once
    classify_indicator() has already confirmed `value` is a HASH.
    """
    if not value or not _HEX_RE.match(value):
        return None
    return _HASH_LENGTHS.get(len(value))


def normalize_indicator(indicator_type: str, value: str) -> str:
    """Canonical storage/cache-key form: IPs via ipaddress's own
    compressed string form (so "1.2.3.04" and "1.2.3.4" - if both were
    ever somehow valid - would still collide correctly; in practice
    this mainly normalizes IPv6 forms), domains/hashes lowercased.
    """
    value = value.strip()
    if indicator_type == IP:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value
    return value.lower()


def is_private_or_local_ip(value: str) -> bool:
    """True for any IP that should never leave this Mac: RFC1918
    private ranges, loopback, link-local, multicast, and other
    ipaddress-flagged reserved ranges. False (and therefore "would be
    sent") only for a genuinely global-looking address.

    Note for readers of this codebase's own tests: the stdlib
    `ipaddress` module marks the IANA TEST-NET-1/2/3 documentation
    ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — the exact
    ranges every fixture elsewhere in this app's test suite uses for
    synthetic IOCs, since they're guaranteed never to route anywhere
    real) as `is_private = True`. That's correct, intentional behavior
    here too: those addresses can never be real internet hosts, so
    "never send them to a network provider" is the right call — it
    just means this module's own tests use a real, well-known public
    resolver address (e.g. 8.8.8.8) to exercise the "genuinely public,
    would be sent" branch, since the usual TEST-NET fixtures can't.
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False  # not a parseable IP at all — not this function's job to decide
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def is_local_domain(value: str) -> bool:
    """Best-effort: a domain that looks internal-only (mDNS/NetBIOS-
    style suffix, or a bare single-label hostname with no dot at all —
    which classify_indicator() would already reject as DOMAIN, but
    this function is also usable standalone on a raw candidate string
    pulled from message text before classification). Not exhaustive —
    a corporate domain that happens to be internal-only but doesn't use
    one of these suffixes will not be caught; documented as a known
    limitation in docs/THREATINTEL.md.
    """
    if not value:
        return True
    lowered = value.strip().lower()
    if "." not in lowered:
        return True
    return any(lowered.endswith(suffix) for suffix in _LOCAL_DOMAIN_SUFFIXES)


def is_sendable_to_network_provider(indicator_type: str, value: str) -> bool:
    """The single check enrich.py calls before letting a `network=True`
    provider see an indicator at all. Conservative in the safe
    direction: returns False (do not send) whenever there's genuine
    doubt, never guesses "probably fine."
    """
    if indicator_type == IP:
        return not is_private_or_local_ip(value)
    if indicator_type == DOMAIN:
        return not is_local_domain(value)
    if indicator_type == HASH:
        return True  # a file hash carries no network/location information by itself
    return False
