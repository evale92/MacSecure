"""
integrations/zeek/identity.py — pure normalization of the two
Zeek-derived identities Secure's behavioral-baseline layer is allowed
to learn from this phase: the DNS query domain and the TLS SNI
hostname (see scanner.py's module docstring for exactly which Zeek
observations feed the baseline layer, and why conn.log/http.log
deliberately do not).

Kept as its own tiny module, separate from parser.py, because these two
functions are called from a different place (scanner.py's baseline
dedup-within-a-scan-pass loop) for a different purpose (deriving a
baseline_entities.entity_key) than parser.py's raw-field normalization
— and so they're independently unit-testable without needing a full
ExternalObservation.
"""

from __future__ import annotations

from typing import Optional


def dns_query_domain(fields: dict) -> "Optional[str]":
    """The baseline entity_key for a dns.log observation's `query`
    field: lowercased, with exactly one trailing dot stripped (Zeek
    sometimes logs the fully-qualified form with a trailing root dot,
    e.g. "example.com."). Returns None for an empty/whitespace-only or
    missing query — never an empty-string entity_key.
    """
    query = fields.get("query")
    if not isinstance(query, str):
        return None
    normalized = query.strip().lower()
    if normalized.endswith(".") and len(normalized) > 1:
        normalized = normalized[:-1]
    return normalized or None


def tls_sni_hostname(fields: dict) -> "Optional[str]":
    """The baseline entity_key for a ssl.log observation's
    `server_name` (SNI) field: lowercased. Returns None when no SNI was
    present in the handshake — a normal, common case (see parser.py's
    parse_ssl_record docstring), never fabricated from another field.
    """
    server_name = fields.get("server_name")
    if not isinstance(server_name, str):
        return None
    normalized = server_name.strip().lower()
    return normalized or None
