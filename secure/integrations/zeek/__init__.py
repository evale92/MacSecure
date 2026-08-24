"""
secure/integrations/zeek/ — Phase 19's fifth concrete integration: Zeek,
used as Secure's specialist BEHAVIORAL/PROTOCOL network telemetry
source, deliberately complementary to (not redundant with) Suricata
(Phase 18):

    Suricata — detection/signature evidence. Its own rule engine
               decides what's worth alerting on; Secure only reads its
               already-decided findings (eve.json). See
               secure/integrations/suricata/.
    Zeek     — behavioral/protocol telemetry. Zeek's own analysis
               scripts produce rich, structured facts ABOUT network
               activity (which domains were queried, which TLS
               hostnames were connected to, connection duration/byte
               counts, ...) without themselves being detection
               judgments. Secure never asks "is this bad" about a Zeek
               record — it normalizes, dedup-classifies, and (for two
               specific observation kinds) feeds it to the behavioral-
               baseline layer that already exists for every other
               entity_type in this app.

This split is enforced structurally: this package has NO analysis.py,
NO severity classifier, and its scanner NEVER calls
add_integration_alert() — there is nothing here that could produce an
integration_alerts row, so Zeek evidence can never be mistaken for a
detection finding the way a Suricata/YARA-X/Sigma match is. See
scanner.py's own module docstring for the full reasoning, including
exactly which two Zeek observation kinds ARE allowed to feed the
baseline layer and why the other two deliberately aren't, and how
"bulk network noise must not immediately create mature baselines" is
satisfied by reusing (not reinventing) Phase 14's own maturity-timing
rules and connections/scanner.py's own "at most one baseline
observation per distinct entity per scan pass" discipline.

    _logs.py       — the only file that reads Zeek's own JSON log
                    files; plain stdlib `json` over a bounded tail of
                    lines, read-only, no subprocess, no packet access.
                    Supports Zeek's native JSON log output only (not
                    the default TSV format) — see that module's own
                    docstring for why.
    _timeutil.py   — parses Zeek's own `ts` field (a UNIX epoch
                    number).
    _shell.py      — the ONLY file that runs a subprocess: a single,
                    optional, read-only `zeek --version` call purely
                    for tool_version provenance. Never required for the
                    rest of this integration to function.
    parser.py      — normalizes one conn.log/dns.log/ssl.log/http.log
                    record into an ExternalObservation (timestamp,
                    endpoint identity, protocol-specific fields, exact
                    source provenance).
    identity.py    — pure normalization of the two Zeek-derived
                    identities the baseline layer is allowed to learn
                    from (a DNS query domain, a TLS SNI hostname).
    availability.py — "is Zeek's log output currently readable and
                    fresh" — see that module's own docstring for how
                    this differs, deliberately, from Suricata's own
                    packet-visibility health check.
    dedup.py       — Phase 19's own explicit "dedup awareness for
                    network events already seen by Secure or Suricata"
                    requirement: classifies each conn.log record as
                    novel, matching a native connection_events row, or
                    matching an already-ingested Suricata EVE alert —
                    identity AND timing, same conservative discipline
                    Suricata's own correlate.py uses for process
                    attribution.
    scanner.py     — orchestrates one ingestion pass, including the
                    baseline-layer wiring; the only file here that
                    touches the database.

Secure's own native network monitoring (connections/listening/arpwatch)
and Suricata's own detection evidence are never disabled, replaced, or
modified by this package — Zeek here is one more evidence source, held
to its own honestly-scoped role.
"""

from secure.integrations.zeek.availability import check_availability
from secure.integrations.zeek.dedup import (
    DEFAULT_DEDUP_WINDOW_SECONDS,
    MATCHES_NATIVE_CONNECTION,
    MATCHES_SURICATA_ALERT,
    NOVEL,
    DedupResult,
    classify_conn_dedup,
)
from secure.integrations.zeek.identity import dns_query_domain, tls_sni_hostname
from secure.integrations.zeek.parser import CONN_KIND, DNS_KIND, HTTP_KIND, SSL_KIND
from secure.integrations.zeek.scanner import INTEGRATION_NAME, ZeekScanResult, scan_zeek

__all__ = [
    "check_availability",
    "DEFAULT_DEDUP_WINDOW_SECONDS",
    "MATCHES_NATIVE_CONNECTION",
    "MATCHES_SURICATA_ALERT",
    "NOVEL",
    "DedupResult",
    "classify_conn_dedup",
    "dns_query_domain",
    "tls_sni_hostname",
    "CONN_KIND",
    "DNS_KIND",
    "HTTP_KIND",
    "SSL_KIND",
    "INTEGRATION_NAME",
    "ZeekScanResult",
    "scan_zeek",
]
