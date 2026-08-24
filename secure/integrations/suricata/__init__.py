"""
secure/integrations/suricata/ — Phase 18's fourth concrete integration:
Suricata, used as Secure's specialist network IDS where macOS's own
network architecture permits reliable collection (see availability.py's
module docstring for the honest scope note on that).

Division of responsibility, deliberately narrow:

    Suricata's own detection engine — installed, configured, and run
    entirely OUTSIDE Secure, by the user — owns all signature/rule
    matching. Secure never reproduces that logic, never manages
    Suricata's process lifecycle, and never touches packet capture or
    network interfaces directly. This integration only reads
    Suricata's own EVE JSON log output, already written to disk.

    _eve.py        — the only file that reads the EVE JSON log itself;
                    plain stdlib `json` over a bounded tail of lines,
                    read-only, no subprocess, no packet access.
    _timeutil.py   — parses Suricata's own EVE timestamp format
                    (`+0000`, no colon) — datetime.fromisoformat() can't
                    on the Python version this project targets.
    _shell.py      — the ONLY file that runs a subprocess: a single,
                    optional, read-only `suricata -V` call purely for
                    tool_version provenance. Never required for the
                    rest of this integration to function.
    parser.py      — normalizes one EVE `alert` record into an
                    ExternalObservation (timestamp, signature/rule,
                    category/severity, source/destination, protocol/
                    flow identity, exact source provenance) and
                    extracts the latest capture-stats snapshot used for
                    honest packet-visibility health.
    analysis.py    — classify_suricata_severity(): translates
                    Suricata's OWN severity scale (1=highest) into
                    Secure's vocabulary — translation only, never a
                    second detection judgment.
    availability.py — the phase's own explicit "handle unavailable
                    packet visibility honestly" requirement: not just
                    "does the log file exist," but "can Secure actually
                    confirm packets are being seen right now," via
                    Suricata's own stats events.
    correlate.py   — attaches Secure's own native process/connection
                    context to an alert ONLY when a genuine
                    identity+timing match against connection_events is
                    found; explicitly says so when it isn't, rather
                    than omitting the field or guessing.
    scanner.py     — orchestrates one ingestion pass; the only file
                    here that touches the database.

Secure's own native network monitoring (connections/listening/arpwatch)
is never disabled, replaced, or modified by this package — Suricata
here is one more evidence source feeding the same integration_alerts
table Phase 15 established, subject to the same correlation and
explanation machinery already built for osquery/YARA-X/Sigma.
"""

from secure.integrations.suricata.analysis import (
    DEFAULT_SEVERITY,
    HIGH,
    LOW,
    MEDIUM,
    classify_suricata_severity,
)
from secure.integrations.suricata.availability import check_availability
from secure.integrations.suricata.correlate import (
    DEFAULT_CORRELATION_WINDOW_SECONDS,
    ProcessCorrelation,
    describe_correlation,
    find_process_correlation,
)
from secure.integrations.suricata.parser import ALERT_KIND, CAPTURE_STATS_KIND
from secure.integrations.suricata.scanner import (
    INTEGRATION_NAME,
    NETWORK_ALERT,
    SuricataFinding,
    SuricataScanResult,
    scan_suricata,
)

__all__ = [
    "DEFAULT_SEVERITY",
    "HIGH",
    "LOW",
    "MEDIUM",
    "classify_suricata_severity",
    "check_availability",
    "DEFAULT_CORRELATION_WINDOW_SECONDS",
    "ProcessCorrelation",
    "describe_correlation",
    "find_process_correlation",
    "ALERT_KIND",
    "CAPTURE_STATS_KIND",
    "INTEGRATION_NAME",
    "NETWORK_ALERT",
    "SuricataFinding",
    "SuricataScanResult",
    "scan_suricata",
]
