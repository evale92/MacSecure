"""
secure/integrations/yarax/ — Phase 16's second concrete integration:
YARA-X (https://virustotal.github.io/yara-x/), used as Secure's
specialist file/content detection engine.

Division of responsibility, kept deliberately clean:

    File Integrity Monitoring (secure/fileintegrity/) answers
    "what changed" — hashes, metadata, timing.
    YARA-X answers "what characteristics does this file match" — content
    patterns, never a timeline.

    _engine.py    — the only file that touches the actual yara_x
                    library, lazily imported (mirrors bleak's own
                    lazy-import pattern in secure/bluetooth/ble/scanner.py).
    availability.py — classifies yara_x into one of IntegrationHealth's
                    four statuses via an actual compile+scan smoke test,
                    not just a successful import.
    rulesets.py    — discovers and compiles user-provided *.yar/*.yara
                    files from AppConfig.yara_rules_dir. No rules ship
                    with Secure — this is BYO detection content.
    analysis.py     — pure severity classification from a rule's own
                    metadata, and the "this is not a malware verdict"
                    interpretation boundary every match carries
                    (Phase 16: "do not automatically classify every
                    YARA match as malware").
    parser.py       — yara_x match objects -> normalized
                    ExternalObservation (secure/integrations/base.py).
    targets.py       — read-only selection of WHICH files to scan
                    (suspicious/FIM-flagged), never a directory walk.
    scanner.py        — orchestrates one scan pass; the only file here
                    that touches the database or reads file contents.

Secure's own native File Integrity Monitoring is never disabled,
replaced, or modified by this package — YARA-X is an additional,
targeted content-scanning capability only.
"""

from secure.integrations.yarax.analysis import (
    DEFAULT_SEVERITY,
    HIGH,
    LOW,
    MEDIUM,
    classify_yara_match_severity,
)
from secure.integrations.yarax.availability import check_availability
from secure.integrations.yarax.scanner import (
    INTEGRATION_NAME,
    YaraFileResult,
    YaraFinding,
    YaraScanResult,
    scan_fim_alerts,
    scan_paths,
    scan_suspicious,
)

__all__ = [
    "DEFAULT_SEVERITY",
    "HIGH",
    "LOW",
    "MEDIUM",
    "classify_yara_match_severity",
    "check_availability",
    "INTEGRATION_NAME",
    "YaraFileResult",
    "YaraFinding",
    "YaraScanResult",
    "scan_fim_alerts",
    "scan_paths",
    "scan_suspicious",
]
