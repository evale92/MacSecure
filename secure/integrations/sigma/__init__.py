"""
secure/integrations/sigma/ — Phase 17's third concrete integration:
a deliberately bounded Sigma detection layer.

"Add Sigma-based detection capability without turning Secure into a
second Sigma implementation." This package supports a small, explicit
subset of the Sigma spec — two logsource categories
(process_creation, network_connection), a handful of fields each, and
a boolean condition grammar covering and/or/not/parens/1-of/all-of —
rather than attempting universal compatibility with the full spec.

Division of responsibility:

    _yaml.py       — the only file that touches the `yaml` (PyYAML)
                    library, lazily imported (mirrors yarax/_engine.py's
                    lazy `import yara_x`).
    rules.py       — discovers and parses user-provided *.yml/*.yaml
                    Sigma rule files from AppConfig.sigma_rules_dir. No
                    rules ship with Secure — BYO detection content,
                    same stance as yarax/rulesets.py.
    capability.py  — the adapter: given one parsed rule, decides
                    EVALUABLE or NOT_EVALUABLE by checking whether
                    Secure's own osquery telemetry actually covers that
                    rule's logsource category, product, and every field
                    it references. This is what makes "if required
                    telemetry is unavailable, report NOT EVALUABLE —
                    never CLEAN" a structural guarantee rather than a
                    convention: evaluator.py never runs a condition for
                    a rule this module rejects.
    condition.py   — tokenizes/parses/evaluates the bounded boolean
                    condition grammar this package supports.
    evaluator.py   — for one EVALUABLE rule, builds per-observation
                    event dicts from recent osquery observations (via
                    capability.py's field_map) and runs the parsed
                    condition against them.
    analysis.py    — classify_sigma_match_severity(): Secure's OWN,
                    deliberately conservative severity mapping from a
                    matched rule's `level` — never a blind passthrough
                    of the rule's own claim (Phase 17: "keep rule
                    matches separate from final Secure severity/
                    confidence decisions").
    scanner.py     — orchestrates one scan pass; the only file here
                    that touches the database. Persists a
                    `sigma_rule_result` integration_observations row for
                    EVERY loaded rule, every pass — evaluable or not,
                    matched or not — and an integration_alerts row only
                    for rules with genuine matches.

Secure's own native detection (osquery crosscheck, YARA-X, FIM,
persistence, etc.) is unaffected — Sigma here is one more evidence
source feeding the same integration_alerts table Phase 15 established,
subject to the same correlation and explanation machinery.
"""

from secure.integrations.sigma.analysis import (
    DEFAULT_SEVERITY,
    HIGH,
    LOW,
    MEDIUM,
    classify_sigma_match_severity,
)
from secure.integrations.sigma.availability import check_availability
from secure.integrations.sigma.capability import (
    CATEGORY_NETWORK_CONNECTION,
    CATEGORY_PROCESS_CREATION,
    SUPPORTED_CATEGORIES,
    CapabilityResult,
    CategorySupport,
    EvaluationStatus,
    check_capability,
)
from secure.integrations.sigma.rules import (
    RuleLoadError,
    SigmaRule,
    discover_rule_files,
    load_rules,
)
from secure.integrations.sigma.scanner import (
    INTEGRATION_NAME,
    SigmaRuleOutcome,
    SigmaScanResult,
    scan_sigma,
)

__all__ = [
    "DEFAULT_SEVERITY",
    "HIGH",
    "LOW",
    "MEDIUM",
    "classify_sigma_match_severity",
    "check_availability",
    "CATEGORY_NETWORK_CONNECTION",
    "CATEGORY_PROCESS_CREATION",
    "SUPPORTED_CATEGORIES",
    "CapabilityResult",
    "CategorySupport",
    "EvaluationStatus",
    "check_capability",
    "RuleLoadError",
    "SigmaRule",
    "discover_rule_files",
    "load_rules",
    "INTEGRATION_NAME",
    "SigmaRuleOutcome",
    "SigmaScanResult",
    "scan_sigma",
]
