"""
integrations/sigma/rules.py — discovers and parses real Sigma rule
files (*.yml/*.yaml) from a configured directory, one rule per file
(the standard Sigma convention). No bundled rules ship with Secure —
same "bring your own detection content" stance
secure/integrations/yarax/rulesets.py already takes for YARA-X rulesets,
for the same reason: Secure owns the evaluation machinery, not a
maintained rule library.

A Sigma rule has no external "version" the way an installed package
does — same situation YARA-X rulesets are in — so "source/version"
provenance here means the exact file path plus a SHA-256 content
fingerprint (`SigmaRule.source_hash`/`version_label`), never a
fabricated version string. This is a direct, deliberate reuse of
`secure/integrations/yarax/rulesets.py`'s `RulesetInfo` pattern.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from secure.integrations.sigma._yaml import parse_yaml

RULE_FILE_SUFFIXES = (".yml", ".yaml")


@dataclass(frozen=True)
class SigmaRule:
    """One parsed Sigma rule, kept close to Sigma's own YAML shape
    (`logsource`/`detection` are the raw parsed dicts, untouched here —
    secure/integrations/sigma/capability.py and condition.py are what
    interpret them) plus Secure's own provenance fields.

    `sigma_status` is Sigma's OWN rule-maturity field (values like
    "experimental"/"test"/"stable") — deliberately NOT named `status`,
    to avoid any confusion with Secure's own per-scan EVALUATION status
    (not_evaluable/evaluated/error — see evaluator.py). The two are
    completely different axes that happen to share a name in Sigma's
    own spec.
    """

    rule_id: str
    title: str
    level: "Optional[str]"
    description: "Optional[str]"
    sigma_status: "Optional[str]"
    tags: Tuple[str, ...]
    logsource: dict
    detection: dict
    source_path: str
    source_hash: str

    @property
    def version_label(self) -> str:
        return f"{self.rule_id}@{self.source_hash[:12]}"


@dataclass(frozen=True)
class RuleLoadError:
    source_path: str
    detail: str


def discover_rule_files(rules_dir: Path) -> List[Path]:
    """Every *.yml/*.yaml file directly inside rules_dir, sorted for
    deterministic ordering. Missing directory -> empty list ("no rules
    configured yet" is normal, not an error). Non-recursive, same
    "avoid indiscriminate scanning" reasoning applied to rule discovery
    itself that yarax/rulesets.py's discover_ruleset_files() documents.
    """
    if not rules_dir.is_dir():
        return []
    return sorted(
        p for p in rules_dir.iterdir() if p.is_file() and p.suffix.lower() in RULE_FILE_SUFFIXES
    )


def _hash_source(source: bytes) -> str:
    return hashlib.sha256(source).hexdigest()


def _parse_one_rule(path: Path) -> SigmaRule:
    """Raises ValueError with a human-readable reason on anything
    malformed — bad YAML, wrong top-level shape, or a missing required
    field. Callers (load_rules()) turn that into a RuleLoadError for
    this one file without aborting the rest of the batch.
    """
    source_bytes = path.read_bytes()
    source_hash = _hash_source(source_bytes)

    try:
        source_text = source_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"not valid UTF-8: {exc}") from exc

    data = parse_yaml(source_text)
    if not isinstance(data, dict):
        raise ValueError("top-level YAML document is not a mapping")

    rule_id = data.get("id")
    title = data.get("title")
    if not rule_id or not isinstance(rule_id, str):
        raise ValueError("missing or non-string required field: id")
    if not title or not isinstance(title, str):
        raise ValueError("missing or non-string required field: title")

    logsource = data.get("logsource")
    if not isinstance(logsource, dict):
        raise ValueError("missing or non-mapping required field: logsource")

    detection = data.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise ValueError("missing detection block or detection.condition")

    tags = data.get("tags") or []
    if not isinstance(tags, list):
        tags = [str(tags)]

    return SigmaRule(
        rule_id=rule_id,
        title=title,
        level=data.get("level"),
        description=data.get("description"),
        sigma_status=data.get("status"),
        tags=tuple(str(t) for t in tags),
        logsource=logsource,
        detection=detection,
        source_path=str(path),
        source_hash=source_hash,
    )


def load_rules(rules_dir: Path) -> Tuple[List[SigmaRule], List[RuleLoadError]]:
    """Parse every rule file found in rules_dir. One file's malformed
    YAML or missing required field does not prevent the others from
    loading — recorded as a RuleLoadError instead, the same
    "one bad item is logged and skipped" discipline
    secure/integrations/yarax/rulesets.py's load_rulesets() (and, before
    it, secure/persistence/scanner.py's per-entry loops) already use.
    """
    rules: List[SigmaRule] = []
    errors: List[RuleLoadError] = []

    for path in discover_rule_files(rules_dir):
        try:
            rules.append(_parse_one_rule(path))
        except Exception as exc:  # noqa: BLE001 - a bad rule file must not abort the whole batch
            errors.append(RuleLoadError(source_path=str(path), detail=f"{type(exc).__name__}: {exc}"))

    return rules, errors
