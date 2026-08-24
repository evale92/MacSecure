"""
integrations/yarax/rulesets.py — discovers and compiles "configurable
rulesets": every `*.yar`/`*.yara` file in the user's configured rules
directory (`AppConfig.yara_rules_dir`, default `~/.secure/yara_rules/`
— see secure/config.py). No bundled/default rules ship with Secure —
per Phase 16's "configurable rulesets" instruction, this is deliberately
BYO: Secure supplies the scanning/provenance/severity-mapping machinery,
not a maintained detection-content library of its own (the same "Secure
owns *when and why* to scan, not the detection content itself" framing
the project's own roadmap uses for this phase).

A ruleset has no meaningful external version number the way an
installed package does (these are the user's own local files) — so
"ruleset/version provenance" here means a stable, verifiable content
fingerprint (SHA-256 of the exact source text) rather than a fabricated
version string. Two scans of an unchanged ruleset file produce the
identical hash; editing the file changes it, which is exactly the
"version" signal that matters for provenance.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from secure.integrations.yarax import _engine

RULE_FILE_SUFFIXES = (".yar", ".yara")


@dataclass(frozen=True)
class RulesetInfo:
    """One ruleset's identity/provenance, independent of whether it
    compiled successfully — used for both the success and failure case
    so a broken ruleset is still reportable (which file, which hash).
    """

    name: str  # file stem, e.g. "suspicious_strings" for suspicious_strings.yar
    source_path: str
    source_hash: str  # sha256 of the exact file bytes, hex

    @property
    def version_label(self) -> str:
        """Short, stable label for provenance strings — e.g.
        "suspicious_strings@a1b2c3d4e5f6" — never claims a real semver.
        """
        return f"{self.name}@{self.source_hash[:12]}"


@dataclass(frozen=True)
class CompiledRuleset:
    info: RulesetInfo
    rules: object  # yara_x Rules — opaque here, only _engine.scan_bytes() uses it


@dataclass(frozen=True)
class RulesetLoadError:
    info: RulesetInfo
    detail: str


def _hash_source(source: bytes) -> str:
    return hashlib.sha256(source).hexdigest()


def discover_ruleset_files(rules_dir: Path) -> List[Path]:
    """Every *.yar/*.yara file directly inside rules_dir, sorted for
    deterministic ordering. A missing directory yields an empty list —
    "no rulesets configured yet" is a normal, honest state, not an
    error (mirrors watch_paths/persistence's own "empty is fine"
    conventions elsewhere in this app). Deliberately NOT recursive —
    an explicit, flat ruleset directory is easier to reason about than
    a silently-expanding recursive walk, and keeps this in line with
    "avoid indiscriminate...scanning" applied to rule DISCOVERY too.
    """
    if not rules_dir.is_dir():
        return []
    return sorted(
        p for p in rules_dir.iterdir() if p.is_file() and p.suffix.lower() in RULE_FILE_SUFFIXES
    )


def load_rulesets(rules_dir: Path) -> Tuple[List[CompiledRuleset], List[RulesetLoadError]]:
    """Compile every ruleset file found in rules_dir. One file's syntax
    error does not prevent the others from loading — returned as a
    RulesetLoadError instead, the same "one bad item is logged and
    skipped, not allowed to abort the rest" discipline
    secure/persistence/scanner.py's per-process/per-entry loops use.
    """
    compiled: List[CompiledRuleset] = []
    errors: List[RulesetLoadError] = []

    for path in discover_ruleset_files(rules_dir):
        try:
            source_bytes = path.read_bytes()
        except OSError as exc:
            info = RulesetInfo(name=path.stem, source_path=str(path), source_hash="")
            errors.append(RulesetLoadError(info=info, detail=f"could not read file: {exc}"))
            continue

        info = RulesetInfo(
            name=path.stem, source_path=str(path), source_hash=_hash_source(source_bytes)
        )
        try:
            source_text = source_bytes.decode("utf-8")
            rules = _engine.compile_ruleset(source_text, origin=str(path))
        except Exception as exc:  # noqa: BLE001 - a bad ruleset must not abort the whole batch
            errors.append(RulesetLoadError(info=info, detail=f"{type(exc).__name__}: {exc}"))
            continue

        compiled.append(CompiledRuleset(info=info, rules=rules))

    return compiled, errors
