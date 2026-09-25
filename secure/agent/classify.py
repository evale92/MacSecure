"""
secure/agent/classify.py — Phase 39 (Part 2: Supervised Agentic
Development & Self-Healing — "Change Classification").

Classifies a proposed change BEFORE promotion, deterministically, into
one of five classes. Governing text, verbatim

    "Classification must be deterministic where possible. When
    uncertain, choose the more restrictive class. Do not let model
    confidence downgrade the required approval level."

    "ACCEPTANCE: Tests prove consequential changes cannot be classified
    into automatic execution merely because an LLM describes them as
    safe. Unknown/ambiguous cases fail toward the more restrictive
    classification."

WHY THIS MODULE HAS NO MODEL CALL IN IT AT ALL

The obvious way to build this would be to ask a model "is this change
consequential?" That is precisely what the acceptance criterion
forbids, so every classification here is computed from the changed file
paths and the ADDED lines of the diff by fixed rules. A model's opinion
is accepted only through `apply_model_opinion()`, which can RAISE the
class and can never lower it — the same one-directional trust rule
Phase 38's reviewer follows (it can restrict, never permit).

WHY THE ADDED LINES, NOT THE WHOLE DIFF

A diff that REMOVES a `sudo` call is not a privileged change; it is a
change that deletes one. Scanning the whole diff text would classify
both directions identically and would eventually train an operator to
ignore the classification. Only `+` lines are scanned for
consequential signals, with one deliberate exception noted at
`_DESTRUCTIVE_PATTERNS`.

RELATIONSHIP TO THE PATH DENYLIST

`AppConfig.agent_path_denylist` (Phase 31) BLOCKS an agent edit
outright — a repair touching those paths never becomes a change
request at all. This module does something different and broader: it
labels the approval level a change requires, for changes from any
source, including Phase 46's dependency/tool maintenance proposals that
no agent authored. The two overlap but neither replaces the other.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------
# The five classes, and their restrictiveness order
# ---------------------------------------------------------------------

CLASS_SAFE_PROJECT_CODE = "SAFE_PROJECT_CODE"
CLASS_DEPENDENCY_CHANGE = "DEPENDENCY_CHANGE"
CLASS_SECURITY_SEMANTIC_CHANGE = "SECURITY_SEMANTIC_CHANGE"
CLASS_SYSTEM_CHANGE = "SYSTEM_CHANGE"
CLASS_PRIVILEGED_CHANGE = "PRIVILEGED_CHANGE"

ALL_CLASSES = (
    CLASS_SAFE_PROJECT_CODE,
    CLASS_DEPENDENCY_CHANGE,
    CLASS_SECURITY_SEMANTIC_CHANGE,
    CLASS_SYSTEM_CHANGE,
    CLASS_PRIVILEGED_CHANGE,
)

# Higher number = more restrictive. Used by `more_restrictive()` so
# "when uncertain, choose the more restrictive class" is a single
# comparison rather than a pile of if-statements that could each drift.
# The ordering follows the governing text's own listing, with the two
# host-level classes above the two project-level ones: a change that
# touches the machine outranks a change that touches this repository,
# and a privileged (credential/root) change outranks an ordinary system
# one.
RESTRICTIVENESS = {
    CLASS_SAFE_PROJECT_CODE: 0,
    CLASS_DEPENDENCY_CHANGE: 1,
    CLASS_SECURITY_SEMANTIC_CHANGE: 2,
    CLASS_SYSTEM_CHANGE: 3,
    CLASS_PRIVILEGED_CHANGE: 4,
}

# The one class that does not require human approval. Everything else
# does. Deliberately expressed as "everything except one" rather than a
# list of four, so a class added later is approval-gated by default
# instead of silently automatic.
AUTOMATIC_CLASSES = (CLASS_SAFE_PROJECT_CODE,)

# The class assigned when scope cannot be determined. Not the maximum —
# "more restrictive," not "most restrictive." SYSTEM_CHANGE is solidly
# approval-gated, which is what the rule is actually protecting; making
# every unknown PRIVILEGED would flatten the vocabulary and make the
# most serious label meaningless.
UNKNOWN_SCOPE_CLASS = CLASS_SYSTEM_CHANGE


def more_restrictive(a: str, b: str) -> str:
    return a if RESTRICTIVENESS.get(a, 0) >= RESTRICTIVENESS.get(b, 0) else b


def requires_human_approval(classification: str) -> bool:
    """An unrecognized class is approval-gated, not automatic."""
    return classification not in AUTOMATIC_CLASSES


# ---------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------

# Files whose very identity makes a change dependency-related.
_DEPENDENCY_FILES = (
    "requirements.txt", "requirements-dev.txt", "pyproject.toml",
    "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock", "poetry.lock",
    "package.json", "package-lock.json", "Brewfile",
)

# Paths whose contents decide security outcomes, or decide whether a
# change is allowed to land. Editing any of them changes what "secure"
# or "approved" MEANS, which is a different thing from an ordinary bug
# fix in a sensor.
_SECURITY_SEMANTIC_PREFIXES = (
    "secure/validate/",
    "secure/detect/",
    "secure/correlate/",
    "secure/evidence/",
    "secure/explain/",
    "secure/ai/verify/",
    "secure/ai/changes/",
    "secure/agent/",
    "secure/permissions.py",
    "secure/config.py",
    "secure/storage/database.py",
    "SECURITY_INVARIANTS.md",
    "ARCHITECTURE_RULES.md",
    "AGENTS.md",
    "TESTING_POLICY.md",
)

# Added-line patterns. Each is anchored to an invocation-ish shape
# rather than a bare word, for the same reason Phase 29's
# no-launchctl test uses an argv-shaped regex: several modules'
# docstrings discuss `launchctl` and `sudo` in prose precisely to
# explain that this app does NOT do those things, and a plain
# substring check would misfire on the explanation.
_ARGVISH = r"""["']{token}["']"""


def _argv_pattern(token: str) -> "re.Pattern[str]":
    return re.compile(_ARGVISH.format(token=re.escape(token)))


# NOTE ON HOW THESE TOKEN LISTS ARE WRITTEN. They are built by
# splitting a plain space-separated string rather than written as
# tuple-of-string-literals. That is not a style preference. Phase 29's
# test_never_registers_itself_as_a_persistent_os_service statically
# scans every file under secure/ for a quoted service-management tool
# name appearing immediately inside an opening bracket or parenthesis —
# the shape a real subprocess argv takes — because no module in this
# app may ever invoke one. A tuple of quoted literals here would match
# that shape exactly and trip the check, correctly: the check cannot
# tell "invokes it" from "merely names it." Rather than weaken a real
# invariant's test to accommodate a lookup table, the table is written
# in a form that is unambiguously data. For the same reason this
# comment describes the shape in words instead of showing it.
_PRIVILEGED_TOKENS = tuple("sudo security chown chmod dscl csrutil spctl".split())
_PRIVILEGED_EXTRA = (
    re.compile(r"\bos\.set(e?[ug]id|groups)\s*\("),
    re.compile(r"\bkeychain\b", re.IGNORECASE),
    re.compile(r"/etc/sudoers"),
)

_SYSTEM_TOKENS = tuple(
    "launchctl networksetup systemsetup pfctl socketfilterfw "
    "blueutil wdutil airport scutil nvram defaults".split()
)
_SYSTEM_EXTRA = (
    re.compile(r"LaunchAgents|LaunchDaemons"),
    re.compile(r"\.plist['\"]?\s*\)?\s*$", re.MULTILINE),
)

# Destructive data/schema operations. This is the deliberate exception
# to "added lines only": a DROP TABLE that appears anywhere in the diff
# is worth a human's attention regardless of which side of the diff it
# landed on, because the cost of being wrong is unrecoverable and the
# cost of being over-cautious is one extra approval click.
_DESTRUCTIVE_PATTERNS = (
    re.compile(r"\bDROP\s+(TABLE|INDEX|COLUMN)\b", re.IGNORECASE),
    re.compile(r"\bTRUNCATE\b", re.IGNORECASE),
    re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE),
    re.compile(r"\brm\s+-rf\b"),
    re.compile(r"\bshutil\.rmtree\s*\("),
)

_INSTALL_PATTERNS = (
    re.compile(r"\bpip3?\s+(install|uninstall)\b"),
    re.compile(r"\bbrew\s+(install|uninstall|upgrade)\b"),
    re.compile(r"\bnpm\s+(install|uninstall)\b"),
    re.compile(r"\bapt(-get)?\s+(install|remove)\b"),
    re.compile(r"--break-system-packages"),
)


@dataclass(frozen=True)
class Classification:
    """The classification plus every signal that produced it — so a
    human reading a change request can see WHY it was labelled this
    way, and so a wrong rule is findable rather than mysterious."""

    classification: str
    reasons: "tuple[str, ...]" = field(default_factory=tuple)
    deterministic: bool = True
    model_suggested: "Optional[str]" = None
    model_suggestion_ignored: bool = False

    @property
    def requires_approval(self) -> bool:
        return requires_human_approval(self.classification)

    def describe(self) -> str:
        lines = [f"Classification: {self.classification} "
                 f"({'requires human approval' if self.requires_approval else 'automatic promotion permitted by class'})"]
        for reason in self.reasons:
            lines.append(f"  - {reason}")
        if self.model_suggested is not None:
            lines.append(
                f"  - a model suggested {self.model_suggested}; "
                + ("IGNORED (a model may never lower the required approval level)"
                   if self.model_suggestion_ignored else "accepted (it raised, not lowered, the class)")
            )
        return "\n".join(lines)


def _added_lines(diff_text: str) -> str:
    return "\n".join(
        line[1:]
        for line in diff_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )


def _normalize(path: str) -> str:
    return path.replace("\\", "/").strip()


def _is_understandable_path(path: str) -> bool:
    """A path Secure can reason about: repo-relative, no traversal, no
    absolute path. Anything else is ambiguous by definition and must
    not be silently treated as ordinary project code."""
    p = _normalize(path)
    if not p:
        return False
    if p.startswith("/") or p.startswith("~"):
        return False
    if ".." in p.split("/"):
        return False
    return True


def classify_change(
    changed_files: "list[str]", diff_text: str = "", *, model_suggested: "Optional[str]" = None
) -> Classification:
    """Deterministic classification. `model_suggested` is recorded and
    may only RAISE the result — see apply_model_opinion()."""
    reasons: "list[str]" = []
    result = CLASS_SAFE_PROJECT_CODE

    files = [_normalize(f) for f in changed_files]

    if not files:
        return apply_model_opinion(
            Classification(
                classification=UNKNOWN_SCOPE_CLASS,
                reasons=("scope is unknown (no changed files were determined) — classified toward "
                         "the more restrictive class rather than assumed safe",),
            ),
            model_suggested,
        )

    unreadable = [f for f in files if not _is_understandable_path(f)]
    if unreadable:
        result = more_restrictive(result, UNKNOWN_SCOPE_CLASS)
        reasons.append(
            f"path(s) outside this repository or otherwise not interpretable: {', '.join(sorted(unreadable))}"
        )

    for f in files:
        name = f.rsplit("/", 1)[-1]
        if name in _DEPENDENCY_FILES:
            result = more_restrictive(result, CLASS_DEPENDENCY_CHANGE)
            reasons.append(f"{f} declares this project's dependencies")

    for f in files:
        for prefix in _SECURITY_SEMANTIC_PREFIXES:
            if f == prefix or f.startswith(prefix):
                result = more_restrictive(result, CLASS_SECURITY_SEMANTIC_CHANGE)
                reasons.append(f"{f} decides security outcomes or whether a change may land")
                break

    added = _added_lines(diff_text)

    for pattern in _INSTALL_PATTERNS:
        if pattern.search(added):
            result = more_restrictive(result, CLASS_DEPENDENCY_CHANGE)
            reasons.append(f"an added line performs a package install/removal ({pattern.pattern})")
            break

    for token in _SYSTEM_TOKENS:
        if _argv_pattern(token).search(added):
            result = more_restrictive(result, CLASS_SYSTEM_CHANGE)
            reasons.append(f"an added line invokes {token!r}, which changes host configuration")
    for pattern in _SYSTEM_EXTRA:
        if pattern.search(added):
            result = more_restrictive(result, CLASS_SYSTEM_CHANGE)
            reasons.append(f"an added line touches OS service configuration ({pattern.pattern})")
            break

    for pattern in _DESTRUCTIVE_PATTERNS:
        if pattern.search(diff_text):
            result = more_restrictive(result, CLASS_SYSTEM_CHANGE)
            reasons.append(
                f"the diff contains a destructive data/schema operation ({pattern.pattern}) — "
                "reverting a diff does not restore deleted data"
            )
            break

    for token in _PRIVILEGED_TOKENS:
        if _argv_pattern(token).search(added):
            result = more_restrictive(result, CLASS_PRIVILEGED_CHANGE)
            reasons.append(f"an added line invokes {token!r}, which requires elevated privilege or touches credentials")
    for pattern in _PRIVILEGED_EXTRA:
        if pattern.search(added):
            result = more_restrictive(result, CLASS_PRIVILEGED_CHANGE)
            reasons.append(f"an added line performs a privileged operation ({pattern.pattern})")
            break

    if not reasons:
        reasons.append("only ordinary project files changed, and no consequential operation appears in the added lines")

    return apply_model_opinion(
        Classification(classification=result, reasons=tuple(reasons)), model_suggested
    )


def apply_model_opinion(base: Classification, model_suggested: "Optional[str]") -> Classification:
    """A model may RAISE a classification and may never lower it.

    This is the whole of the model's influence on approval level, and it
    is deliberately one-directional: raising costs a human one extra
    review, while lowering would let a confident sentence turn a system
    change into an automatic one. A suggestion that is not a recognized
    class is ignored outright rather than guessed at.
    """
    if model_suggested is None:
        return base
    if model_suggested not in ALL_CLASSES:
        return Classification(
            classification=base.classification, reasons=base.reasons, deterministic=base.deterministic,
            model_suggested=model_suggested, model_suggestion_ignored=True,
        )
    raised = more_restrictive(base.classification, model_suggested)
    # The suggestion was ignored exactly when it did not change the
    # outcome AND differed from it — i.e. the model proposed something
    # LESS restrictive and was overruled. A suggestion that matched, or
    # that raised the class, was not ignored.
    ignored = raised == base.classification and model_suggested != base.classification
    return Classification(
        classification=raised,
        reasons=base.reasons,
        # Still purely deterministic only if the model changed nothing.
        deterministic=base.deterministic and raised == base.classification,
        model_suggested=model_suggested,
        model_suggestion_ignored=ignored,
    )
