"""
integrations/sigma/capability.py — the adapter Phase 17 asks for:
"Design an adapter that determines whether a Sigma rule can be
evaluated using telemetry Secure actually possesses."

This is the mechanism that enforces the phase's one non-negotiable
rule — "If required telemetry is unavailable, report NOT EVALUABLE —
never CLEAN" — structurally, not just by convention: check_capability()
runs BEFORE evaluator.py ever queries an observation or evaluates a
condition. If this function says NOT_EVALUABLE, evaluator.py never
gets the chance to produce a false "no match" for a rule Secure never
actually had the telemetry to check.

Deliberately small, per the phase instruction ("start with a small
subset ... rather than attempting universal compatibility"): exactly
two Sigma logsource categories, each backed by ONE osquery observation
kind already collected by secure/integrations/osquery/, with a short,
explicit field map. Anything outside this — other categories, other
fields, Windows/Sysmon-only rules — is NOT_EVALUABLE, not silently
best-efforted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, List, Tuple

from secure.integrations.sigma.rules import SigmaRule

CATEGORY_PROCESS_CREATION = "process_creation"
CATEGORY_NETWORK_CONNECTION = "network_connection"

# Only macOS telemetry exists in this deployment. Many published Sigma
# rules declare `logsource.product: windows` (Sysmon-derived) and use
# field names — CommandLine, Image — that happen to overlap ours by
# coincidence, not compatibility. Without this check such a rule would
# wrongly look evaluable. `product` is optional in Sigma; when absent
# we don't reject on this basis alone (see check_capability below).
ALLOWED_PRODUCTS: FrozenSet[str] = frozenset({"macos"})

# A rule's `detection` block always has one `condition` key (a string,
# handled separately by condition.py) plus one or more "selection"
# entries — the rest of the mapping. This is the field-map lookup key
# used for "condition" so it never gets misread as a field name.
_CONDITION_KEY = "condition"

# A field reference in a Sigma selection may carry a `|modifier` suffix
# (e.g. "CommandLine|contains"). Only the base field name determines
# telemetry support; the modifier is condition.py's concern.
_FIELD_MODIFIER_RE = re.compile(r"\|[a-zA-Z0-9_]+$")


@dataclass(frozen=True)
class CategorySupport:
    """One supported Sigma logsource category and exactly how Secure
    backs it: which osquery observation kind supplies events, and the
    Sigma-field -> Secure-field translation available for it.
    """

    category: str
    integration: str  # which secure/integrations/* supplies telemetry (always "osquery" in v1)
    observation_kind: str  # secure.integrations.osquery ExternalObservation.kind
    field_map: Dict[str, str]  # Sigma field name -> Secure/osquery event field name
    allowed_products: FrozenSet[str] = ALLOWED_PRODUCTS


SUPPORTED_CATEGORIES: Dict[str, CategorySupport] = {
    CATEGORY_PROCESS_CREATION: CategorySupport(
        category=CATEGORY_PROCESS_CREATION,
        integration="osquery",
        observation_kind="processes",
        # Deliberately NOT supported (documented gap, not an oversight):
        # ParentImage, User, ParentCommandLine, Hashes, IntegrityLevel —
        # osquery's `processes` table observations Secure collects don't
        # carry parent-process linkage, user context, or file hashes in
        # v1. A rule referencing any of those fields is NOT_EVALUABLE.
        field_map={
            "Image": "path",
            "CommandLine": "cmdline",
        },
    ),
    CATEGORY_NETWORK_CONNECTION: CategorySupport(
        category=CATEGORY_NETWORK_CONNECTION,
        integration="osquery",
        observation_kind="process_open_sockets",
        # `Image` here is a documented approximation: osquery's
        # process_open_sockets observations carry only a process NAME
        # (`process_name`), not a full executable path, unlike the real
        # Sysmon `Image` field this category is modeled on.
        field_map={
            "DestinationIp": "remote_address",
            "DestinationPort": "remote_port",
            "Protocol": "proto",
            "Image": "process_name",
        },
    ),
}


class EvaluationStatus(str, Enum):
    EVALUABLE = "evaluable"
    NOT_EVALUABLE = "not_evaluable"


@dataclass(frozen=True)
class CapabilityResult:
    """What check_capability() returns for one rule: whether Secure can
    actually evaluate it, plus the human-readable reason either way —
    satisfies Phase 17's "required telemetry" + "evaluation status"
    exposure requirements on their own, independent of whether the rule
    ever gets as far as evaluator.py.
    """

    status: EvaluationStatus
    category_support: "CategorySupport | None"
    required_telemetry: str
    reason: str

    @property
    def evaluable(self) -> bool:
        return self.status is EvaluationStatus.EVALUABLE


def _strip_modifier(field_name: str) -> str:
    return _FIELD_MODIFIER_RE.sub("", field_name)


def _referenced_fields(detection: dict) -> List[str]:
    """Every field name referenced anywhere in a rule's selection
    entries (everything in `detection` except the `condition` key).
    Selections may be a dict of field->value(s), or a list of such
    dicts/plain values (Sigma's own "list of maps means OR" shorthand);
    plain string/scalar list entries contribute no field name (they're
    the `keywords` form, unsupported here — see check_capability).
    """
    fields: List[str] = []
    for key, selection in detection.items():
        if key == _CONDITION_KEY:
            continue
        fields.extend(_fields_in_selection(selection))
    return fields


def _fields_in_selection(selection) -> List[str]:
    if isinstance(selection, dict):
        return [_strip_modifier(k) for k in selection.keys()]
    if isinstance(selection, list):
        fields: List[str] = []
        for item in selection:
            fields.extend(_fields_in_selection(item))
        return fields
    # A bare scalar/keyword-list entry (no field name at all) — v1
    # doesn't support Sigma's plain "keywords" detection form.
    return []


def _required_telemetry_label(category: str, fields: "List[str] | None" = None) -> str:
    if fields:
        return f"osquery:{category} fields={sorted(set(fields))}"
    return f"osquery:{category}"


def check_capability(rule: SigmaRule) -> CapabilityResult:
    """The core adapter decision. Three checks, in order, ANY of which
    failing means NOT_EVALUABLE:

      1. logsource.category is one of SUPPORTED_CATEGORIES.
      2. logsource.product, if declared, is in that category's
         allowed_products (undeclared product is not held against a
         rule — many real Sigma rules omit it).
      3. every field referenced anywhere in detection's selections
         (after stripping |modifier suffixes) is in that category's
         field_map.

    Never raises — a rule this function can't make sense of is itself
    just another NOT_EVALUABLE reason, never treated as CLEAN.
    """
    logsource = rule.logsource or {}
    category = logsource.get("category")

    if not category or category not in SUPPORTED_CATEGORIES:
        return CapabilityResult(
            status=EvaluationStatus.NOT_EVALUABLE,
            category_support=None,
            required_telemetry=_required_telemetry_label(str(category or "<none>")),
            reason=(
                f"logsource.category={category!r} is not one of Secure's supported "
                f"categories ({sorted(SUPPORTED_CATEGORIES)})"
            ),
        )

    support = SUPPORTED_CATEGORIES[category]

    product = logsource.get("product")
    if product and str(product).lower() not in support.allowed_products:
        return CapabilityResult(
            status=EvaluationStatus.NOT_EVALUABLE,
            category_support=support,
            required_telemetry=_required_telemetry_label(category),
            reason=(
                f"logsource.product={product!r} is not telemetry Secure collects "
                f"(supported products: {sorted(support.allowed_products)})"
            ),
        )

    referenced = _referenced_fields(rule.detection)
    unsupported = sorted({f for f in referenced if f not in support.field_map})
    if unsupported:
        return CapabilityResult(
            status=EvaluationStatus.NOT_EVALUABLE,
            category_support=support,
            required_telemetry=_required_telemetry_label(category, referenced),
            reason=(
                f"references field(s) {unsupported} Secure has no telemetry for in "
                f"category {category!r} (supported: {sorted(support.field_map)})"
            ),
        )

    return CapabilityResult(
        status=EvaluationStatus.EVALUABLE,
        category_support=support,
        required_telemetry=_required_telemetry_label(category, referenced),
        reason=f"category {category!r} and all referenced fields are supported",
    )
