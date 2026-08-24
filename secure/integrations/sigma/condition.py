"""
integrations/sigma/condition.py — the bounded Sigma condition engine:
tokenizer, recursive-descent parser, and evaluator for the specific
boolean grammar this integration supports, plus the field-value
matching logic used to turn one named "selection" block into a
true/false verdict against one telemetry event.

Deliberately NOT a general Sigma condition implementation. Supported
grammar only:

    <selection-name>
    not <expr>
    <expr> and <expr>
    <expr> or <expr>
    ( <expr> )
    1 of <selection-name-or-glob*>
    all of <selection-name-or-glob*>
    1 of them
    all of them

Explicitly NOT supported (a rule needing these was never made
EVALUABLE by capability.py in the first place, since such rules use
detection shapes capability.py doesn't recognize as safely
interpretable): Sigma's newer aggregation/correlation syntax
(`| count() by X > N`), near/temporal correlation across rules, and
multi-logsource backreferences.

Field-value modifiers supported (single modifier per field key only —
chained modifiers like `Field|contains|all` are rejected upstream by
capability.py, which only strips one trailing `|modifier` suffix, so a
double-piped field name never matches anything in a category's
field_map and the rule is reported NOT_EVALUABLE rather than
partially, silently interpreted): none (plain value, itself allowed to
contain Sigma's own `*`/`?` wildcards, case-insensitive — Sigma's own
default), `contains`, `startswith`, `endswith`, `re` (regex, also
case-insensitive), and `all` (AND instead of the default OR across a
field's list of values).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Dict, List, Union


class ConditionError(ValueError):
    """Raised for anything this module can't safely interpret — a
    malformed condition string, an unknown selection reference, an
    unsupported selection shape, or an unsupported field modifier.
    Callers (evaluator.py) treat this the same way a NOT_EVALUABLE
    capability result is treated: never silently reported as CLEAN.
    """


# ---------- AST ----------


@dataclass(frozen=True)
class Ref:
    name: str


@dataclass(frozen=True)
class Not_:
    expr: object


@dataclass(frozen=True)
class And_:
    left: object
    right: object


@dataclass(frozen=True)
class Or_:
    left: object
    right: object


@dataclass(frozen=True)
class Quantifier:
    quant: str  # "1" or "all"
    target: str  # exact selection name, a "prefix*" glob, or "them"


ConditionNode = Union[Ref, Not_, And_, Or_, Quantifier]


# ---------- tokenizer ----------

_TOKEN_RE = re.compile(
    r"""
    (?P<LPAREN>\()
    |(?P<RPAREN>\))
    |(?P<AND>\band\b)
    |(?P<OR>\bor\b)
    |(?P<NOT>\bnot\b)
    |(?P<ALL>\ball\b)
    |(?P<OF>\bof\b)
    |(?P<THEM>\bthem\b)
    |(?P<NUMBER>\b1\b)
    |(?P<IDENT>[A-Za-z_][A-Za-z0-9_*]*)
    |(?P<WS>\s+)
    """,
    re.VERBOSE,
)


def _tokenize(text: str) -> List[tuple]:
    tokens = []
    pos = 0
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if not match:
            raise ConditionError(f"unexpected character at position {pos}: {text[pos]!r}")
        kind = match.lastgroup
        value = match.group()
        if kind != "WS":
            tokens.append((kind, value))
        pos = match.end()
    tokens.append(("EOF", ""))
    return tokens


# ---------- parser ----------


class _Parser:
    def __init__(self, tokens: List[tuple]):
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> tuple:
        return self._tokens[self._pos]

    def _advance(self) -> tuple:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _expect(self, kind: str) -> tuple:
        tok = self._advance()
        if tok[0] != kind:
            raise ConditionError(f"expected {kind}, got {tok[0]} ({tok[1]!r})")
        return tok

    def parse(self) -> ConditionNode:
        node = self._parse_or()
        self._expect("EOF")
        return node

    def _parse_or(self) -> ConditionNode:
        node = self._parse_and()
        while self._peek()[0] == "OR":
            self._advance()
            node = Or_(node, self._parse_and())
        return node

    def _parse_and(self) -> ConditionNode:
        node = self._parse_not()
        while self._peek()[0] == "AND":
            self._advance()
            node = And_(node, self._parse_not())
        return node

    def _parse_not(self) -> ConditionNode:
        if self._peek()[0] == "NOT":
            self._advance()
            return Not_(self._parse_not())
        return self._parse_atom()

    def _parse_atom(self) -> ConditionNode:
        kind, value = self._peek()
        if kind == "LPAREN":
            self._advance()
            node = self._parse_or()
            self._expect("RPAREN")
            return node
        if kind in ("NUMBER", "ALL"):
            return self._parse_quantifier()
        if kind == "IDENT":
            self._advance()
            return Ref(value)
        raise ConditionError(f"unexpected token {kind} ({value!r})")

    def _parse_quantifier(self) -> Quantifier:
        kind, _value = self._advance()
        quant = "1" if kind == "NUMBER" else "all"
        self._expect("OF")
        tkind, tvalue = self._advance()
        if tkind == "THEM":
            target = "them"
        elif tkind == "IDENT":
            target = tvalue
        else:
            raise ConditionError(f"expected a selection name or 'them' after 'of', got {tkind}")
        return Quantifier(quant, target)


def parse_condition(text: str) -> ConditionNode:
    """Parse one Sigma `detection.condition` string into an AST. Raises
    ConditionError on anything outside this module's supported grammar.
    """
    if not isinstance(text, str) or not text.strip():
        raise ConditionError("condition must be a non-empty string")
    parser = _Parser(_tokenize(text))
    return parser.parse()


# ---------- boolean evaluation ----------


def evaluate_condition(node: ConditionNode, selection_results: Dict[str, bool]) -> bool:
    """Evaluate a parsed condition AST against a dict of already-computed
    per-selection true/false results (selection name -> matched this
    event). Raises ConditionError if the condition references a
    selection name that doesn't exist in the rule's detection block —
    a rule shape capability.py should never have let through as
    EVALUABLE, so this is a defensive backstop, not the primary check.
    """
    if isinstance(node, Ref):
        if node.name not in selection_results:
            raise ConditionError(f"condition references unknown selection {node.name!r}")
        return selection_results[node.name]
    if isinstance(node, Not_):
        return not evaluate_condition(node.expr, selection_results)
    if isinstance(node, And_):
        return evaluate_condition(node.left, selection_results) and evaluate_condition(
            node.right, selection_results
        )
    if isinstance(node, Or_):
        return evaluate_condition(node.left, selection_results) or evaluate_condition(
            node.right, selection_results
        )
    if isinstance(node, Quantifier):
        if node.target == "them":
            names = list(selection_results.keys())
        elif "*" in node.target:
            names = [n for n in selection_results if fnmatch.fnmatchcase(n, node.target)]
        else:
            if node.target not in selection_results:
                raise ConditionError(f"condition references unknown selection {node.target!r}")
            names = [node.target]
        if not names:
            # A quantifier matching zero selections (e.g. a glob with no
            # matches) is false, never vacuously true — matches Sigma's
            # own documented behavior and avoids a spurious match.
            return False
        values = [selection_results[n] for n in names]
        return any(values) if node.quant == "1" else all(values)
    raise ConditionError(f"unknown condition node: {node!r}")


# ---------- field-value matching ----------

_FIELD_MODIFIER_RE = re.compile(r"^(?P<field>.+?)\|(?P<modifier>[A-Za-z0-9_]+)$")
_SUPPORTED_MODIFIERS = frozenset({"contains", "startswith", "endswith", "re", "all"})


def split_field_modifier(raw_key: str) -> "tuple[str, str | None]":
    match = _FIELD_MODIFIER_RE.match(raw_key)
    if not match:
        return raw_key, None
    return match.group("field"), match.group("modifier")


def _wildcard_regex(pattern: str) -> "re.Pattern[str]":
    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(f"^{escaped}$", re.IGNORECASE | re.DOTALL)


def _single_value_matches(actual: str, spec: str, modifier: "str | None") -> bool:
    if modifier == "re":
        return re.search(spec, actual, re.IGNORECASE) is not None
    if modifier == "contains":
        pattern = f"*{spec}*"
    elif modifier == "startswith":
        pattern = f"{spec}*"
    elif modifier == "endswith":
        pattern = f"*{spec}"
    else:
        # No modifier (or "all", handled by the caller): plain value,
        # itself allowed to carry Sigma's own literal *? wildcards.
        pattern = spec
    return _wildcard_regex(pattern).match(actual) is not None


def match_field_values(actual_value, spec_value, modifier: "str | None") -> bool:
    """One field's match verdict. `spec_value` may be a single scalar or
    a list (Sigma's own "OR across a value list" shorthand, or, with
    the `|all` modifier, an AND). Comparison is always
    string/case-insensitive, matching Sigma's own default.
    """
    values = spec_value if isinstance(spec_value, list) else [spec_value]
    str_values = [str(v) for v in values]
    actual_str = "" if actual_value is None else str(actual_value)

    if modifier is not None and modifier not in _SUPPORTED_MODIFIERS:
        raise ConditionError(f"unsupported field modifier: {modifier!r}")

    if modifier == "all":
        return all(_single_value_matches(actual_str, v, None) for v in str_values)
    return any(_single_value_matches(actual_str, v, modifier) for v in str_values)


def match_selection(selection, event: dict, field_map: Dict[str, str]) -> bool:
    """Evaluate one named selection block (the value side of one key in
    a rule's `detection` mapping) against one telemetry event dict.

    Supported shapes: a mapping of field->value(s) (all fields must
    match — AND), or a list of such mappings (Sigma's "list of maps"
    shorthand — any one mapping matching is enough — OR). A list
    containing bare scalars (Sigma's plain "keywords" form) is not
    supported and raises ConditionError — capability.py's own field
    scan already treats such entries as contributing no recognizable
    field, so a rule built entirely from one is never reported
    EVALUABLE in the first place; this is a defensive backstop for a
    selection that mixes forms.
    """
    if isinstance(selection, dict):
        return _match_selection_mapping(selection, event, field_map)
    if isinstance(selection, list):
        if not selection:
            return False
        return any(_match_selection_list_item(item, event, field_map) for item in selection)
    raise ConditionError(
        "unsupported selection shape (only a field mapping, or a list of field "
        "mappings, is supported — plain keyword lists are not)"
    )


def _match_selection_list_item(item, event: dict, field_map: Dict[str, str]) -> bool:
    if not isinstance(item, dict):
        raise ConditionError(
            "unsupported selection list item (plain keyword lists are not supported)"
        )
    return _match_selection_mapping(item, event, field_map)


def _match_selection_mapping(mapping: dict, event: dict, field_map: Dict[str, str]) -> bool:
    for raw_key, spec_value in mapping.items():
        base_field, modifier = split_field_modifier(raw_key)
        secure_field = field_map.get(base_field)
        if secure_field is None:
            # Should already have been rejected by capability.py — a
            # rule that gets here with an unmapped field is treated as
            # a non-match for this selection rather than a crash.
            raise ConditionError(
                f"field {base_field!r} has no telemetry mapping for this category"
            )
        actual = event.get(secure_field)
        if not match_field_values(actual, spec_value, modifier):
            return False
    return True
