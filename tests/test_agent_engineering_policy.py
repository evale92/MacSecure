"""tests/test_agent_engineering_policy.py — Phase 37 ("Engineering
Policy", Part 2: Supervised Agentic Development & Self-Healing).

Phase 33 built `secure/agent/context.py`'s `policy_excerpts` hook and
proved it works against synthetic fixture repositories in `tmp_path`.
It could not prove the hook actually lights up for THIS repository,
because none of the four policy files existed yet — `_load_policy_excerpts()`
honestly returned `{}`.

These tests close that gap against the LIVE checkout rather than a
fixture: the four files really exist at `project_root()`, a real
`RepairContext` built from them really carries all four, and the
rendered prompt block really contains them. They also enforce the one
structural convention the files themselves depend on — every numbered
rule is front-loaded ahead of the `---` marker so that
`_MAX_POLICY_CHARS_PER_FILE` truncation can never cut a normative rule
out of a repair prompt. That convention is prose in the files; here it
is a test, per TESTING_POLICY.md rule 8.
"""

from __future__ import annotations

import re
from pathlib import Path

from secure.agent.context import (
    _MAX_POLICY_CHARS_PER_FILE,
    _POLICY_FILENAMES,
    build_repair_context,
    render_context_block,
)
from secure.agent.policy import TRIGGER_PYTEST_FAILURE, RepairCandidate
from secure.agent.worktree import project_root

# Matches a top-level numbered rule line, e.g. "3. **Never weaken a
# test to make it pass.**" — deliberately anchored to the exact shape
# every policy file uses, so a rule that is reformatted out of that
# shape is caught rather than silently uncounted.
_RULE_RE = re.compile(r"^(\d+)\. \*\*", re.MULTILINE)

# The separator each policy file places after its complete normative
# section. Everything before it must fit the excerpt budget; everything
# after it is human-facing elaboration that may be truncated.
_NORMATIVE_MARKER = "\n---\n"

_EXPECTED_POLICY_FILES = ("AGENTS.md", "ARCHITECTURE_RULES.md", "SECURITY_INVARIANTS.md", "TESTING_POLICY.md")


def _policy_path(name: str) -> Path:
    return project_root() / name


def _candidate() -> RepairCandidate:
    return RepairCandidate(
        TRIGGER_PYTEST_FAILURE,
        "tests/test_agent_engineering_policy.py::test_policy_files_exist_at_project_root",
        "boom",
    )


# ---------- the files themselves ----------


def test_policy_files_exist_at_project_root():
    missing = [name for name in _EXPECTED_POLICY_FILES if not _policy_path(name).is_file()]
    assert missing == []


def test_context_module_looks_for_exactly_these_four_filenames():
    """Guards against the files and the loader drifting apart: adding a
    fifth policy file without teaching `_POLICY_FILENAMES` about it
    would leave it silently absent from every repair prompt."""
    assert tuple(_POLICY_FILENAMES) == _EXPECTED_POLICY_FILES


def test_every_policy_file_has_a_normative_section_with_numbered_rules():
    for name in _EXPECTED_POLICY_FILES:
        text = _policy_path(name).read_text(encoding="utf-8")
        assert _NORMATIVE_MARKER in text, f"{name} has no '---' normative-section marker"
        head = text.split(_NORMATIVE_MARKER)[0]
        numbers = [int(n) for n in _RULE_RE.findall(head)]
        assert numbers, f"{name} has no numbered rules before the marker"
        assert numbers == list(range(1, len(numbers) + 1)), f"{name} rule numbering is not 1..n: {numbers}"


# ---------- the truncation guarantee ----------


def test_normative_section_of_every_policy_file_fits_the_excerpt_budget():
    """The whole point of front-loading: `_load_policy_excerpts()` keeps
    only the first `_MAX_POLICY_CHARS_PER_FILE` characters, so the
    complete rule set has to live inside that budget."""
    for name in _EXPECTED_POLICY_FILES:
        head = _policy_path(name).read_text(encoding="utf-8").split(_NORMATIVE_MARKER)[0]
        assert len(head) <= _MAX_POLICY_CHARS_PER_FILE, f"{name} normative section is {len(head)} chars"


def test_no_numbered_rule_is_lost_to_truncation_in_a_real_repair_context():
    """Behavioral, not arithmetic: builds the real context and compares
    the rule count in each excerpt actually handed to a coding agent
    against the rule count in the file on disk."""
    context = build_repair_context(_candidate(), root=project_root())
    for name in _EXPECTED_POLICY_FILES:
        on_disk = _policy_path(name).read_text(encoding="utf-8")
        expected = len(_RULE_RE.findall(on_disk.split(_NORMATIVE_MARKER)[0]))
        in_prompt = len(_RULE_RE.findall(context.policy_excerpts[name]))
        assert in_prompt == expected, f"{name}: {expected} rules on disk, {in_prompt} survived into the prompt"


# ---------- the wiring, against the live checkout ----------


def test_build_repair_context_against_live_root_includes_every_policy_file():
    context = build_repair_context(_candidate(), root=project_root())
    assert set(context.policy_excerpts) == set(_EXPECTED_POLICY_FILES)
    for name, text in context.policy_excerpts.items():
        assert text.strip(), f"{name} excerpt is empty"


def test_render_context_block_emits_the_policy_section_for_the_live_root():
    context = build_repair_context(_candidate(), root=project_root())
    rendered = render_context_block(context)
    assert "Engineering policy (must be followed):" in rendered
    for name in _EXPECTED_POLICY_FILES:
        assert f"--- {name} ---" in rendered


def test_rendered_prompt_carries_the_never_weaken_a_test_rule():
    """The single rule the repair loop's own soundness depends on — if
    it is ever silently dropped from the prompt, this fails."""
    rendered = render_context_block(build_repair_context(_candidate(), root=project_root()))
    assert "Never weaken a test to make it pass" in rendered


def test_policy_files_are_still_absent_for_an_unrelated_root(tmp_path: Path):
    """Phase 33's honest-absence behavior is unchanged: the loader reads
    whatever exists at the root it is given, and reports nothing for a
    root that has no policy files — it does not fall back to this
    repository's own."""
    context = build_repair_context(_candidate(), root=tmp_path)
    assert context.policy_excerpts == {}
