"""tests/test_agent_classify.py — Phase 39 ("Change Classification").

Acceptance criterion under test (verbatim, from

    "Tests prove consequential changes cannot be classified into
    automatic execution merely because an LLM describes them as safe.
    Unknown/ambiguous cases fail toward the more restrictive
    classification."

The two adversarial groups below map directly onto those two
sentences: "a model can never lower the class" and "ambiguity is never
SAFE_PROJECT_CODE."
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import secure.agent.orchestrator as orch_module
from secure.agent.classify import (
    ALL_CLASSES,
    AUTOMATIC_CLASSES,
    CLASS_DEPENDENCY_CHANGE,
    CLASS_PRIVILEGED_CHANGE,
    CLASS_SAFE_PROJECT_CODE,
    CLASS_SECURITY_SEMANTIC_CHANGE,
    CLASS_SYSTEM_CHANGE,
    RESTRICTIVENESS,
    Classification,
    apply_model_opinion,
    classify_change,
    more_restrictive,
    requires_human_approval,
)
from secure.agent.orchestrator import attempt_repair
from secure.agent.policy import TRIGGER_PYTEST_FAILURE, RepairCandidate
from secure.agent.verify import VerificationOutcome, VerifyResult
from secure.config import AppConfig, default_config
from secure.storage.database import Database
from secure.storage.models import find_ai_change_request


def _c(files, diff="") -> str:
    return classify_change(files, diff).classification


# =====================================================================
# The vocabulary itself
# =====================================================================


def test_all_five_governing_classes_exist():
    assert set(ALL_CLASSES) == {
        "SAFE_PROJECT_CODE", "DEPENDENCY_CHANGE", "SECURITY_SEMANTIC_CHANGE",
        "SYSTEM_CHANGE", "PRIVILEGED_CHANGE",
    }


def test_exactly_one_class_permits_automatic_promotion():
    assert AUTOMATIC_CLASSES == (CLASS_SAFE_PROJECT_CODE,)


def test_an_unrecognized_class_is_approval_gated_not_automatic():
    """A class added later must be gated by default rather than
    silently automatic."""
    assert requires_human_approval("SOME_FUTURE_CLASS") is True


def test_every_class_has_a_restrictiveness_rank():
    assert set(RESTRICTIVENESS) == set(ALL_CLASSES)


def test_more_restrictive_picks_the_higher_rank():
    assert more_restrictive(CLASS_SAFE_PROJECT_CODE, CLASS_SYSTEM_CHANGE) == CLASS_SYSTEM_CHANGE
    assert more_restrictive(CLASS_PRIVILEGED_CHANGE, CLASS_DEPENDENCY_CHANGE) == CLASS_PRIVILEGED_CHANGE


# =====================================================================
# Deterministic classification
# =====================================================================


def test_ordinary_project_code_is_safe():
    assert _c(["secure/widget.py"], "+    return 2\n-    return 1\n") == CLASS_SAFE_PROJECT_CODE


def test_ordinary_test_change_is_safe_project_code():
    """Phase 38's reviewer is what scrutinizes a test edit; the
    classifier's job is approval level, and an ordinary test change
    needs no more than the usual change request."""
    assert _c(["tests/test_widget.py"], "+assert True\n") == CLASS_SAFE_PROJECT_CODE


def test_requirements_file_is_a_dependency_change():
    assert _c(["requirements.txt"], "+requests==2.31.0\n") == CLASS_DEPENDENCY_CHANGE


def test_pyproject_is_a_dependency_change():
    assert _c(["pyproject.toml"], "+x = 1\n") == CLASS_DEPENDENCY_CHANGE


def test_an_added_pip_install_line_is_a_dependency_change():
    assert _c(["scripts/setup.py.txt"], '+os.system("pip install requests")\n') == CLASS_DEPENDENCY_CHANGE


def test_detection_logic_is_a_security_semantic_change():
    assert _c(["secure/detect/registry.py"], "+x = 1\n") == CLASS_SECURITY_SEMANTIC_CHANGE


def test_the_approval_machinery_is_a_security_semantic_change():
    assert _c(["secure/ai/changes/workflow.py"], "+x = 1\n") == CLASS_SECURITY_SEMANTIC_CHANGE


def test_editing_the_policy_files_themselves_is_a_security_semantic_change():
    """Changing what the rules SAY is not an ordinary code change."""
    assert _c(["SECURITY_INVARIANTS.md"], "+anything goes now\n") == CLASS_SECURITY_SEMANTIC_CHANGE


def test_launchctl_invocation_is_a_system_change():
    assert _c(["secure/widget.py"], '+    subprocess.run(["launchctl", "load", path])\n') == CLASS_SYSTEM_CHANGE


def test_firewall_invocation_is_a_system_change():
    assert _c(["secure/widget.py"], '+    subprocess.run(["socketfilterfw", "--setglobalstate", "off"])\n') == CLASS_SYSTEM_CHANGE


def test_network_configuration_is_a_system_change():
    assert _c(["secure/widget.py"], '+    subprocess.run(["networksetup", "-setairportpower", "en0", "off"])\n') == CLASS_SYSTEM_CHANGE


def test_destructive_schema_operation_is_a_system_change():
    assert _c(["secure/widget.py"], "+    conn.execute('DROP TABLE agent_actions')\n") == CLASS_SYSTEM_CHANGE


def test_recursive_delete_is_a_system_change():
    assert _c(["secure/widget.py"], "+    shutil.rmtree(target)\n") == CLASS_SYSTEM_CHANGE


def test_sudo_is_a_privileged_change():
    assert _c(["secure/widget.py"], '+    subprocess.run(["sudo", "chmod", "777", p])\n') == CLASS_PRIVILEGED_CHANGE


def test_keychain_access_is_a_privileged_change():
    assert _c(["secure/widget.py"], '+    subprocess.run(["security", "find-generic-password"])\n') == CLASS_PRIVILEGED_CHANGE


def test_setuid_is_a_privileged_change():
    assert _c(["secure/widget.py"], "+    os.setuid(0)\n") == CLASS_PRIVILEGED_CHANGE


def test_the_most_restrictive_signal_wins_when_several_apply():
    diff = (
        "+requests==2.0\n"
        '+subprocess.run(["launchctl", "load", p])\n'
        '+subprocess.run(["sudo", "rm", p])\n'
    )
    assert _c(["requirements.txt", "secure/detect/x.py"], diff) == CLASS_PRIVILEGED_CHANGE


# ---------- direction matters ----------


def test_removing_a_sudo_call_is_not_a_privileged_change():
    """A diff that DELETES a privileged call is not a privileged
    change; it is a change that removes one. Scanning the whole diff
    text would classify both directions identically and would train an
    operator to ignore the label."""
    assert _c(["secure/widget.py"], '-    subprocess.run(["sudo", "rm", p])\n') == CLASS_SAFE_PROJECT_CODE


def test_a_diff_header_line_is_not_mistaken_for_an_added_line():
    diff = "--- a/secure/widget.py\n+++ b/secure/widget.py\n+x = 1\n"
    assert _c(["secure/widget.py"], diff) == CLASS_SAFE_PROJECT_CODE


def test_prose_mentioning_sudo_in_a_removed_comment_does_not_escalate():
    assert _c(["secure/widget.py"], "-# this app never calls sudo\n") == CLASS_SAFE_PROJECT_CODE


# =====================================================================
# Ambiguity fails toward the more restrictive class
# =====================================================================


def test_unknown_scope_is_never_safe():
    result = classify_change([], "")
    assert result.classification != CLASS_SAFE_PROJECT_CODE
    assert result.requires_approval is True


def test_an_absolute_path_outside_the_repo_is_never_safe():
    assert _c(["/etc/hosts"], "+1.2.3.4 evil\n") != CLASS_SAFE_PROJECT_CODE


def test_a_traversal_path_is_never_safe():
    assert _c(["../../.ssh/authorized_keys"], "+ssh-rsa AAA\n") != CLASS_SAFE_PROJECT_CODE


def test_a_home_relative_path_is_never_safe():
    assert _c(["~/Library/LaunchAgents/x.plist"], "+<plist/>\n") != CLASS_SAFE_PROJECT_CODE


def test_ambiguous_scope_reasons_say_so_out_loud():
    result = classify_change([], "")
    assert any("unknown" in r.lower() for r in result.reasons)


# =====================================================================
# A model may never lower the required approval level
# =====================================================================


def test_a_model_calling_a_system_change_safe_does_not_make_it_safe():
    diff = '+    subprocess.run(["launchctl", "load", p])\n'
    result = classify_change(["secure/widget.py"], diff, model_suggested=CLASS_SAFE_PROJECT_CODE)
    assert result.classification == CLASS_SYSTEM_CHANGE
    assert result.requires_approval is True
    assert result.model_suggestion_ignored is True


def test_a_model_calling_a_privileged_change_a_dependency_change_does_not_downgrade_it():
    diff = '+    subprocess.run(["sudo", "rm", p])\n'
    result = classify_change(["secure/widget.py"], diff, model_suggested=CLASS_DEPENDENCY_CHANGE)
    assert result.classification == CLASS_PRIVILEGED_CHANGE
    assert result.model_suggestion_ignored is True


def test_a_model_may_raise_the_class():
    """The safe direction is permitted: extra caution costs one human
    review, whereas the other direction costs the whole guarantee."""
    result = classify_change(["secure/widget.py"], "+x = 1\n", model_suggested=CLASS_PRIVILEGED_CHANGE)
    assert result.classification == CLASS_PRIVILEGED_CHANGE
    assert result.model_suggestion_ignored is False
    assert result.deterministic is False  # honestly no longer purely deterministic


def test_a_model_suggesting_a_nonsense_class_is_ignored_entirely():
    result = classify_change(["secure/widget.py"], "+x = 1\n", model_suggested="TOTALLY_FINE_TRUST_ME")
    assert result.classification == CLASS_SAFE_PROJECT_CODE
    assert result.model_suggestion_ignored is True


def test_the_model_suggestion_is_recorded_even_when_overruled():
    diff = '+    subprocess.run(["sudo", "x"])\n'
    result = classify_change(["secure/widget.py"], diff, model_suggested=CLASS_SAFE_PROJECT_CODE)
    assert result.model_suggested == CLASS_SAFE_PROJECT_CODE
    assert "IGNORED" in result.describe()


def test_no_model_opinion_leaves_the_result_purely_deterministic():
    result = classify_change(["secure/widget.py"], "+x = 1\n")
    assert result.deterministic is True
    assert result.model_suggested is None


def test_apply_model_opinion_never_lowers_for_any_pair():
    """Exhaustive rather than illustrative: for every (deterministic,
    suggested) pair, the outcome is never less restrictive than the
    deterministic input."""
    for base_class in ALL_CLASSES:
        base = Classification(classification=base_class, reasons=())
        for suggested in ALL_CLASSES:
            out = apply_model_opinion(base, suggested)
            assert RESTRICTIVENESS[out.classification] >= RESTRICTIVENESS[base_class]


# =====================================================================
# Orchestrator integration
# =====================================================================


def _git(args, cwd):
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True)


def _init_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(["init", "-q"], root)
    _git(["config", "user.email", "t@t.com"], root)
    _git(["config", "user.name", "T"], root)
    (root / "secure").mkdir()
    (root / "secure" / "widget.py").write_text("def widget():\n    return 1\n")
    (root / "tests").mkdir()
    (root / "tests" / "test_widget.py").write_text("def test_widget():\n    assert True\n")
    _git(["add", "-A"], root)
    _git(["commit", "-q", "-m", "init"], root)
    return root


def _cfg(tmp_path: Path) -> AppConfig:
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    cfg.agent_verify_timeout_seconds = 30
    cfg.agent_timeout_seconds = 30
    return cfg


def _run(tmp_path, monkeypatch, *, target: str, content: str):
    repo = _init_repo(tmp_path)

    def fake_run_mini(cfg, worktree, candidate, *, audit_trail=None, context=None):
        from secure.agent.runner import MiniRunResult

        path = worktree.worktree_path / target
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return MiniRunResult(
            status="completed", returncode=0, exit_status="Submitted", submission="done",
            mini_version="fake", instance_cost=None, transcript_path=None, model_name="ollama/x",
            argv=["fake"], config_yaml="", transcript_hash=None,
        )

    monkeypatch.setattr(orch_module, "run_mini_swe_agent", fake_run_mini)
    monkeypatch.setattr(
        orch_module, "verify_worktree",
        lambda worktree, cfg_, **_kw: VerificationOutcome(VerifyResult("ok", True, "ok"), VerifyResult("ok", True, "ok")),
    )
    with Database(tmp_path / "secure.db") as db:
        cfg = _cfg(tmp_path)
        record = attempt_repair(db.conn, cfg, RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::t", "boom"),
                                repo_root=repo, providers={"ollama": None, "openai_compatible": None})
        cr = find_ai_change_request(db.conn, record.change_request_id) if record.change_request_id else None
        return record, cr


def test_an_ordinary_repair_is_classified_and_recorded(tmp_path: Path, monkeypatch):
    record, cr = _run(tmp_path, monkeypatch, target="secure/widget.py", content="def widget():\n    return 2\n")
    assert record.classification == CLASS_SAFE_PROJECT_CODE
    assert record.classification_reasons
    assert cr.classification == CLASS_SAFE_PROJECT_CODE


def test_a_consequential_repair_is_classified_consequential(tmp_path: Path, monkeypatch):
    record, cr = _run(
        tmp_path, monkeypatch, target="secure/widget.py",
        content='import subprocess\n\n\ndef widget():\n    subprocess.run(["launchctl", "load", "/x.plist"])\n',
    )
    assert record.classification == CLASS_SYSTEM_CHANGE
    assert cr.classification == CLASS_SYSTEM_CHANGE


def test_the_classification_is_bound_into_what_a_human_approves(tmp_path: Path, monkeypatch):
    """The class is embedded in `risks`, which Phase 28's
    compute_revision_hash() already covers — so approval is bound to
    the class the human was shown, with no change to the hash
    computation itself."""
    from secure.ai.changes.model import ProposedChangeContent, compute_revision_hash

    _record, cr = _run(
        tmp_path, monkeypatch, target="secure/widget.py",
        content='import subprocess\n\n\ndef widget():\n    subprocess.run(["launchctl", "load", "/x.plist"])\n',
    )
    assert CLASS_SYSTEM_CHANGE in cr.risks
    assert "requires human approval" in cr.risks

    # And the stored hash really is a hash of that text — so altering
    # the recorded class would invalidate the approval hash.
    recomputed = compute_revision_hash(ProposedChangeContent(
        title=cr.title, proposed_change=cr.proposed_change, reason=cr.reason,
        affected_component=cr.affected_component, risks=cr.risks,
    ))
    assert recomputed == cr.revision_hash

    tampered = compute_revision_hash(ProposedChangeContent(
        title=cr.title, proposed_change=cr.proposed_change, reason=cr.reason,
        affected_component=cr.affected_component,
        risks=cr.risks.replace(CLASS_SYSTEM_CHANGE, CLASS_SAFE_PROJECT_CODE),
    ))
    assert tampered != cr.revision_hash
