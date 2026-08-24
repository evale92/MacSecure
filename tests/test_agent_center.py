"""tests/test_agent_center.py — Phase 40 ("Change Request Center").

Acceptance criterion under test (verbatim, from
docs/ROADMAP_PART2_PHASES_38_47.md):

    "A consequential candidate can be reviewed end-to-end in Secure;
    approval is cryptographically/revision-bound to the reviewed
    content; changed content cannot inherit stale approval."

The GUI module itself (secure_gui/change_requests_view.py) imports
tkinter and so is never imported here — the same convention
tests/test_gui_components.py already documents. Its one piece of real
logic, `detail_text()`, is deliberately Tkinter-free, but importing the
module to reach it would pull tkinter in; so the equivalent field
coverage is asserted here against the ChangeRequestView the window
renders, and the module itself is syntax-checked by
tests/test_clean_install.py's existing static sweep.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import secure.agent.orchestrator as orch_module
from secure.agent.center import (
    AWAITING_APPROVAL_STATUSES,
    approval_integrity,
    build_change_request_view,
    list_pending_change_requests,
    read_diff,
    reviewer_report,
    rollback_strategy,
    tests_report,
)
from secure.agent.changes import STATUS_SUPERSEDED, invalidate_change_request_if_content_changed
from secure.agent.classify import CLASS_SAFE_PROJECT_CODE, CLASS_SYSTEM_CHANGE
from secure.agent.orchestrator import attempt_repair
from secure.agent.policy import TRIGGER_PYTEST_FAILURE, RepairCandidate
from secure.agent.verify import VerificationOutcome, VerifyResult
from secure.ai.changes.workflow import approve_change
from secure.config import AppConfig, default_config
from secure.storage.database import Database
from secure.storage.models import find_ai_change_request


# ---------- shared helpers ----------


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


_CONSEQUENTIAL = 'import subprocess\n\n\ndef widget():\n    subprocess.run(["launchctl", "load", "/x.plist"])\n'
_ORDINARY = "def widget():\n    return 2\n"


def _seed(tmp_path, monkeypatch, *, content: str = _ORDINARY):
    """Runs one real repair through the real orchestrator so the
    resulting change request is assembled from genuinely-written rows
    rather than hand-built fixtures."""
    repo = _init_repo(tmp_path)

    def fake_run_mini(cfg, worktree, candidate, *, audit_trail=None, context=None):
        from secure.agent.runner import MiniRunResult

        (worktree.worktree_path / "secure" / "widget.py").write_text(content)
        return MiniRunResult(
            status="completed", returncode=0, exit_status="Submitted", submission="I fixed it",
            mini_version="fake", instance_cost=None, transcript_path=None, model_name="ollama/x",
            argv=["fake"], config_yaml="", transcript_hash=None,
        )

    monkeypatch.setattr(orch_module, "run_mini_swe_agent", fake_run_mini)
    monkeypatch.setattr(
        orch_module, "verify_worktree",
        lambda worktree, cfg_, **_kw: VerificationOutcome(
            VerifyResult("ok", True, "5 passed"), VerifyResult("ok", True, "validate ok")
        ),
    )
    db = Database(tmp_path / "secure.db")
    db.__enter__()
    cfg = _cfg(tmp_path)
    record = attempt_repair(
        db.conn, cfg, RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::t", "boom"),
        repo_root=repo, providers={"ollama": None, "openai_compatible": None},
    )
    return db, record


# =====================================================================
# End-to-end assembly: every field the governing text lists
# =====================================================================


def test_a_change_request_assembles_every_required_field(tmp_path: Path, monkeypatch):
    db, record = _seed(tmp_path, monkeypatch, content=_CONSEQUENTIAL)
    try:
        view = build_change_request_view(db.conn, record.change_request_id)

        assert view.cr_id == record.change_request_id          # request ID
        assert view.run_id == record.run_id                     # requesting run
        assert view.requesting_tool                             # requesting model/framework
        assert view.requesting_model
        assert view.reason                                      # reason
        assert view.proposed_action                             # exact proposed action
        assert view.diff_path                                   # actual diff (path to it)
        assert view.diff_hash                                   # diff hash
        assert view.revision_hash                               # revision hash
        assert view.changed_files == ["secure/widget.py"]       # affected files
        assert view.affected_component                          # affected settings/component
        assert view.classification == CLASS_SYSTEM_CHANGE       # risk classification
        assert view.commands                                    # commands involved
        assert view.pytest_status == "ok"                       # tests performed
        assert "5 passed" in view.pytest_summary                # test results
        assert view.review_status                               # reviewer assessment
        assert view.rollback                                    # rollback strategy
        assert view.status in AWAITING_APPROVAL_STATUSES        # status
    finally:
        db.__exit__(None, None, None)


def test_pending_listing_includes_the_new_request(tmp_path: Path, monkeypatch):
    db, record = _seed(tmp_path, monkeypatch)
    try:
        views = list_pending_change_requests(db.conn)
        assert [v.cr_id for v in views] == [record.change_request_id]
    finally:
        db.__exit__(None, None, None)


def test_a_non_pending_request_drops_out_of_the_listing(tmp_path: Path, monkeypatch):
    db, record = _seed(tmp_path, monkeypatch)
    try:
        cr = find_ai_change_request(db.conn, record.change_request_id)
        approve_change(db.conn, cr.cr_id, revision_hash=cr.revision_hash, approved_by="tester")
        assert list_pending_change_requests(db.conn) == []
    finally:
        db.__exit__(None, None, None)


def test_view_diff_reads_the_real_diff_from_disk(tmp_path: Path, monkeypatch):
    db, record = _seed(tmp_path, monkeypatch)
    try:
        view = build_change_request_view(db.conn, record.change_request_id)
        diff = read_diff(view)
        assert "secure/widget.py" in diff
        assert "return 2" in diff
    finally:
        db.__exit__(None, None, None)


def test_view_diff_reports_a_missing_diff_file_honestly(tmp_path: Path, monkeypatch):
    db, record = _seed(tmp_path, monkeypatch)
    try:
        view = build_change_request_view(db.conn, record.change_request_id)
        Path(view.diff_path).unlink()
        text = read_diff(view)
        assert "no longer exists" in text
        assert "return 2" not in text
    finally:
        db.__exit__(None, None, None)


def test_view_tests_reports_deterministic_results_and_says_they_are_not_authorization(tmp_path: Path, monkeypatch):
    db, record = _seed(tmp_path, monkeypatch)
    try:
        view = build_change_request_view(db.conn, record.change_request_id)
        report = tests_report(view)
        assert "5 passed" in report
        assert "NOT authorization" in report
    finally:
        db.__exit__(None, None, None)


def test_reviewer_report_frames_a_clean_review_as_an_opinion_not_an_approval(tmp_path: Path, monkeypatch):
    db, record = _seed(tmp_path, monkeypatch)
    try:
        view = build_change_request_view(db.conn, record.change_request_id)
        assert "not an approval" in reviewer_report(view)
    finally:
        db.__exit__(None, None, None)


def test_an_unclassified_request_is_treated_as_requiring_approval(tmp_path: Path, monkeypatch):
    """Direction of failure: unknown means gated, never automatic."""
    db, record = _seed(tmp_path, monkeypatch)
    try:
        db.conn.execute("UPDATE ai_change_requests SET classification = NULL")
        db.conn.commit()
        view = build_change_request_view(db.conn, record.change_request_id)
        assert view.classification is None
        assert view.requires_human_approval is True
    finally:
        db.__exit__(None, None, None)


def test_an_ordinary_repair_is_classified_safe_but_still_awaits_a_human(tmp_path: Path, monkeypatch):
    """SAFE_PROJECT_CODE describes the approval level a class permits;
    it does not mean this phase applies anything automatically. Phase
    44 is where automatic promotion is even defined."""
    db, record = _seed(tmp_path, monkeypatch, content=_ORDINARY)
    try:
        view = build_change_request_view(db.conn, record.change_request_id)
        assert view.classification == CLASS_SAFE_PROJECT_CODE
        assert view.awaiting_approval is True
        assert view.status == "pending"
    finally:
        db.__exit__(None, None, None)


# =====================================================================
# Rollback strategy — derived, never stored
# =====================================================================


def test_a_pending_request_says_there_is_nothing_to_roll_back():
    text = rollback_strategy(status="pending", diff_hash="abc", diff_path="/x/diff.patch", worktree_path="/x/wt")
    assert "Nothing to roll back" in text
    assert "has NOT been applied" in text


def test_an_approved_request_explains_how_to_revert_and_what_to_verify():
    text = rollback_strategy(status="approved", diff_hash="abc123", diff_path="/x/diff.patch", worktree_path="/x/wt")
    assert "git apply -R" in text
    assert "abc123" in text


def test_a_superseded_request_can_never_be_approved_as_written():
    assert "never be approved" in rollback_strategy(
        status=STATUS_SUPERSEDED, diff_hash=None, diff_path=None, worktree_path=None
    )


def test_an_unrecognized_status_is_not_assumed_inert():
    text = rollback_strategy(status="something_new", diff_hash=None, diff_path=None, worktree_path=None)
    assert "unknown" in text.lower()
    assert "rather than assuming this change is inert" in text


# =====================================================================
# Approval is revision-bound; changed content cannot inherit it
# =====================================================================


def test_integrity_is_intact_immediately_after_proposal(tmp_path: Path, monkeypatch):
    db, record = _seed(tmp_path, monkeypatch)
    try:
        integrity = approval_integrity(db.conn, record.change_request_id)
        assert integrity.intact is True
        assert integrity.content_hash_matches is True
        assert integrity.diff_hash_matches is True
    finally:
        db.__exit__(None, None, None)


def test_editing_the_diff_on_disk_breaks_integrity(tmp_path: Path, monkeypatch):
    db, record = _seed(tmp_path, monkeypatch)
    try:
        Path(record.diff_path).write_text("totally different patch\n")
        integrity = approval_integrity(db.conn, record.change_request_id)
        assert integrity.diff_hash_matches is False
        assert integrity.intact is False
        assert "has changed" in integrity.detail
    finally:
        db.__exit__(None, None, None)


def test_editing_the_stored_proposal_text_breaks_integrity(tmp_path: Path, monkeypatch):
    db, record = _seed(tmp_path, monkeypatch)
    try:
        db.conn.execute(
            "UPDATE ai_change_requests SET risks = ? WHERE cr_id = ?",
            ("actually this is completely safe, no approval needed", record.change_request_id),
        )
        db.conn.commit()
        integrity = approval_integrity(db.conn, record.change_request_id)
        assert integrity.content_hash_matches is False
        assert integrity.intact is False
    finally:
        db.__exit__(None, None, None)


def test_changed_content_after_approval_is_superseded_not_inherited(tmp_path: Path, monkeypatch):
    """The governing sentence, tested directly: a request that was
    genuinely approved, whose content then changes, must not keep
    carrying that approval."""
    db, record = _seed(tmp_path, monkeypatch)
    try:
        cr = find_ai_change_request(db.conn, record.change_request_id)
        approved = approve_change(db.conn, cr.cr_id, revision_hash=cr.revision_hash, approved_by="tester")
        assert approved.status == "approved"

        Path(record.diff_path).write_text("a different patch entirely\n")
        integrity, updated = invalidate_change_request_if_content_changed(db.conn, cr.cr_id)

        assert integrity.intact is False
        assert updated.status == STATUS_SUPERSEDED
        assert updated.status != "approved"
    finally:
        db.__exit__(None, None, None)


def test_unchanged_content_after_approval_is_left_alone(tmp_path: Path, monkeypatch):
    """The check must not be trigger-happy: an untouched approved
    request keeps its approval."""
    db, record = _seed(tmp_path, monkeypatch)
    try:
        cr = find_ai_change_request(db.conn, record.change_request_id)
        approve_change(db.conn, cr.cr_id, revision_hash=cr.revision_hash, approved_by="tester")
        integrity, updated = invalidate_change_request_if_content_changed(db.conn, cr.cr_id)
        assert integrity.intact is True
        assert updated.status == "approved"
    finally:
        db.__exit__(None, None, None)


def test_a_superseded_request_cannot_then_be_approved(tmp_path: Path, monkeypatch):
    """Phase 28's approve_change() already requires status == 'pending',
    so superseding is a real dead end rather than a label."""
    db, record = _seed(tmp_path, monkeypatch)
    try:
        cr = find_ai_change_request(db.conn, record.change_request_id)
        Path(record.diff_path).write_text("drifted\n")
        invalidate_change_request_if_content_changed(db.conn, cr.cr_id)

        raised = False
        try:
            approve_change(db.conn, cr.cr_id, revision_hash=cr.revision_hash, approved_by="tester")
        except Exception:
            raised = True
        after = find_ai_change_request(db.conn, cr.cr_id)
        assert raised or after.status == STATUS_SUPERSEDED
        assert after.status != "approved"
    finally:
        db.__exit__(None, None, None)


def test_the_recorded_revision_hash_really_is_a_hash_of_the_recorded_content(tmp_path: Path, monkeypatch):
    db, record = _seed(tmp_path, monkeypatch)
    try:
        from secure.ai.changes.model import ProposedChangeContent, compute_revision_hash

        cr = find_ai_change_request(db.conn, record.change_request_id)
        recomputed = compute_revision_hash(ProposedChangeContent(
            title=cr.title, proposed_change=cr.proposed_change, reason=cr.reason,
            affected_component=cr.affected_component, risks=cr.risks,
        ))
        assert recomputed == cr.revision_hash
    finally:
        db.__exit__(None, None, None)


def test_the_diff_hash_recorded_on_the_run_matches_the_file_on_disk(tmp_path: Path, monkeypatch):
    db, record = _seed(tmp_path, monkeypatch)
    try:
        on_disk = hashlib.sha256(Path(record.diff_path).read_bytes()).hexdigest()
        assert on_disk == record.diff_hash
    finally:
        db.__exit__(None, None, None)


def test_integrity_check_on_a_missing_request_reports_nothing_rather_than_raising(tmp_path: Path, monkeypatch):
    db, _record = _seed(tmp_path, monkeypatch)
    try:
        assert approval_integrity(db.conn, "CR-does-not-exist") is None
        integrity, record = invalidate_change_request_if_content_changed(db.conn, "CR-does-not-exist")
        assert integrity is None and record is None
    finally:
        db.__exit__(None, None, None)


# =====================================================================
# This module is a reader
# =====================================================================


def test_center_module_performs_no_database_writes():
    """The Change Request Center is a READER. `secure/agent/` is already
    covered by test_agent.py's AST-based no-self-approval check, so
    repeating that here would add nothing; this asserts the distinct
    property this module's own docstring claims — that it contains no
    SQL mutation at all, so a future edit that adds one is visible.

    Checked against string literals in the parsed AST rather than the
    raw file text, because this module's docstring legitimately
    discusses approval and superseding in prose — the same reason
    test_agent.py's own no-self-approval check parses the source
    instead of grepping it.
    """
    import ast

    source = Path(__file__).resolve().parents[1] / "secure" / "agent" / "center.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))

    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)

    offending = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if node.value in docstrings:
            continue
        upper = node.value.upper()
        for verb in ("INSERT INTO", "UPDATE ", "DELETE FROM", "DROP ", "ALTER "):
            if verb in upper:
                offending.append(f"line {node.lineno}: {node.value[:60]!r}")

    assert offending == []
