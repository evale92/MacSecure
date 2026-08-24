"""tests/test_agent_notify.py — Phase 41 ("Email Change Notifications").

Acceptance criterion under test (verbatim, from
docs/ROADMAP_PART2_PHASES_38_47.md):

    "Tests prove the correct approval states generate sanitized
    notifications, ordinary SAFE_PROJECT_CODE does not unnecessarily
    notify, secrets cannot enter the generated email, and email has no
    authorization path."

NO REAL EMAIL IS EVER SENT BY THIS FILE. `AppConfig.smtp_host` defaults
to the empty string, which every path here relies on as the "not
configured" gate, and the one test that exercises the transport
monkeypatches `smtplib.SMTP` with a recorder. There is no test in this
file that would open a socket.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import secure.agent.orchestrator as orch_module
import secure.ai.changes.notify as notify_module
from secure.agent.classify import (
    CLASS_DEPENDENCY_CHANGE,
    CLASS_PRIVILEGED_CHANGE,
    CLASS_SAFE_PROJECT_CODE,
    CLASS_SECURITY_SEMANTIC_CHANGE,
    CLASS_SYSTEM_CHANGE,
)
from secure.agent.notify import (
    NOTIFY_CLASSES,
    REDACTED,
    build_notification_email,
    notify_if_consequential,
    sanitize,
    should_notify,
)
from secure.agent.orchestrator import attempt_repair
from secure.agent.policy import TRIGGER_PYTEST_FAILURE, RepairCandidate
from secure.agent.verify import VerificationOutcome, VerifyResult
from secure.ai.changes.notify import NOTIFY_SENT, NOTIFY_SKIPPED
from secure.config import AppConfig, default_config
from secure.storage.database import Database
from secure.storage.models import find_ai_change_request


# ---------- a stand-in for the Phase 40 view ----------


@dataclass
class _View:
    cr_id: str = "CR-7"
    status: str = "pending"
    classification: "Optional[str]" = CLASS_SYSTEM_CHANGE
    reason: str = "pytest failure in tests/test_widget.py"
    affected_component: str = "secure/widget.py"
    requesting_tool: str = "mini-swe-agent"
    requesting_model: str = "ollama/qwen"
    review_status: "Optional[str]" = "ok"
    review_blocking: list = field(default_factory=list)
    revision_hash: str = "0" * 64


def _cfg_with_smtp(tmp_path: Path) -> AppConfig:
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    cfg.smtp_host = "smtp.example.invalid"
    cfg.smtp_port = 25
    cfg.ai_notify_email = "operator@example.invalid"
    return cfg


class _RecordingSMTP:
    """Captures what would have been sent. Never opens a socket."""

    sent: list = []

    def __init__(self, host, port, timeout=None):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        pass

    def login(self, user, password):
        pass

    def send_message(self, message):
        _RecordingSMTP.sent.append(message)


# =====================================================================
# Which classes notify
# =====================================================================


def test_all_four_consequential_classes_notify():
    for cls in (CLASS_DEPENDENCY_CHANGE, CLASS_SECURITY_SEMANTIC_CHANGE, CLASS_SYSTEM_CHANGE, CLASS_PRIVILEGED_CHANGE):
        assert should_notify(cls).should_notify is True


def test_the_notify_list_is_exactly_the_four_the_roadmap_names():
    assert set(NOTIFY_CLASSES) == {
        CLASS_DEPENDENCY_CHANGE, CLASS_SECURITY_SEMANTIC_CHANGE, CLASS_SYSTEM_CHANGE, CLASS_PRIVILEGED_CHANGE,
    }


def test_ordinary_safe_project_code_does_not_notify():
    decision = should_notify(CLASS_SAFE_PROJECT_CODE)
    assert decision.should_notify is False
    assert "does not require a notification" in decision.reason


def test_an_unclassified_change_notifies_rather_than_staying_silent():
    assert should_notify(None).should_notify is True
    assert should_notify("").should_notify is True


def test_an_unrecognized_class_notifies_rather_than_staying_silent():
    decision = should_notify("SOME_FUTURE_CLASS")
    assert decision.should_notify is True
    assert "approval-gated by default" in decision.reason


def test_the_skip_decision_is_recorded_not_silent():
    """"Does not notify" is a decision with a stated reason, so an
    absent email is inspectable rather than mysterious."""
    assert should_notify(CLASS_SAFE_PROJECT_CODE).reason


# =====================================================================
# Sanitization — secrets cannot enter the email
# =====================================================================


def test_a_field_containing_a_secret_keyword_is_withheld_entirely():
    out = sanitize("api_key=hunter2seventeen")
    assert "hunter2seventeen" not in out
    assert "withheld" in out


def test_password_token_and_bearer_are_all_caught():
    for text in ("password: swordfish", "bearer abc.def.ghi", "TOKEN=zzz", "Authorization: Basic xyz"):
        assert "withheld" in sanitize(text), text


def test_a_long_opaque_token_is_redacted_even_without_a_keyword():
    secret = "A" * 40
    out = sanitize(f"the value is {secret} ok")
    assert secret not in out
    assert REDACTED in out


def test_a_short_ordinary_word_is_not_redacted():
    assert sanitize("secure/widget.py changed") == "secure/widget.py changed"


def test_fields_are_length_bounded_so_a_diff_cannot_be_smuggled_in():
    out = sanitize("x " * 5000)
    assert len(out) < 500
    assert "truncated" in out


def test_sanitize_handles_none_and_empty():
    assert sanitize(None) == ""
    assert sanitize("") == ""


# =====================================================================
# The email body itself
# =====================================================================


def test_email_contains_every_field_the_governing_text_requires():
    subject, body = build_notification_email(_View())
    assert "CR-7" in subject                    # request ID
    assert "Request ID:" in body
    assert "pytest failure" in body             # reason
    assert "Requested action:" in body          # requested action
    assert CLASS_SYSTEM_CHANGE in body          # classification
    assert "mini-swe-agent" in body             # requesting agent
    assert "ollama/qwen" in body                # requesting model
    assert "Reviewer result:" in body           # reviewer result
    assert "Status:" in body                    # status
    assert "secure agent center show" in body   # instruction to review inside Secure


def test_email_says_plainly_that_it_authorizes_nothing():
    _subject, body = build_notification_email(_View())
    assert "NOTIFICATION ONLY" in body
    assert "does not authorize anything" in body


def test_replying_to_the_email_is_stated_to_do_nothing():
    _subject, body = build_notification_email(_View())
    assert "Replying to this email does nothing" in body
    assert "no approval path through email" in body


def test_the_email_carries_no_approval_token_or_link():
    """There is nothing in the body a recipient could act on except a
    command they type into their own terminal — no URL, no token, no
    reply-to instruction that would approve anything."""
    _subject, body = build_notification_email(_View())
    assert "http://" not in body
    assert "https://" not in body
    assert "click" not in body.lower()


def test_the_revision_hash_is_not_in_the_email():
    """Deliberate: including it would invite approving from the email
    rather than from the tool, and it is opaque enough to be caught by
    the entropy rule anyway."""
    view = _View()
    _subject, body = build_notification_email(view)
    assert view.revision_hash not in body


def test_a_blocking_reviewer_finding_is_stated_in_the_email():
    view = _View(review_blocking=["tests_weakened"])
    _subject, body = build_notification_email(view)
    assert "BLOCKING" in body
    assert "tests_weakened" in body


def test_a_missing_review_is_reported_honestly():
    _subject, body = build_notification_email(_View(review_status=None))
    assert "no independent review recorded" in body


def test_a_secret_in_a_view_field_never_reaches_the_body():
    view = _View(reason="the failure was: API_KEY=sk-live-abcdefghijklmnop")
    _subject, body = build_notification_email(view)
    assert "sk-live-abcdefghijklmnop" not in body
    assert "withheld" in body


# =====================================================================
# Transport
# =====================================================================


def test_nothing_is_sent_when_smtp_is_not_configured(tmp_path: Path):
    cfg = default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    status, detail = notify_if_consequential(cfg, _View())
    assert status == NOTIFY_SKIPPED
    assert "not configured" in detail


def test_safe_project_code_is_skipped_before_any_transport(tmp_path: Path, monkeypatch):
    """Even with SMTP fully configured, an ordinary change sends
    nothing — proving the skip is a policy decision, not an accident of
    an unconfigured relay."""
    _RecordingSMTP.sent = []
    monkeypatch.setattr(notify_module.smtplib, "SMTP", _RecordingSMTP)
    cfg = _cfg_with_smtp(tmp_path)
    status, _detail = notify_if_consequential(cfg, _View(classification=CLASS_SAFE_PROJECT_CODE))
    assert status == NOTIFY_SKIPPED
    assert _RecordingSMTP.sent == []


def test_a_consequential_change_sends_exactly_one_sanitized_message(tmp_path: Path, monkeypatch):
    _RecordingSMTP.sent = []
    monkeypatch.setattr(notify_module.smtplib, "SMTP", _RecordingSMTP)
    cfg = _cfg_with_smtp(tmp_path)
    status, _detail = notify_if_consequential(cfg, _View(classification=CLASS_PRIVILEGED_CHANGE))
    assert status == NOTIFY_SENT
    assert len(_RecordingSMTP.sent) == 1
    body = _RecordingSMTP.sent[0].get_content()
    assert "NOTIFICATION ONLY" in body


def test_a_transport_failure_is_reported_not_raised(tmp_path: Path, monkeypatch):
    class _Exploding(_RecordingSMTP):
        def __init__(self, host, port, timeout=None):
            raise OSError("relay unreachable")

    monkeypatch.setattr(notify_module.smtplib, "SMTP", _Exploding)
    cfg = _cfg_with_smtp(tmp_path)
    status, detail = notify_if_consequential(cfg, _View())
    assert status == "failed"
    assert "relay unreachable" in detail


# =====================================================================
# End-to-end through a real repair
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


_CONSEQUENTIAL = 'import subprocess\n\n\ndef widget():\n    subprocess.run(["launchctl", "load", "/x.plist"])\n'
_ORDINARY = "def widget():\n    return 2\n"


def _seed(tmp_path, monkeypatch, *, content: str, smtp: bool):
    repo = _init_repo(tmp_path)

    def fake_run_mini(cfg, worktree, candidate, *, audit_trail=None, context=None):
        from secure.agent.runner import MiniRunResult

        (worktree.worktree_path / "secure" / "widget.py").write_text(content)
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
    _RecordingSMTP.sent = []
    monkeypatch.setattr(notify_module.smtplib, "SMTP", _RecordingSMTP)

    cfg = _cfg_with_smtp(tmp_path) if smtp else default_config()
    cfg.app_dir = str(tmp_path / "appdir")
    cfg.agent_verify_timeout_seconds = 30
    cfg.agent_timeout_seconds = 30

    with Database(tmp_path / "secure.db") as db:
        record = attempt_repair(
            db.conn, cfg, RepairCandidate(TRIGGER_PYTEST_FAILURE, "tests/test_widget.py::t", "boom"),
            repo_root=repo, providers={"ollama": None, "openai_compatible": None},
        )
        cr = find_ai_change_request(db.conn, record.change_request_id)
        return record, cr


def test_a_consequential_repair_notifies_once_and_the_email_has_no_diff(tmp_path: Path, monkeypatch):
    """The reason this phase suppresses Phase 28's own notification for
    the agent path: that body embeds up to 6000 characters of raw diff,
    and a diff is arbitrary repository text."""
    _record, cr = _seed(tmp_path, monkeypatch, content=_CONSEQUENTIAL, smtp=True)
    assert len(_RecordingSMTP.sent) == 1
    body = _RecordingSMTP.sent[0].get_content()
    assert "launchctl" not in body
    assert "--- diff ---" not in body
    assert CLASS_SYSTEM_CHANGE in body
    assert cr.notify_status == NOTIFY_SENT


def test_an_ordinary_repair_sends_no_email_at_all(tmp_path: Path, monkeypatch):
    _record, cr = _seed(tmp_path, monkeypatch, content=_ORDINARY, smtp=True)
    assert _RecordingSMTP.sent == []
    assert cr.notify_status == NOTIFY_SKIPPED


def test_a_repair_with_no_smtp_still_produces_an_approvable_change_request(tmp_path: Path, monkeypatch):
    """A notification problem must never turn a verified, persisted
    repair into a failure."""
    record, cr = _seed(tmp_path, monkeypatch, content=_CONSEQUENTIAL, smtp=False)
    assert record.status == "verified"
    assert cr is not None
    assert cr.status == "pending"
    assert _RecordingSMTP.sent == []


# =====================================================================
# The suppression parameter cannot touch approval
# =====================================================================


def test_propose_change_notify_false_still_creates_a_pending_request(tmp_path: Path, monkeypatch):
    from secure.ai.changes.workflow import propose_change

    _RecordingSMTP.sent = []
    monkeypatch.setattr(notify_module.smtplib, "SMTP", _RecordingSMTP)
    cfg = _cfg_with_smtp(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        cr = propose_change(
            db.conn, cfg, title="t", proposed_change="p", reason="r", affected_component="c",
            risks="risk", model_a_opinion="a", model_b_opinion="b", notify=False,
        )
        assert cr.status == "pending"
        assert cr.revision_hash
        assert _RecordingSMTP.sent == []
        assert cr.notify_status == "deferred_to_caller"


def test_propose_change_defaults_to_notifying_exactly_as_before(tmp_path: Path, monkeypatch):
    """The new parameter is additive: a caller that does not name it
    behaves identically to every pre-Phase-41 caller."""
    from secure.ai.changes.workflow import propose_change

    _RecordingSMTP.sent = []
    monkeypatch.setattr(notify_module.smtplib, "SMTP", _RecordingSMTP)
    cfg = _cfg_with_smtp(tmp_path)
    with Database(tmp_path / "secure.db") as db:
        cr = propose_change(
            db.conn, cfg, title="t", proposed_change="p", reason="r", affected_component="c",
            risks="risk", model_a_opinion="a", model_b_opinion="b",
        )
        assert len(_RecordingSMTP.sent) == 1
        assert cr.notify_status == NOTIFY_SENT


def test_notify_module_has_no_approval_call():
    """Structural: nothing in the notification path can approve
    anything. Checked against the parsed AST's non-docstring content,
    since the module's prose legitimately discusses approval."""
    import ast

    source = Path(__file__).resolve().parents[1] / "secure" / "agent" / "notify.py"
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    banned = {"approve_change", "reject_change", "set_ai_change_request_status"}
    offending = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(a.name in banned for a in node.names):
            offending.append(f"import at line {node.lineno}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in banned:
            offending.append(f"call at line {node.lineno}")
    assert offending == []
