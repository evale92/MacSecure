"""
Tests for Phase 28 Stage 7: the change-request workflow
(secure/ai/changes/model.py, notify.py, workflow.py). Covers the
revision-hash safeguard, the pending-only state machine, notification
gating (skipped without SMTP, sent via a monkeypatched smtplib.SMTP,
never blocking on failure), and the full Model A -> Model B ->
deterministic tests -> PENDING CR pipeline with stub providers.

Run with:  pytest
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from secure.ai.base import STATUS_OK as PSTATUS_OK
from secure.ai.base import ProviderCompletionResult, ProviderIdentity
from secure.ai.changes import notify as notify_module
from secure.ai.changes.model import ProposedChangeContent, compute_revision_hash
from secure.ai.changes.workflow import (
    RevisionMismatchError,
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_REJECTED,
    approve_change,
    propose_change,
    propose_simplification,
    reject_change,
)
from secure.config import AppConfig
from secure.storage.database import Database
from secure.storage.models import find_ai_change_request, list_ai_change_requests


# ---------- model.py ----------


def test_compute_revision_hash_is_deterministic():
    content = ProposedChangeContent(
        title="t", proposed_change="pc", reason="r", affected_component="c", risks="risk"
    )
    assert compute_revision_hash(content) == compute_revision_hash(content)


def test_compute_revision_hash_changes_when_content_changes():
    a = ProposedChangeContent(title="t", proposed_change="pc", reason="r", affected_component="c", risks="risk")
    b = ProposedChangeContent(title="t", proposed_change="different", reason="r", affected_component="c", risks="risk")
    assert compute_revision_hash(a) != compute_revision_hash(b)


# ---------- notify.py ----------


def _cr_record(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        cfg = AppConfig(app_dir=str(tmp_path))
        record = propose_change(
            db.conn, cfg, title="t", proposed_change="pc", reason="r", affected_component="c",
            risks="risk", model_a_opinion="a", model_b_opinion="b",
        )
        return record, cfg


def test_notify_skipped_when_smtp_not_configured(tmp_path: Path):
    record, cfg = _cr_record(tmp_path)
    assert record.notify_status == notify_module.NOTIFY_SKIPPED


def test_notify_email_body_includes_all_required_fields(tmp_path: Path):
    record, cfg = _cr_record(tmp_path)
    body = notify_module.build_email_body(record, verification_summary="verification summary here")
    for expected in (
        record.cr_id, record.proposed_change, record.reason, record.affected_component,
        record.risks, "verification summary here", record.model_a_opinion, record.model_b_opinion,
    ):
        assert expected in body


def test_notify_sent_via_monkeypatched_smtp(tmp_path: Path, monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=15):
            sent["host"] = host
            sent["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            sent["starttls"] = True

        def login(self, user, pw):
            sent["login"] = (user, pw)

        def send_message(self, message):
            sent["message"] = message

    monkeypatch.setattr(notify_module.smtplib, "SMTP", FakeSMTP)

    with Database(tmp_path / "t.db") as db:
        cfg = AppConfig(
            app_dir=str(tmp_path), smtp_host="smtp.example.com", smtp_port=587, smtp_use_tls=True,
            ai_notify_email="evale92@gmail.com",
        )
        record = propose_change(
            db.conn, cfg, title="t", proposed_change="pc", reason="r", affected_component="c",
            risks="risk", model_a_opinion="a", model_b_opinion="b",
        )

    assert record.notify_status == notify_module.NOTIFY_SENT
    assert sent["host"] == "smtp.example.com"
    assert sent["starttls"] is True
    assert sent["message"]["To"] == "evale92@gmail.com"


def test_notify_failure_does_not_block_change_request_creation(tmp_path: Path, monkeypatch):
    def raising_smtp(*a, **k):
        raise ConnectionRefusedError("no smtp server here")

    monkeypatch.setattr(notify_module.smtplib, "SMTP", raising_smtp)

    with Database(tmp_path / "t.db") as db:
        cfg = AppConfig(app_dir=str(tmp_path), smtp_host="smtp.example.com", ai_notify_email="evale92@gmail.com")
        record = propose_change(
            db.conn, cfg, title="t", proposed_change="pc", reason="r", affected_component="c",
            risks="risk", model_a_opinion="a", model_b_opinion="b",
        )

    assert record.status == STATUS_PENDING  # created regardless of notify outcome
    assert record.notify_status == notify_module.NOTIFY_FAILED


# ---------- workflow.py: propose/approve/reject ----------


def test_propose_change_is_always_born_pending(tmp_path: Path):
    record, _ = _cr_record(tmp_path)
    assert record.status == STATUS_PENDING
    assert record.cr_id == "CR-1"


def test_cr_ids_are_sequential(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        cfg = AppConfig(app_dir=str(tmp_path))
        r1 = propose_change(db.conn, cfg, title="1", proposed_change="p", reason="r", affected_component="c", risks="k", model_a_opinion="a", model_b_opinion="b")
        r2 = propose_change(db.conn, cfg, title="2", proposed_change="p", reason="r", affected_component="c", risks="k", model_a_opinion="a", model_b_opinion="b")
    assert r1.cr_id == "CR-1"
    assert r2.cr_id == "CR-2"


def test_approve_change_requires_the_exact_revision_hash(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        cfg = AppConfig(app_dir=str(tmp_path))
        record = propose_change(db.conn, cfg, title="t", proposed_change="p", reason="r", affected_component="c", risks="k", model_a_opinion="a", model_b_opinion="b")
        try:
            approve_change(db.conn, record.cr_id, revision_hash="wrong-hash", approved_by="erick")
            assert False, "should have raised"
        except RevisionMismatchError:
            pass
        approved = approve_change(db.conn, record.cr_id, revision_hash=record.revision_hash, approved_by="erick")
    assert approved.status == STATUS_APPROVED
    assert approved.approved_by == "erick"


def test_approve_change_missing_cr_raises(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        try:
            approve_change(db.conn, "CR-999", revision_hash="x", approved_by="erick")
            assert False, "should have raised"
        except ValueError:
            pass


def test_cannot_approve_a_non_pending_change_request_twice(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        cfg = AppConfig(app_dir=str(tmp_path))
        record = propose_change(db.conn, cfg, title="t", proposed_change="p", reason="r", affected_component="c", risks="k", model_a_opinion="a", model_b_opinion="b")
        approve_change(db.conn, record.cr_id, revision_hash=record.revision_hash, approved_by="erick")
        try:
            approve_change(db.conn, record.cr_id, revision_hash=record.revision_hash, approved_by="erick")
            assert False, "should have raised"
        except ValueError as exc:
            assert "not pending" in str(exc)


def test_reject_change(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        cfg = AppConfig(app_dir=str(tmp_path))
        record = propose_change(db.conn, cfg, title="t", proposed_change="p", reason="r", affected_component="c", risks="k", model_a_opinion="a", model_b_opinion="b")
        rejected = reject_change(db.conn, record.cr_id, approved_by="erick")
    assert rejected.status == STATUS_REJECTED


def test_list_ai_change_requests_status_filter(tmp_path: Path):
    with Database(tmp_path / "t.db") as db:
        cfg = AppConfig(app_dir=str(tmp_path))
        r1 = propose_change(db.conn, cfg, title="1", proposed_change="p", reason="r", affected_component="c", risks="k", model_a_opinion="a", model_b_opinion="b")
        r2 = propose_change(db.conn, cfg, title="2", proposed_change="p", reason="r", affected_component="c", risks="k", model_a_opinion="a", model_b_opinion="b")
        approve_change(db.conn, r1.cr_id, revision_hash=r1.revision_hash, approved_by="erick")

        pending = list_ai_change_requests(db.conn, status="pending")
        approved = list_ai_change_requests(db.conn, status="approved")

    assert {r.cr_id for r in pending} == {r2.cr_id}
    assert {r.cr_id for r in approved} == {r1.cr_id}


# ---------- propose_simplification() end-to-end with stub providers ----------


@dataclass
class StubProvider:
    name: str
    configured: bool = True
    text: str = "{}"

    def __post_init__(self):
        self.identity = ProviderIdentity(name=self.name)
        self.model_name = f"{self.name}-model"

    def check_reachable(self):
        return self.configured, "stub"

    def complete(self, system_prompt, user_prompt, *, timeout=None):
        return ProviderCompletionResult(
            provider=self.name, model=self.model_name, status=PSTATUS_OK, text=self.text,
            requested_at="t", latency_ms=1.0, raw_response=None, error=None,
        )


def _answer(summary: str, **extra) -> str:
    payload = {"summary": summary, "claims": [], "suggested_next_steps": []}
    payload.update(extra)
    return json.dumps(payload)


def test_propose_simplification_no_provider_creates_no_change_request(tmp_path: Path, monkeypatch):
    import secure.ai.changes.workflow as workflow_module

    monkeypatch.setattr(
        workflow_module, "build_providers",
        lambda cfg: {"ollama": StubProvider(name="ollama", configured=False),
                     "openai_compatible": StubProvider(name="openai_compatible", configured=False)},
    )
    with Database(tmp_path / "t.db") as db:
        outcome = propose_simplification(
            db.conn, AppConfig(app_dir=str(tmp_path)), title="t", topic="topic", affected_component="c",
        )
    assert outcome.change_request is None


@pytest.mark.usefixtures("stub_verification_pytest")
def test_propose_simplification_full_pipeline_creates_pending_cr(tmp_path: Path, monkeypatch):
    import secure.ai.changes.workflow as workflow_module

    monkeypatch.setattr(
        workflow_module, "build_providers",
        lambda cfg: {
            "ollama": StubProvider(name="ollama", text=_answer("simplify the dedup pass")),
            "openai_compatible": StubProvider(
                name="openai_compatible",
                text=_answer("my independent take", agreement="agrees", contradictions_found=["watch for X"]),
            ),
        },
    )
    with Database(tmp_path / "t.db") as db:
        outcome = propose_simplification(
            db.conn, AppConfig(app_dir=str(tmp_path)), title="Simplify dedup", topic="dedup logic",
            affected_component="secure/integrations/suricata",
        )
        record = find_ai_change_request(db.conn, outcome.change_request.cr_id)

    assert record.status == STATUS_PENDING
    assert record.proposed_change == "simplify the dedup pass"
    assert "watch for X" in record.risks
    assert record.verification_run_id is not None
    assert outcome.verification is not None


@pytest.mark.usefixtures("stub_verification_pytest")
def test_propose_simplification_never_auto_approves(tmp_path: Path, monkeypatch):
    # Even when both models "agree," the resulting change request must
    # still be 'pending' — agreement between the two models is
    # explicitly NOT approval per the governing instruction.
    import secure.ai.changes.workflow as workflow_module

    monkeypatch.setattr(
        workflow_module, "build_providers",
        lambda cfg: {
            "ollama": StubProvider(name="ollama", text=_answer("proposal")),
            "openai_compatible": StubProvider(name="openai_compatible", text=_answer("also agrees", agreement="agrees")),
        },
    )
    with Database(tmp_path / "t.db") as db:
        outcome = propose_simplification(
            db.conn, AppConfig(app_dir=str(tmp_path)), title="t", topic="topic", affected_component="c",
        )
    assert outcome.change_request.status == STATUS_PENDING
