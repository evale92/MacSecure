"""
secure/agent/ — Phase 31: Agent Foundation.

Supervised, human-approved autonomous repair. This package sits where
secure/ai/ and secure/validate/ do in the layer model
(docs/ARCHITECTURE.md) — callable only from the interfaces layer
(secure/cli/, secure_gui/), never imported by any sensor, integration,
evidence, baseline, correlation, or explanation module, in either
direction. Nothing here writes to severity, anomaly_score,
correlation_alerts, or anything secure/explain/ reads — an autonomous
repair is a maintenance action, not a security finding.

Secure owns policy, isolation, evidence, verification, approval, and
auditability. It does NOT own the coding-agent loop, patch generation,
or command execution during a repair attempt — that belongs entirely
to the external tool (mini-SWE-agent, Phase 31's only supported tool;
see secure/agent/runner.py's own module docstring for why Aider and
OpenHands are explicitly out of scope this phase).

Five hard rules this package is built around — the first four inherited
unchanged from secure/ai/changes/__init__.py's own five (see that
module's docstring for the full reasoning), the fifth new to this
phase:

1.  EVERY CHANGE REQUEST A REPAIR PRODUCES IS BORN 'pending'. This
    package never calls anything except secure.ai.changes.workflow's
    own propose_change() to create one — the exact same function, the
    exact same hard-coded 'pending' status, unmodified.

2.  ONLY approve_change()/reject_change() IN secure/ai/changes/workflow.py
    MAY MOVE A STATUS AWAY FROM 'pending' — called from exactly the
    same place Phase 28 already restricts them to: an explicit
    human-triggered CLI/GUI action. Nothing in secure/agent/ ever
    calls them itself.

3.  APPROVAL IS BOUND TO AN EXACT REVISION HASH, and Phase 31 extends
    what that hash covers: the produced diff's own SHA-256 is embedded
    directly in the change request's proposed_change text, so
    approve_change()'s existing exact-match check transitively pins
    the exact diff content too — with zero changes to workflow.py.

4.  NOTHING HERE — not the tool run, not verification, not a passing
    test suite, not the model's own summary — IS EVER TREATED AS
    AUTHORIZATION. A verified repair still only ever produces a
    PENDING change request.

5.  THE EXTERNAL AGENT MAY MODIFY ONLY THE ISOLATED WORKTREE. It is
    invoked with its working directory pinned to a `git worktree`
    (secure/agent/worktree.py) that is never the live checkout;
    verification (secure/agent/verify.py) always re-derives PASS/FAIL
    by running pytest and `secure validate` as fresh subprocesses
    against that same worktree, never by trusting the tool's own
    self-reported success; and this package computes the diff of
    record itself via `git diff` inside the worktree, never by
    trusting the tool's self-reported patch text.

Even a fully passing, fully verified repair never applies itself to
the live repository in Phase 31 — see secure/agent/changes.py's own
docstring for why, and for how a later, separately-approved
`secure agent apply` capability could be added without changing
anything here.
"""
