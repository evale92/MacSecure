"""
secure/ai/changes/ — Phase 28 Stage 7: the change-request workflow the
governing instruction requires for anything either model proposes:

    "A simplification should follow: Model A proposes change -> Model B
    attacks proposal -> deterministic tests run -> change request
    created -> human approval required."

    "Critical rule: any system change proposed by either LLM must be
    approved by me before execution. ... Neither LLM may approve the
    other. Agreement between both models does not equal approval.
    Passing tests does not equal approval. Silence does not equal
    approval."

Five hard rules this package enforces structurally, not just by
convention:

1.  EVERY CHANGE REQUEST IS BORN 'pending'. `add_ai_change_request()`
    (secure/storage/models/ai.py) hard-codes the insert to
    `status = 'pending'` — there is no code path, anywhere, that can
    create a change request in any other state.

2.  ONLY `approve_change()`/`reject_change()` IN THIS MODULE MAY MOVE A
    STATUS AWAY FROM 'pending', and both are written to be called from
    exactly one place: an explicit human-triggered CLI command
    (`secure ai changes approve/reject`). Nothing in secure/ai/roles.py,
    secure/ai/analyst.py, or this package's own `propose_change()` ever
    calls them. An LLM's own output is never treated as an approval,
    no matter how it agrees, how confident it sounds, or what it claims
    about being pre-authorized.

3.  APPROVAL IS BOUND TO AN EXACT REVISION HASH. `propose_change()`
    computes a hash over the change request's own proposed content
    (title, proposed_change, reason, affected_component, risks) at
    creation time and stores it. `approve_change()` requires the caller
    to pass that same hash back and refuses to approve on a mismatch —
    so a change request can never be silently re-purposed after a human
    has seen and approved a specific version of it.

4.  NOTIFICATION IS NEVER AUTHORIZATION. `notify.py` sends an
    informational email; it never writes to `ai_change_requests.status`
    and its own success/failure never affects whether the change
    request was created. A dead mail server does not block Secure.

5.  THIS PACKAGE NEVER EXECUTES A CHANGE. There is no code here, in
    Stage 6's verification package, or anywhere else in secure/ai/,
    that edits source, changes configuration, or touches detection
    logic, thresholds, baselines, the database schema, or any macOS
    setting. Approving a change request is a paper-trail event only —
    acting on it, if ever, is a manual step a human takes outside
    Secure, using the change request as their own record of what was
    proposed, attacked, tested, and approved.
"""
