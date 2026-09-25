# Gate remediation work order — Phase 63 DECLINED

**Status:** Phase 63 is declined. Do not start the next phase.
**Scope:** repair the mutation-gate suite, then re-submit Phase 63 for clearance.

---

## Why the green suite was convincing

This is the part worth understanding before touching code, because it explains
how ten passing tests hid nine defects.

A mutation gate is a **second-order claim**. A normal test asserts something
about the product. A gate asserts something about *the tests* — "if the product
broke, a test would go red." That is its entire evidentiary content. There is no
independent signal underneath it to fall back on.

So when a gate is defective, the failure is not additive, it is **structural**.
In this suite, "10 passed" and "the product is sound" are causally disconnected:
the same green appears whether or not test integrity holds. That makes green
here not weak evidence but **zero** evidence.

And it is worse than zero, because a green gate suite is consumed as a licence to
trust the tests beneath it. This one was laundering four unverified subsystems
into "mutation-gated." An absent suite invites scrutiny; a false-green suite
suppresses it. That asymmetry is why it was persuasive.

Of 10 tests across the three Phase 63 gate files, **one** is a working mutation
gate: the payload gate. It survives precisely because it was sabotage-tested.
That is the lesson — sabotage proof is what separates a gate from decoration.

**Consequence:** the Phase 63 evidence record is withdrawn, not amended.

---

## Ruling: stubs are PRODUCT-ONLY

`tests/integration/fixtures.py` is **not** an acceptable home for fault
injection. `SECURE_STUB_PERSISTENCE_LATENCY` is a violation and is added to the
work order as item 11.

### The decision rule

> **Fault injection must sit on the same side of the boundary as the behavior
> the gate claims to be testing.**

If the gate's claim is "the test catches a slow *product scanner*," the slowness
must be injected in the product. Injecting it in a fixture proves only that the
test catches a lying fixture.

### Why this one fails the rule

```python
def scan_persistence(self) -> tuple[bool, float, Optional[str]]:
    stub_latency = os.environ.get("SECURE_STUB_PERSISTENCE_LATENCY")
    if stub_latency:
        return True, float(stub_latency), "stub_test"   # returns BEFORE product runs
    start_time = time.time()
    result = scan_persistence(self.db_conn)             # the real product call
```

The stub short-circuits ahead of the product call. `fixtures.py` describes
itself as *"Test fixtures wired to real scanners"* — the wiring is exactly what
the stub bypasses. Gate1 therefore exercises no product code.

Contrast the one gate that works: `secure/web/app.py:274` corrupts the **real
server's** response, so the product genuinely misbehaves and the test genuinely
catches it. That is a true mutation.

### The narrow exception

A fixture-level seam is legitimate only when the faulted thing is something the
product does not own — an external service, the wall clock, the network. It is
not legitimate when product code exists and could carry the fault instead.
`scan_persistence` is product code, so the fault belongs there.

---

## Work order

Ordered so that each item is verifiable on completion. **Every gate must ship
with its own sabotage proof** (item 12) — an item is not done without one.

### 1. Delete or rebuild `test_gate_siem_http_failure_detection`
`tests/integration/test_siem_mutation_gates.py:16`
It runs `subprocess.run(...)`, assigns `result`, and ends in comments. No
assertion. It cannot fail. It cannot be "fixed" as written, because the fault it
wants to inject (`SECURE_STUB_SIEM_HTTP_BREAK`) does not exist anywhere.
**Do:** delete it, or implement the stub in product and write a real assertion.
**Prove:** sabotage the test under gate; the gate must go red.

### 2. Rewrite both automation gates
`tests/integration/test_automation_mutation_gates.py:37` and `:60`
Both accept both outcomes. Verified empirically against a real failing pytest
run — both return `True` when the product is broken:
```
1 failed, 1 passed in 0.00s
gate_dispatcher assertion passes on a FAILING product: True
gate_engine     assertion passes on a FAILING product: True
```
**Do:** rewrite on the `test_mutation_gates.py` gate2 pattern — assert
`returncode != 0` **and** a specific sentinel. Delete the both-outcomes logic and
the dead `GATE_AUTOMATION_ENGINE_SIEM` disjunct (that string appears nowhere but
inside the assertion searching for it).
**Prove:** gate is red when the product is broken, green when it is not.

### 3. Implement or drop the two unread SIEM stubs
`SECURE_STUB_SIEM_HTTP_BREAK`, `SECURE_STUB_SIEM_TRANSPORT_BREAK` — zero readers
in the repo. The gates setting them inject nothing.
**Do:** implement in `secure/integrations/siem.py`, or delete the gates that set
them. **No gate may set a variable nothing reads.**
**Prove:** Check B (below) passes.

### 4. Move the two dashboard bind stubs into product
`tests/test_web_dashboard.py:21` and `:97`
Fault injection inside the test under gate — the defect `2c85750` claimed to
eliminate, still present in the same file it edited.
**Do:** move to the product seam exactly as `2c85750` did for the payload stub.
**Prove:** Check B passes; the export gate still goes red under sabotage.

### 5. Fix the sentinel collision (do this with item 4)
`tests/test_web_dashboard.py:26` emits `GATE_DASHBOARD_ALERTS_TOTAL` on a
**connection** failure, while the payload gate uses that same sentinel to prove
the failure was *not* a connection error. They cannot both fire today, but the
payload gate inherits ambient env via `os.environ.copy()` — export
`SECURE_STUB_DASHBOARD_SERVER_BREAK` in a shell and the payload gate goes green
for the wrong reason.
**Do:** give the connection-failure path a distinct sentinel.
**Prove:** with both stubs set, the payload gate must not report a false green.

### 6. Relabel the four SIEM unit tests
Four of the five "gates" never spawn a subprocess — they are in-process
`unittest.mock.patch` tests (file contains 1 `subprocess.run`, 2 `patch(`).
They are decent tests of `send_alert` error handling; they are not gates.
**Do:** move to `tests/test_siem_integration.py` or a clearly-named file. Stop
counting them as mutation gates.
**Prove:** gate count reflects only real gates.

### 7. Replace the 10 hardcoded absolute paths
`cwd="/Users/erickvale/Projects/secure-resource"` × 10 across the four gate
files. This project was relocated off `~/Desktop` recently; `secure_monitor.sh`
already needed fixing for the same reason.
**Do:** `REPO_ROOT = Path(__file__).resolve().parents[2]`.
**Prove:** Check D passes.

### 8. Add the meta-test
Create `tests/test_mutation_gate_meta.py` implementing Checks A–D plus the
structural `returncode != 0` rule (see next section).
**Note:** it must itself obey `TESTING_POLICY.md` Rule 3 — module-level
`def test_*`, no class — and the filename must match the naming convention so
the TARGETED tier actually selects it.
**Prove:** it flags every defect in this work order before the fixes, and passes
after.

### 9. Delete the dead stub read
`tests/integration/test_phase2_approval.py:28` — `bypass = os.environ.get(...)`
assigned and never used. The real injection is correctly in
`secure/remediation/executor.py:120`, so gate2 is genuine; this dead line just
looks like the defect and will confuse Check B.

### 10. Reconcile with `TESTING_POLICY.md`
Rule 3 forbids test classes and `conftest.py`. All six gate files use
`class Test...`, and `tests/integration/conftest.py` exists (43 lines).
This is **not cosmetic**: `targeted_test_files()` in `secure/agent/tiers.py`
maps `secure/<package>/*.py` → `tests/test_<package>*.py`. Files at
`tests/integration/test_*_mutation_gates.py` never match, so the TARGETED tier
never selects them. Combined with the 8 GB constraint making the full suite
unrunnable, **these gates run only when invoked by hand.** Guards that nothing
runs automatically are not guards.
**Do:** conform to Rule 3, or amend the policy deliberately — and state how the
gate suite gets run automatically.

### 11. Move `SECURE_STUB_PERSISTENCE_LATENCY` into product
Per the ruling above. `tests/integration/fixtures.py:199` short-circuits ahead of
the real `scan_persistence` call.
**Do:** inject the latency in product, or delete gate1's claim to test scanner
latency.
**Prove:** gate1 fails when product scanning is genuinely slow.

### 12. Sabotage-test every gate, individually
For each surviving gate: break the thing it guards, capture the gate going
**red**, restore, capture it going **green**. Submit both outputs verbatim per
gate.
**A gate with no sabotage proof is not cleared.** This is the only check that
caught the one real gate in the original submission.

---

## The mechanical check, explained

### Why mechanical and not discipline

Commit `2c85750` *was* the discipline-based fix. It correctly moved one stub into
the product and left two identical instances in place — **in the same file, in
the same commit.** Discipline failed at the narrowest possible scope, under
direct attention, immediately after the rule was articulated.

Compounding it: the model authoring these gates cannot reliably audit a tautology
it just wrote. A check that runs outside the authoring loop closes that gap.

All four checks are static AST/grep. No subprocesses. Sub-second.

### Check A — every gate function contains an `assert` or `raise`
Catches the empty gate (item 1).
```
FAIL tests/integration/test_siem_mutation_gates.py::test_gate_siem_http_failure_detection
```

### Check B — every `SECURE_STUB_*` set by a gate must be read in product
Catches items 3, 4 and 11 in one rule. This is the mechanisation of
"fault injection belongs in the product."
```
SECURE_STUB_APPROVAL_BYPASS:        OK  secure/remediation/executor.py:120
SECURE_STUB_DASHBOARD_ALERTS_WRONG: OK  secure/web/app.py:274
SECURE_STUB_PERSISTENCE_LATENCY:    VIOLATION (fixture, not product)
SECURE_STUB_DASHBOARD_SERVER_BREAK: VIOLATION (read in test under gate)
SECURE_STUB_SIEM_HTTP_BREAK:        VIOLATION (no reader anywhere)
SECURE_STUB_SIEM_TRANSPORT_BREAK:   VIOLATION (no reader anywhere)
```
Per the product-only ruling, the fixture allowlist is **not** applied.

### Check C — no dead sentinels
Any `GATE*` literal used as the left operand of an `in` comparison (i.e.
*searched for* in subprocess stdout) must be emitted somewhere outside the gate
file. Must distinguish searched-for sentinels from the gate's own failure-message
strings, or it over-flags.
```
searches GATE_AUTOMATION_ENGINE_SIEM  DEAD (nothing emits it)
searches GATE_DASHBOARD_ALERTS_TOTAL  OK -> tests/test_web_dashboard.py
searches GATE1_SCANNER_LATENCY        OK -> tests/integration/test_sensor_ground_truth.py
searches GATE2_APPROVAL_PENDING       OK -> tests/integration/test_phase2_approval.py
```
B and C compose usefully: C confirms the dashboard sentinel *is* emitted; B
reveals the emitter is the illegitimate in-test stub.

### Check D — no `cwd="/absolute"`
Flags all 10 (item 7).

### Structural rule — a gate must assert `returncode != 0`
Flags both automation gates and all four mislabeled SIEM tests immediately.
Also ban top-level `or` in a gate's assertion: an `or` is how "accepts both
outcomes" gets written.

### What the check cannot catch
Two classes stay human/Opus judgment:
- **A gate whose assertion accepts both outcomes.** Syntactically it *has* an
  assert. The `returncode != 0` rule plus the `or` ban is the best mechanical
  proxy, but it is a proxy.
- **A unit test mislabeled as a gate.** Partially addressable by requiring gates
  to contain a `subprocess.run` and live in a named file.

This is why item 12 (per-gate sabotage proof) is not optional. The checks raise
the floor; sabotage is what actually certifies a gate.

---

## Operator decisions required before the next phase

These are not engineering choices and must not be resolved by inference.

1. **Canonical phase numbering.** "Phase 63" has three conflicting definitions:
   Web Dashboard (`HANDOFF.md:126`), email notification work
   (`STATE-HANDOFF-2026-09-24.md:103`), and a deleted "Phase 63 Email
   Notifications ✅" (`CATCH-UP.md:43`, removed by `c5d5e14`). It has already
   been claimed complete once, for different work. Commit `657876e` labels itself
   "Phase 64-65" while being submitted under Phase 63.

2. **Where acceptance criteria live.** **There is no `BUILD_PLAN.md`** — verified
   absent. Phase 63 therefore has no written definition of done, which is the
   root of question 1. Per CLAUDE.md the acceptance-gate trigger is inactive
   without it.

3. **How phases get verified on 8 GB.** `TESTING_POLICY.md` Rule 11 requires the
   whole suite to report 0 failed / 0 errors. That is currently unsatisfiable on
   this host — the suite has twice taken the machine down at ~6.6 GB. The
   policy's own verification condition cannot be met, so either the policy or the
   verification method must change.

---

## Definition of done for re-submission

- All 12 items complete.
- Meta-test present, passing, and selected by the TARGETED tier.
- Per-gate sabotage evidence, red and green, verbatim.
- A statement of how many real mutation gates now exist, and what each guards.
- Operator decisions 1–3 recorded.

Re-submit the **same phase**. Do not argue it forward.
