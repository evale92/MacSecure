"""
secure/dfir/ — Phase 24: Targeted DFIR Integration.

Velociraptor is Secure's specialist forensic collection engine, wired
in where practical — never a DFIR framework Secure reimplements itself.
Four hard rules, matching the phase's own explicit instruction:

    1. Never auto-triggered. Nothing in this package runs a collection
       on its own — not from `secure run-all`, not from any scan, not
       from a low-confidence finding. `secure/dfir/suggest.py` may
       PROPOSE a candidate artifact; only an explicit
       `secure dfir collect` invocation ever executes one. That
       explicit invocation, with its exact artifact name, parameters,
       and stated reason, IS the "user-approved collection" step named
       in the instruction's own pipeline — the same "one deliberate CLI
       command is the whole trigger" discipline `secure threatintel
       lookup` (Phase 20) and `secure correlate chains run` (Phase 22)
       already established, not a new ceremony invented for this phase.

    2. Reuse secure/integrations/base.py's STATUS_OK/DEGRADED/
       UNAVAILABLE/ERROR vocabulary directly — never a second health
       vocabulary invented for Velociraptor specifically. A collection
       is either a normal external-tool health outcome or it isn't.

    3. Failure means unavailable, never exculpatory. A collection that
       couldn't run, or that failed partway, is recorded as
       UNAVAILABLE/ERROR/DEGRADED and must never be read anywhere —
       by this package, by secure/investigate/, or by a caller — as
       "ran cleanly and found nothing." Zero forensic_evidence_items
       rows attached to a failed collection means "we don't know," not
       "clean."

    4. Every artifact name is checked against `AppConfig.
       dfir_artifact_allowlist` BEFORE any subprocess is ever started
       — the concrete safety rail behind "narrowly scoped... based on
       an investigation," not just a documented convention. An
       artifact outside the allowlist is refused; no
       forensic_collections row is ever written for a refused request
       — it simply never happened.

Preserved end to end, per the instruction's own explicit requirement:
artifact name, collection parameters, every relevant timestamp
(requested/started/completed), Velociraptor's own tool version, and
exact provenance (the EntityRef this collection is about, and the
specific finding — if any — that motivated it) — see
secure/storage/models/dfir.py's ForensicCollectionRecord.
"""
