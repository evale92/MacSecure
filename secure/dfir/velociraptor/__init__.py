"""
secure/dfir/velociraptor/ — the Velociraptor-specific half of Phase 24.
Velociraptor's own local/offline collector mode is what this talks to
(no server deployment required — see PROJECT_NOTES.md's Phase 24 change
log entry for why that mode was chosen): a single subprocess call per
collection, never a managed daemon Secure starts or supervises.

    _shell.py       — the only file that runs a subprocess. A thin
                      wrapper, same shape as
                      secure/integrations/suricata/_shell.py.
    availability.py — whether the `velociraptor` binary is usable right
                      now, and its version — same STATUS_OK/DEGRADED/
                      UNAVAILABLE/ERROR discipline every other
                      integration's own availability.py already uses.
    collect.py       — runs exactly one artifact collection and returns
                      its outcome. Never called directly by a scan or
                      by run-all — only by secure/dfir/collector.py's
                      explicit, user-approved orchestration.
    parser.py        — reshapes Velociraptor's own JSONL result output
                      into plain row dicts. Knows nothing about what any
                      artifact's columns MEAN — same "reshape, don't
                      interpret" discipline as
                      secure/integrations/base.py's ExternalObservation.

Honesty note (see docs/DFIR.md): the exact `velociraptor` CLI
invocation used here (subcommand and flags) is this integration's own
best-effort reading of Velociraptor's documented offline-collector
usage, written without a live Velociraptor install available to
validate against in this sandbox — collect.py isolates that one
invocation behind a small, dependency-injectable surface specifically
so it can be corrected without touching any caller, the same
reasoning secure/integrations/osquery/_shell.py already documents for
its own binary-invocation boundary.
"""
