"""
secure/detect/ — Phase 25: Detection Engineering Workbench.

A coherent lifecycle for the detection rules Secure already evaluates
or observes across four families — Sigma, YARA-X, Suricata, and
Secure's own correlation engines — WITHOUT inventing a fifth, universal
rule language. Two hard rules, matching the phase's own explicit
instruction:

    1. Never a second rule language. Every family keeps its own native
       format, loader, and evaluator, entirely unchanged by this
       package: secure/integrations/sigma/ still owns Sigma YAML and
       its condition grammar; secure/integrations/yarax/ still owns
       .yar/.yara files and yara_x itself; secure/integrations/
       suricata/ still owns nothing of Suricata's rule content at all
       (Secure never loads it — see below); secure/correlate/ still
       owns its own two scoring algorithms. secure/detect/ only
       DISCOVERS what each family's own existing loader already knows
       how to find, and CATALOGS identity/version/enabled-state/
       telemetry/validation on top — never rule CONTENT.

    2. Orchestrate cleanly, don't reimplement. Every capability check,
       every evaluation, every severity judgment stays exactly where
       it already lives (secure/integrations/sigma/capability.py's
       check_capability(), each family's own check_availability(),
       secure/correlate/chains.py's score_chain(), ...). This package
       calls into those, never duplicates their logic.

The four families are NOT symmetric, and this package is honest about
that rather than forcing a uniform shape where none exists:

    - Sigma tracks identity per RULE (rule_id, one rule per file).
    - YARA-X tracks identity per RULESET FILE — the only granularity
      anything in this codebase can already compile/enable/version at
      today; an individual named rule inside a file only becomes
      visible after it actually matches something (see
      docs/DETECTION_ENGINEERING.md for the full reasoning, approved
      explicitly rather than assumed).
    - Suricata signatures are NEVER loaded or parsed by Secure at all
      — Suricata's own engine and rule files are entirely external.
      This package can only catalog a signature AFTER it has fired at
      least once, passively, from Suricata's own EVE JSON alert
      output. There is no way to enumerate "signatures Suricata could
      fire" — only "signatures we've observed fire."
    - Secure's own correlation logic isn't itemized rules at all — it
      is two deterministic algorithms (secure/correlate/analysis.py's
      temporal clustering, secure/correlate/chains.py's provenance-
      aware chain scoring). This package registers exactly those two,
      as static, always-present entries — never invents finer-grained
      "rules" where the underlying code has none.

`enabled` is REAL enforcement for sigma/yarax only (per explicit
approval): secure/integrations/sigma/scanner.py and .../yarax/
scanner.py consult this package's registry and skip a disabled rule/
ruleset before it is ever evaluated. Default state is enabled, so with
nothing disabled, scan output is unchanged from before this phase
existed. For suricata (Secure doesn't control Suricata's own engine)
and correlate (disabling a whole scoring algorithm is a bigger, later
decision), `enabled` is tracking-only — never consulted by any
scanner.
"""
