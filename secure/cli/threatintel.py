"""
cli/threatintel.py — `secure threatintel ...` (Phase 20): the
provider-neutral threat-intelligence enrichment layer's CLI surface.

`lookup` is the ONLY command in this whole app that can make a real
external network request on the user's behalf for an arbitrary
indicator — see secure/threatintel/enrich.py's module docstring for why
that's deliberately never triggered implicitly (e.g. just from viewing
an alert's explanation). `history`/`providers` are read-only.
"""

from __future__ import annotations

import argparse

from secure.cli import _bootstrap, logger
from secure.storage.database import Database
from secure.storage.models import list_threat_intel_lookups
from secure.threatintel.enrich import enrich_indicator
from secure.threatintel.indicators import INDICATOR_TYPES, classify_indicator
from secure.threatintel.registry import build_providers


def cmd_threatintel_lookup(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    indicator_type = args.type
    if indicator_type == "auto":
        detected = classify_indicator(args.value)
        if detected is None:
            print(
                f"Could not classify {args.value!r} as an ip/domain/hash. "
                f"Pass --type explicitly: one of {', '.join(INDICATOR_TYPES)}."
            )
            return 1
        indicator_type = detected
        print(f"Detected indicator type: {indicator_type}")

    with Database(cfg.database_path()) as db:
        result = enrich_indicator(db.conn, cfg, indicator_type, args.value)

    print(f"Threat-intelligence lookup: {result.indicator_type} {result.indicator_value}")
    for enriched in result.lookups:
        r = enriched.result
        cache_note = " (from cache)" if enriched.from_cache else ""
        print(f"\n  Provider: {r.provider}{cache_note}")
        print(f"    status:  {r.status.upper()}")
        if r.verdict is not None:
            print(f"    verdict: {r.verdict}")
        if r.score is not None:
            print(f"    score:   {r.score} ({r.score_meaning})")
        if r.categories:
            print(f"    categories: {', '.join(r.categories)}")
        print(f"    detail:  {r.detail}")
        if r.expires_at:
            print(f"    cache expires: {r.expires_at}")

    logger.info(
        "Ran a threat-intelligence lookup",
        extra={"event": "threatintel_lookup", "component": "cli"},
    )
    return 1 if (result.any_malicious or result.any_suspicious) else 0


def cmd_threatintel_history(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    with Database(cfg.database_path()) as db:
        lookups = list_threat_intel_lookups(
            db.conn, indicator_type=args.type, indicator_value=args.value,
            provider=args.provider, limit=args.limit,
        )

    if not lookups:
        print("No threat-intelligence lookups recorded yet. Run: secure threatintel lookup <type> <value>")
        return 0

    for record in lookups:
        print(
            f"#{record.id:<5} [{record.indicator_type}] {record.indicator_value} "
            f"via {record.provider} — {record.status.upper()}"
            + (f" ({record.verdict})" if record.verdict else "")
            + f" — {record.created_at}"
        )
        if record.detail:
            print(f"          {record.detail}")

    return 0


def cmd_threatintel_providers(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    providers = build_providers(cfg)
    print("Registered threat-intelligence providers:")
    for provider in providers:
        identity = provider.identity
        scope = "network" if identity.network else "local (no outbound calls)"
        print(f"  - {identity.name} ({scope}, schema v{identity.schema_version})")

    return 0
