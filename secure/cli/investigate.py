"""
secure/cli/investigate.py — Phase 23 Stage 5: the CLI front end for
secure/investigate/. Thin on purpose — every real decision (what an
entity is, how to resolve it, what's on its timeline, what it pivots
to, what a linked alert means) already lives in secure/investigate/ and
secure/explain/; this module only formats and prints. Read-only, same
as everything it calls.
"""

from __future__ import annotations

import argparse

from secure.investigate.entity import ENTITY_TYPES, EntityRef
from secure.investigate.view import explain_observation, investigate
from secure.storage.database import Database
from secure.cli import _bootstrap, logger

# One short line per entity_type describing how its entity_key is built
# — an operator has to type this by hand (there is no free-text search
# yet; see PROJECT_NOTES.md's own Phase 23 scope notes), so `secure
# investigate types` needs to actually explain the shape, not just name
# it. Kept here, not in secure/investigate/entity.py, since this is
# CLI-presentation text, not part of the pure entity model.
_ENTITY_KEY_HELP = {
    "inventory": "mac address, or ip if no mac is known",
    "process": "the executable's full path, e.g. /usr/bin/curl",
    "process_destination": "process_name::remote_addr:remote_port/proto, e.g. curl::203.0.113.5:443/tcp "
    "((unknown)::... when the process wasn't attributed)",
    "listening": "process_name:identity_port/proto, e.g. sshd:22/tcp",
    "wifi": "the SSID",
    "bluetooth": "the Bluetooth device address",
    "ble": "the CoreBluetooth peripheral UUID (rotates — see docs/BASELINING.md)",
    "persistence": "kind::path (or kind::label with no path), e.g. launch_agent::/x.plist",
    "file_watch_path": "the watch path's numeric id, from `secure fileintegrity watch-list`",
    "dns_query": "the queried domain",
    "tls_sni": "the TLS SNI hostname",
    "destination": "remote_addr:remote_port/proto, e.g. 203.0.113.5:443/tcp",
    "file": "the monitored file's full path",
    "indicator": "type:value, e.g. hash:<sha256>, ip:203.0.113.5, domain:example.com",
}


def cmd_investigate_types(args: argparse.Namespace) -> int:
    print("Entity types `secure investigate show` accepts, and how to build their key:\n")
    for entity_type in ENTITY_TYPES:
        print(f"  {entity_type:20} {_ENTITY_KEY_HELP.get(entity_type, '')}")
    return 0


def cmd_investigate_show(args: argparse.Namespace) -> int:
    cfg = _bootstrap()

    try:
        entity = EntityRef(entity_type=args.entity_type, entity_key=args.entity_key)
    except ValueError as exc:
        print(f"Invalid entity: {exc}")
        print("Run `secure investigate types` to see valid entity types and key formats.")
        return 1

    with Database(cfg.database_path()) as db:
        view = investigate(db.conn, entity, max_hops=args.max_hops)

        if not view.exists:
            print(f"No {entity.entity_type} entity found for key {entity.entity_key!r}.")
            return 1

        print(f"Entity: {entity}")
        print()
        print("Summary:")
        for key, value in view.summary.items():
            print(f"  {key}: {value}")

        print()
        print(f"Timeline ({len(view.timeline.events)} event(s)):")
        for event in view.timeline.events:
            marker = "* " if event.is_anchor else "  "
            when = event.timestamp.isoformat() if event.timestamp else "(no timestamp on record)"
            print(f"  {marker}{when}  {event.source_table}#{event.source_id}  (hop {event.hops_from_entity})")

        print()
        print(f"Related evidence ({sum(len(g.observations) for g in view.related.groups)} row(s)):")
        for group in view.related.groups:
            print(f"  {group.hops} hop(s) away:")
            for ref in group.observations:
                exp = explain_observation(db.conn, ref)
                if exp is not None:
                    print(f"    {ref.source_table}#{ref.source_id} — [{exp.severity.upper()}] {exp.summary}")
                else:
                    print(f"    {ref.source_table}#{ref.source_id}")

        print()
        print(f"Pivots ({len(view.pivots)}):")
        for pivot in view.pivots:
            print(f"  {pivot.entity} — {pivot.reason}")
        if not view.pivots:
            print("  (none found)")

    logger.info(
        "Ran an investigation",
        extra={"event": "investigate_show", "component": "cli"},
    )
    return 0
