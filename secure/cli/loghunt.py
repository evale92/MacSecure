from __future__ import annotations

import argparse

from secure.cli import _bootstrap, logger
from secure.loghunt import run_hunts


def cmd_loghunt(args: argparse.Namespace) -> int:
    _bootstrap()
    try:
        results = run_hunts(hours=args.hours, names=args.hunt)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    failed = 0
    for r in results:
        if r.status != "OK":
            failed += 1
            print(f"{r.name}: {r.status} — {r.detail}")
            print("    This is not the same as no events.")
            continue
        print(f"{r.name}: {r.total} event(s) in the last {args.hours}h — {r.meaning}")
        for t in r.templates:
            print(f"    {t['count']:6}  {t['template']}")
            print(f"            first {t['first']}  last {t['last']}")
            if t["example"]:
                print(f"            e.g. {t['example']}")
    print()
    print("A zero means the fixed predicate matched nothing in the window. Predicates were measured on "
          "macOS 26 (2026-09-16); on another version a zero can also mean Apple renamed the subsystem.")
    logger.info("Ran unified log hunts", extra={"event": "loghunt", "component": "cli"})
    return 1 if failed else 0
