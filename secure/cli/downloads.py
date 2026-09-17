from __future__ import annotations

import argparse
from datetime import datetime

from secure.cli import _bootstrap, logger
from secure.downloads import download_history
from secure.downloads.history import COVERAGE_NOTE


def cmd_downloads(args: argparse.Namespace) -> int:
    _bootstrap()
    report = download_history(days=args.days, limit=args.limit)

    if report.status != "OK":
        print(f"UNAVAILABLE: could not read the macOS download history ({report.reason}).")
        print("This is not the same as 'nothing was downloaded'.")
        logger.warning("Download history unavailable", extra={"event": "downloads_unavailable", "component": "cli"})
        return 1

    shown = report.flagged if args.flagged else report.events
    print(f"Downloads recorded in the last {report.days} day(s): {len(report.events)}"
          f"{' (limit reached, older ones not shown)' if report.truncated else ''}; "
          f"flagged: {len(report.flagged)}")
    print(COVERAGE_NOTE)
    print()
    for item in shown:
        e = item.event
        when = datetime.fromtimestamp(e.timestamp).strftime("%Y-%m-%d %H:%M") if e.timestamp else "unknown time"
        tag = f" [{', '.join(item.flags)}]" if item.flags else ""
        print(f"{when}  {e.agent_name or e.agent_bundle_id or 'unknown app'}{tag}")
        if e.data_url:
            print(f"    file:   {e.data_url}")
        if e.origin_url:
            print(f"    from:   {e.origin_url}")
    logger.info("Listed download history", extra={"event": "downloads_listed", "component": "cli"})
    return 0
