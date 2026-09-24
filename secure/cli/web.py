"""Web dashboard CLI command (Phase 63)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secure.web.app import run_server


def cmd_web_start(args: argparse.Namespace) -> int:
    """Start the web dashboard server."""
    db_path = args.db or f"{Path.home()}/.secure/secure.db"
    host = args.host or "127.0.0.1"
    port = args.port or 5000

    print(f"Starting Secure Monitor dashboard on {host}:{port}")
    print(f"Database: {db_path}")
    print("Press Ctrl+C to stop")

    try:
        run_server(host=host, port=port, db_path=db_path)
    except KeyboardInterrupt:
        print("\nDashboard stopped")
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    return 0
