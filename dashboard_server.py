#!/usr/bin/env python3
"""
Dashboard server for Secure.

Serves an interactive web dashboard for security monitoring. The dashboard
displays system health, active findings, sensor status, and recent activity.

Usage:
    python3 dashboard_server.py [--port 8765]

Open http://127.0.0.1:8765 in your browser (or the specified port).
"""

import http.server
import socketserver
import argparse
import json
import sys
from pathlib import Path

PORT = 8765


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler for the dashboard."""

    def do_GET(self):
        """Serve dashboard HTML or API endpoints."""
        if self.path == '/':
            self.path = '/dashboard.html'

        if self.path.endswith('.json'):
            # Future: API endpoints for dynamic data
            self.send_response(404)
            self.end_headers()
            return

        # Serve static files
        super().do_GET()

    def end_headers(self):
        """Add cache headers."""
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()


def run_server(port):
    """Run the dashboard server."""
    repo_root = Path(__file__).resolve().parent

    # Change to repo directory so static files are found
    import os
    os.chdir(repo_root)

    handler = DashboardHandler
    with socketserver.TCPServer(('127.0.0.1', port), handler) as httpd:
        print(f'Dashboard server running at http://127.0.0.1:{port}')
        print('Press Ctrl+C to stop.')
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print('\nShutting down…')
            sys.exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Secure dashboard server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Example:\n  python3 dashboard_server.py --port 8765',
    )
    parser.add_argument('--port', type=int, default=PORT, help=f'Port to serve on (default: {PORT})')
    args = parser.parse_args()

    run_server(args.port)
