"""Web dashboard API — Phase 63. Uses only stdlib, no Flask required."""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from secure.feedback.store import FeedbackStore
from secure.storage.alerting_schema import init_alerting_schema
from secure.feedback.schema import init_feedback_schema


HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure Monitor Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; }
        .header { background: #1a1a1a; color: white; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .container { max-width: 1200px; margin: 20px auto; padding: 0 20px; }
        .controls { background: white; padding: 15px; margin-bottom: 20px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .controls button { background: #007bff; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin-right: 10px; }
        .controls button:hover { background: #0056b3; }
        .alerts-container { background: white; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .alert-item { padding: 15px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .alert-item:last-child { border-bottom: none; }
        .alert-header { flex: 1; }
        .alert-title { font-weight: bold; margin-bottom: 5px; }
        .alert-meta { font-size: 12px; color: #666; }
        .severity-CRITICAL { color: #d32f2f; }
        .severity-HIGH { color: #f57c00; }
        .severity-MEDIUM { color: #fbc02d; }
        .severity-LOW { color: #388e3c; }
        .alert-actions { display: flex; gap: 10px; }
        .btn-sm { padding: 4px 8px; font-size: 12px; border: 1px solid #ddd; background: white; cursor: pointer; border-radius: 3px; }
        .btn-sm:hover { background: #f5f5f5; }
        .feedback-form { display: none; padding: 10px; background: #f9f9f9; border-radius: 3px; margin-top: 10px; }
        .feedback-form.open { display: block; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }
        .stat-value { font-size: 28px; font-weight: bold; color: #007bff; }
        .stat-label { font-size: 12px; color: #666; margin-top: 5px; }
        input, select, textarea { padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 12px; }
        textarea { resize: vertical; min-height: 60px; width: 100%; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Secure Monitor Dashboard</h1>
    </div>
    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value" id="total-alerts">—</div>
                <div class="stat-label">Total Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="critical-count">—</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="fp-rate">—</div>
                <div class="stat-label">False Positive Rate</div>
            </div>
        </div>

        <div class="controls">
            <button onclick="loadAlerts()">Refresh</button>
            <button onclick="exportJSON()">Export JSON</button>
            <button onclick="exportCSV()">Export CSV</button>
            <select id="severity-filter" onchange="loadAlerts()">
                <option value="">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
            </select>
            <select id="verdict-filter" onchange="loadAlerts()">
                <option value="">All Verdicts</option>
                <option value="ACTIVE">Active</option>
                <option value="SUPPRESSED_EXPECTED">Suppressed</option>
                <option value="DOWNGRADED_EXPECTED">Downgraded</option>
            </select>
        </div>

        <div class="alerts-container" id="alerts-list"></div>
    </div>

    <script>
        async function loadAlerts() {
            const severity = document.getElementById('severity-filter').value;
            const verdict = document.getElementById('verdict-filter').value;
            const params = new URLSearchParams();
            if (severity) params.append('severity', severity);
            if (verdict) params.append('verdict', verdict);

            const resp = await fetch(`/api/alerts?${params}`);
            const data = await resp.json();

            document.getElementById('total-alerts').textContent = data.total;
            document.getElementById('critical-count').textContent = data.critical_count;
            document.getElementById('fp-rate').textContent = data.fp_rate || '—';

            const container = document.getElementById('alerts-list');
            if (data.alerts.length === 0) {
                container.innerHTML = '<div style="padding: 20px; text-align: center; color: #999;">No alerts</div>';
                return;
            }

            container.innerHTML = data.alerts.map(alert => `
                <div class="alert-item">
                    <div class="alert-header">
                        <div class="alert-title">
                            <span class="severity-${alert.final_severity}">${alert.final_severity}</span>
                            ${alert.entity_type}
                        </div>
                        <div class="alert-meta">
                            ID: ${alert.id} | ${alert.entity_path || 'unknown'} | ${alert.verdict}
                        </div>
                        <div class="alert-meta">${new Date(alert.created_at).toLocaleString()}</div>
                    </div>
                    <div class="alert-actions">
                        <button class="btn-sm" onclick="toggleFeedbackForm(${alert.id})">Mark FP</button>
                    </div>
                    <div id="feedback-${alert.id}" class="feedback-form">
                        <textarea id="reason-${alert.id}" placeholder="Why is this a false positive?"></textarea>
                        <br><br>
                        <button class="btn-sm" onclick="submitFeedback(${alert.id})">Submit</button>
                        <button class="btn-sm" onclick="toggleFeedbackForm(${alert.id})">Cancel</button>
                    </div>
                </div>
            `).join('');
        }

        function toggleFeedbackForm(alertId) {
            const form = document.getElementById(`feedback-${alertId}`);
            form.classList.toggle('open');
        }

        async function submitFeedback(alertId) {
            const reason = document.getElementById(`reason-${alertId}`).value;
            const resp = await fetch('/api/feedback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ decision_id: alertId, verdict: 'false_positive', reason })
            });
            if (resp.ok) {
                toggleFeedbackForm(alertId);
                loadAlerts();
            } else {
                alert('Error submitting feedback');
            }
        }

        async function exportJSON() {
            const resp = await fetch('/api/export?format=json');
            const blob = await resp.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `alerts_${new Date().toISOString().split('T')[0]}.json`;
            a.click();
        }

        async function exportCSV() {
            const resp = await fetch('/api/export?format=csv');
            const blob = await resp.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `alerts_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
        }

        loadAlerts();
        setInterval(loadAlerts, 30000);  // Refresh every 30s
    </script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for dashboard server."""

    db_path = None

    def get_conn(self):
        """Get database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        init_alerting_schema(conn)
        init_feedback_schema(conn)
        return conn

    def do_GET(self):
        """Handle GET requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)

        if path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode())

        elif path == "/api/alerts":
            severity = query_params.get("severity", [None])[0]
            verdict = query_params.get("verdict", [None])[0]
            limit = int(query_params.get("limit", [100])[0])
            offset = int(query_params.get("offset", [0])[0])

            conn = self.get_conn()
            query = "SELECT * FROM alert_decisions WHERE 1=1"
            params = []

            if severity:
                query += " AND final_severity = ?"
                params.append(severity)
            if verdict:
                query += " AND verdict = ?"
                params.append(verdict)

            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = conn.execute(query, params).fetchall()
            total = conn.execute("SELECT COUNT(*) FROM alert_decisions").fetchone()[0]
            critical_count = conn.execute(
                "SELECT COUNT(*) FROM alert_decisions WHERE final_severity = 'CRITICAL'"
            ).fetchone()[0]

            fp_rate = "—"
            try:
                store = FeedbackStore(conn)
                stats = store.get_feedback_stats()
                if stats:
                    fp_rate = f"{stats.false_positives}/{stats.total_feedback}"
            except Exception:
                pass

            response_data = {
                "total": total,
                "critical_count": critical_count,
                "fp_rate": fp_rate,
                "alerts": [
                    {
                        "id": dict(row)["id"],
                        "source_table": dict(row)["source_table"],
                        "entity_type": dict(row)["entity_type"],
                        "entity_path": dict(row)["entity_path"],
                        "base_severity": dict(row)["base_severity"],
                        "final_severity": dict(row)["final_severity"],
                        "verdict": dict(row)["verdict"],
                        "created_at": dict(row)["created_at"],
                        "evaluated_at": dict(row)["evaluated_at"],
                    }
                    for row in rows
                ],
            }

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode())
            conn.close()

        elif path == "/api/export":
            fmt = query_params.get("format", ["json"])[0]
            conn = self.get_conn()
            rows = conn.execute(
                "SELECT * FROM alert_decisions ORDER BY created_at DESC"
            ).fetchall()

            if fmt == "json":
                data = {"alerts": [dict(row) for row in rows]}
                response_json = json.dumps(data, indent=2, default=str)
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=alerts_{datetime.now().strftime('%Y%m%d')}.json",
                )
                self.end_headers()
                self.wfile.write(response_json.encode())

            elif fmt == "csv":
                output = io.StringIO()
                if rows:
                    fieldnames = list(dict(rows[0]).keys())
                    writer = csv.DictWriter(output, fieldnames=fieldnames)
                    writer.writeheader()
                    for row in rows:
                        writer.writerow(dict(row))

                self.send_response(200)
                self.send_header("Content-type", "text/csv")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=alerts_{datetime.now().strftime('%Y%m%d')}.csv",
                )
                self.end_headers()
                self.wfile.write(output.getvalue().encode())

            else:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid format"}).encode())

            conn.close()

        else:
            self.send_response(404)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not found"}).encode())

    def do_POST(self):
        """Handle POST requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == "/api/feedback":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body.decode())

            decision_id = data.get("decision_id")
            verdict = data.get("verdict")
            reason = data.get("reason", "")

            if not decision_id or verdict not in ("true_positive", "false_positive", "unclear"):
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid input"}).encode())
                return

            conn = self.get_conn()
            store = FeedbackStore(conn)
            feedback_id = store.record_feedback(
                decision_id=decision_id,
                verdict=verdict,
                reason=reason,
                feedback_by="dashboard",
            )

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({"feedback_id": feedback_id, "status": "ok"}).encode()
            )
            conn.close()

        else:
            self.send_response(404)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not found"}).encode())

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


def run_server(host: str = "127.0.0.1", port: int = 5000, db_path: str = None):
    """Run dashboard server."""
    if db_path is None:
        db_path = f"{Path.home()}/.secure/secure.db"

    DashboardHandler.db_path = db_path
    server = HTTPServer((host, port), DashboardHandler)
    print(f"Dashboard: http://{host}:{port}", file=sys.stderr)
    print(f"Database: {db_path}", file=sys.stderr)
    print("Press Ctrl+C to stop", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped", file=sys.stderr)
        server.shutdown()
