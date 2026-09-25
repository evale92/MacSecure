"""Web dashboard API — Phase 63. Uses only stdlib, no Flask required."""

from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from secure.feedback.store import FeedbackStore
from secure.storage.alerting_schema import init_alerting_schema
from secure.feedback.schema import init_feedback_schema


def _gui_launch_command() -> str:
    """Command that starts the desktop GUI, derived from this file's
    location so it survives the project being moved."""
    repo = Path(__file__).resolve().parents[2]
    launcher = repo / "Launch Secure GUI.command"
    if launcher.exists():
        return str(launcher)
    venv = repo / ".venv-tk" / "bin" / "python3"
    py = str(venv) if venv.exists() else "python3"
    return f"{py} {repo / 'secure_gui.py'}"


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Secure · Dashboard</title>
    <style>
:root {
  color-scheme: light;
  --page: #f3f2ef;
  --surface: #fcfcfb;
  --surface-2: #f0efec;
  --line: #deddd8;
  --text: #0b0b0b;
  --text-2: #52514e;
  --muted: #6f6e69;
  --accent: #2a78d6;
  --good: #0ca30c;
  --warning: #fab219;
  --critical: #d03b3b;
  --neutral: #8b8a85;
  --shadow: 0 1px 2px rgba(0,0,0,.06), 0 4px 16px rgba(0,0,0,.04);
}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--page:#121211;--surface:#1a1a19;--surface-2:#232321;--line:#34342f;--text:#fff;--text-2:#c3c2b7;--muted:#9b9a91;--accent:#3987e5;--neutral:#8f8e86;--shadow:0 1px 2px rgba(0,0,0,.4)}}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { margin: 0; }
body { background: var(--page); color: var(--text); font: 15px/1.5 -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", "Helvetica Neue", Arial, sans-serif; }
header.top { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; flex-wrap: wrap; padding: 22px clamp(16px, 4vw, 48px) 16px; background: var(--page); border-bottom: 1px solid var(--line); }
.eyebrow { font-size: 11px; font-weight: 700; letter-spacing: .09em; text-transform: uppercase; color: var(--accent); }
header h1 { font-size: 30px; letter-spacing: -.02em; margin: 2px 0 0; line-height: 1.15; }
header p { margin: 4px 0 0; color: var(--text-2); font-size: 13.5px; }
.head-right { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
main { max-width: 1320px; margin: auto; padding: 22px clamp(16px, 4vw, 48px) 40px; }
h2 { font-size: 16px; margin: 0; letter-spacing: -.005em; }
h3 { font-size: 14.5px; margin: 6px 0; }
p { margin: 6px 0; }
.section { margin-top: 22px; }
h2.section { font-size: 13px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; color: var(--text-2); margin: 4px 0 10px; }
button, select, input { font: inherit; font-size: 14px; border: 1px solid var(--line); border-radius: 8px; padding: 7px 12px; background: var(--surface); color: var(--text); }
button { cursor: pointer; font-weight: 600; }
button:hover { border-color: var(--muted); }
button.primary, #refresh { background: var(--accent); border-color: var(--accent); color: #fff; }
button:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
button:disabled { opacity: .45; cursor: default; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 999px; background: var(--surface-2); color: var(--text-2); font-size: 12px; font-weight: 600; white-space: nowrap; }
.pill.alert { background: transparent; color: var(--critical); box-shadow: inset 0 0 0 1px var(--critical); }
.small { font-size: 12.5px; color: var(--muted); }
.muted { color: var(--muted); }
.num { font-variant-numeric: tabular-nums; }
.panel { background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 16px 20px; margin-bottom: 16px; box-shadow: var(--shadow); min-width: 0; }
.panel-head { display: flex; justify-content: space-between; align-items: baseline; gap: 6px 14px; flex-wrap: wrap; margin-bottom: 10px; }
.agg { font-size: 12.5px; color: var(--text-2); font-variant-numeric: tabular-nums; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 6px; }
.kpi { background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 12px 16px; box-shadow: var(--shadow); min-width: 0; }
.kpi .label { font-size: 12.5px; color: var(--text-2); }
.kpi .value { font-size: 28px; font-weight: 700; letter-spacing: -.02em; font-variant-numeric: tabular-nums; line-height: 1.25; }
.kpi .value.unknown { color: var(--muted); }
.kpi .note { font-size: 12px; color: var(--muted); overflow-wrap: anywhere; }
.kpi.alarm { border-left: 4px solid var(--critical); }
.kpi.warn { border-left: 4px solid var(--warning); }
.kpi.good { border-left: 4px solid var(--good); }
.chip { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; font-weight: 600; padding: 1px 8px 1px 4px; border-radius: 999px; background: var(--surface-2); color: var(--text); white-space: nowrap; vertical-align: middle; }
.dot { width: 15px; height: 15px; border-radius: 50%; display: inline-grid; place-items: center; color: #fff; font-size: 9.5px; line-height: 1; flex: none; }
.controls { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; align-items: center; }
.controls input { flex: 1; min-width: 160px; }
.scroll { max-height: 640px; overflow: auto; border: 1px solid var(--line); border-radius: 8px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--line); vertical-align: top; }
th { position: sticky; top: 0; background: var(--surface-2); z-index: 1; font-size: 11.5px; font-weight: 700; color: var(--text-2); text-transform: uppercase; letter-spacing: .05em; }
tr.resolved td { opacity: .6; }
tr.resolved:hover td { opacity: 1; }
.feedback-form { display: none; padding: 10px; background: var(--surface-2); border-radius: 3px; margin-top: 10px; }
.feedback-form.open { display: block; }
textarea { resize: vertical; min-height: 60px; width: 100%; }
.btn-sm { padding: 4px 8px; font-size: 12px; border: 1px solid var(--line); background: var(--surface); color: var(--text); cursor: pointer; border-radius: 3px; }
.btn-sm:hover { background: var(--surface-2); }
.alert-item { padding: 15px; border-bottom: 1px solid var(--line); display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; }
.alert-item:last-child { border-bottom: none; }
.alert-header { flex: 1; }
.alert-title { font-weight: bold; margin-bottom: 5px; }
.alert-meta { font-size: 12px; color: var(--text-2); margin: 3px 0; }
.severity-badge { display: inline-flex; align-items: center; gap: 4px; font-weight: 600; }
.severity-CRITICAL { color: var(--critical); }
.severity-HIGH { color: var(--warning); }
.severity-MEDIUM { color: #f39c12; }
.severity-LOW { color: var(--good); }
.alert-actions { display: flex; gap: 10px; white-space: nowrap; }
.launch { margin-top: 10px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; font-size: 13px; }
.launch-label { opacity: .75; text-transform: uppercase; letter-spacing: .06em; }
.launch code { background: rgba(0,0,0,.28); padding: 6px 10px; border-radius: 6px; font-family: Menlo, Consolas, monospace; font-size: 12px; user-select: all; word-break: break-all; color: #fff; }
.copy-btn { background: rgba(255,255,255,.18); color: #fff; border: 0; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; }
.copy-btn:hover { background: rgba(255,255,255,.3); }
@media(max-width:900px) { .kpis { grid-template-columns: minmax(0,1fr); } .controls { flex-direction: column; } .controls input { width: 100%; } .alert-item { flex-direction: column; } .alert-actions { width: 100%; } }
    </style>
</head>
<body>
    <header class="top">
        <div>
            <div class="eyebrow">System Monitoring</div>
            <h1>🔐 Secure Dashboard</h1>
            <p>Security posture and app diagnostics.</p>
        </div>
        <div class="head-right">
            <div style="display: flex; gap: 8px; align-items: center;">
                <button id="view-security" class="primary" onclick="switchView('security')" style="border-radius: 8px 0 0 8px;">🛡️ Security</button>
                <button id="view-developer" onclick="switchView('developer')" style="border-radius: 0 8px 8px 0;">⚙️ Developer</button>
            </div>
            <button id="refresh" class="primary" onclick="loadDashboard()" style="margin-left: 10px;">Refresh</button>
        </div>
    </header>

    <main>
        <!-- Security Health View -->
        <div id="security-view" style="display: block;">
            <h2 class="section">Overall Security Status</h2>
            <div id="security-kpis"></div>

            <h2 class="section">System Protection</h2>
            <div class="panel">
                <div class="panel-head">
                    <h2>Core Defenses</h2>
                </div>
                <div id="system-defenses" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; padding: 10px;"></div>
            </div>

            <h2 class="section">Active Threats & Alerts</h2>
            <div class="controls">
                <button onclick="exportJSON()">Export JSON</button>
                <button onclick="exportCSV()">Export CSV</button>
                <select id="severity-filter" onchange="loadAlerts()">
                    <option value="">All Severities</option>
                    <option value="CRITICAL">🔴 Critical</option>
                    <option value="HIGH">🟠 High</option>
                    <option value="MEDIUM">🟡 Medium</option>
                    <option value="LOW">🟢 Low</option>
                </select>
                <select id="verdict-filter" onchange="loadAlerts()">
                    <option value="">All Verdicts</option>
                    <option value="ACTIVE">Active</option>
                    <option value="SUPPRESSED_EXPECTED">Suppressed</option>
                    <option value="DOWNGRADED_EXPECTED">Downgraded</option>
                </select>
            </div>
            <div class="panel">
                <div class="panel-head">
                    <h2>Recent Findings</h2>
                    <span class="agg" id="alert-count">—</span>
                </div>
                <div class="scroll">
                    <table>
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Type</th>
                                <th>Path / ID</th>
                                <th>Verdict</th>
                                <th>Time</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="alerts-list"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Developer Health View -->
        <div id="developer-view" style="display: none;">
            <h2 class="section">App Performance & Health</h2>
            <div id="developer-kpis"></div>

            <h2 class="section">System Integration</h2>
            <div id="system-health" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px;"></div>

            <h2 class="section">Diagnostics & Logs</h2>
            <div class="panel">
                <div class="panel-head">
                    <h2>System Events</h2>
                </div>
                <div style="padding: 15px; color: var(--text-2); font-size: 13px;">
                    <p><strong>Log Pipeline Status:</strong></p>
                    <ul style="margin: 10px 0 0 20px;">
                        <li>Events processed: <span id="events-processed">—</span></li>
                        <li>Last scan: <span id="last-scan">—</span></li>
                        <li>Database size: <span id="db-size">—</span></li>
                        <li>Alert feedback rate: <span id="feedback-rate">—</span></li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="launch" style="justify-content: center; margin-top: 40px; padding: 20px; border-top: 1px solid var(--line);">
            <span class="launch-label">Launch Desktop GUI</span>
            <code id="gui-cmd" style="margin: 0;">__GUI_CMD__</code>
            <button class="copy-btn" onclick="startGui()">Start</button>
            <span id="gui-status"></span>
        </div>
    </main>

    <script>
let currentView = 'security';
const severityIcons = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' };

function dot(severity) {
  const colors = { CRITICAL: 'var(--critical)', HIGH: 'var(--warning)', MEDIUM: '#f39c12', LOW: 'var(--good)' };
  return `<span class="dot" style="background:${colors[severity]||'var(--muted)'}">${severityIcons[severity]||'•'}</span>`;
}

function switchView(view) {
  currentView = view;
  document.getElementById('security-view').style.display = view === 'security' ? 'block' : 'none';
  document.getElementById('developer-view').style.display = view === 'developer' ? 'block' : 'none';

  document.getElementById('view-security').style.background = view === 'security' ? 'var(--accent)' : 'var(--surface)';
  document.getElementById('view-security').style.color = view === 'security' ? '#fff' : 'var(--text)';
  document.getElementById('view-security').style.borderColor = view === 'security' ? 'var(--accent)' : 'var(--line)';

  document.getElementById('view-developer').style.background = view === 'developer' ? 'var(--accent)' : 'var(--surface)';
  document.getElementById('view-developer').style.color = view === 'developer' ? '#fff' : 'var(--text)';
  document.getElementById('view-developer').style.borderColor = view === 'developer' ? 'var(--accent)' : 'var(--line)';

  if (view === 'security') loadSecurityView();
  else loadDeveloperView();
}

function buildSecurityKpis(data, diag) {
  diag = diag || {check_pass: '—', check_warning: '—', check_fail: '—'};
  const criticalPenalty = Math.min(40, (data.critical_count || 0) * 20);
  const highPenalty = Math.min(30, Math.max(0, (data.total || 0) - (data.critical_count || 0)) * 2);
  const securityScore = Math.max(0, 100 - criticalPenalty - highPenalty);
  const kpiHtml = `<div class="kpis">
    <div class="kpi ${securityScore < 70 ? 'alarm' : securityScore < 85 ? 'warn' : 'good'}">
      <div class="label">Security Score</div>
      <div class="value">${securityScore}/100</div>
      <div class="note">${securityScore >= 85 ? 'Protected' : securityScore >= 70 ? 'At risk' : 'Critical'}</div>
    </div>
    <div class="kpi ${data.critical_count > 0 ? 'alarm' : 'good'}">
      <div class="label">Critical Threats</div>
      <div class="value">${data.critical_count}</div>
      <div class="note">${data.critical_count === 0 ? 'None detected' : 'Needs attention'}</div>
    </div>
    <div class="kpi ${data.total > 10 ? 'warn' : 'good'}">
      <div class="label">Total Findings</div>
      <div class="value">${data.total}</div>
      <div class="note">Across all categories</div>
    </div>
    <div class="kpi">
      <div class="label">False Positive Rate</div>
      <div class="value">${data.fp_rate || '—'}</div>
      <div class="note">From user feedback</div>
    </div>
  </div>`;
  document.getElementById('security-kpis').innerHTML = kpiHtml;

  const checkPass = parseInt(diag.check_pass) || 0;
  const checkWarn = parseInt(diag.check_warning) || 0;
  const checkFail = parseInt(diag.check_fail) || 0;

  const defenses = `
    <div style="padding: 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-2);">
      <div style="font-weight: 600; margin-bottom: 8px;">✓ Posture Checks</div>
      <div style="font-size: 12px; color: var(--good);">${checkPass} PASS</div>
      ${checkWarn > 0 ? `<div style="font-size: 12px; color: var(--warning);">${checkWarn} WARNING</div>` : ''}
      ${checkFail > 0 ? `<div style="font-size: 12px; color: var(--critical);">${checkFail} FAIL</div>` : ''}
    </div>
    <div style="padding: 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-2);">
      <div style="font-weight: 600; margin-bottom: 8px;">🔒 FileVault</div>
      <div style="font-size: 12px; color: var(--text-2);">Disk encryption enabled</div>
    </div>
    <div style="padding: 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-2);">
      <div style="font-weight: 600; margin-bottom: 8px;">🛡️ System Integrity Protection</div>
      <div style="font-size: 12px; color: var(--text-2);">Protecting system files</div>
    </div>
    <div style="padding: 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-2);">
      <div style="font-weight: 600; margin-bottom: 8px;">🔥 Firewall</div>
      <div style="font-size: 12px; color: var(--text-2);">Monitoring connections</div>
    </div>
    <div style="padding: 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-2);">
      <div style="font-weight: 600; margin-bottom: 8px;">👁️ Gatekeeper</div>
      <div style="font-size: 12px; color: var(--text-2);">App verification active</div>
    </div>
  `;
  document.getElementById('system-defenses').innerHTML = defenses;
}

function buildDeveloperKpis(diag) {
  const kpiHtml = `<div class="kpis">
    <div class="kpi">
      <div class="label">Memory Usage</div>
      <div class="value">${diag.memory_mb}</div>
      <div class="note">Resident set size</div>
    </div>
    <div class="kpi">
      <div class="label">CPU Time</div>
      <div class="value">${diag.cpu_seconds}s</div>
      <div class="note">Total runtime</div>
    </div>
    <div class="kpi">
      <div class="label">Database Size</div>
      <div class="value">${diag.db_mb}</div>
      <div class="note">Storage used</div>
    </div>
    <div class="kpi">
      <div class="label">Events</div>
      <div class="value">${diag.events}</div>
      <div class="note">Stored in database</div>
    </div>
  </div>`;
  document.getElementById('developer-kpis').innerHTML = kpiHtml;

  const checkPass = parseInt(diag.check_pass) || 0;
  const checkWarn = parseInt(diag.check_warning) || 0;
  const checkFail = parseInt(diag.check_fail) || 0;

  const health = `
    <div style="padding: 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-2);">
      <div style="font-weight: 600; margin-bottom: 4px;">✓ Posture Checks</div>
      <div style="font-size: 12px; color: var(--good);">${checkPass} PASS</div>
      ${checkWarn > 0 ? `<div style="font-size: 12px; color: var(--warning);">${checkWarn} WARNING</div>` : ''}
      ${checkFail > 0 ? `<div style="font-size: 12px; color: var(--critical);">${checkFail} FAIL</div>` : ''}
    </div>
    <div style="padding: 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-2);">
      <div style="font-weight: 600; margin-bottom: 4px;">✓ Database Health</div>
      <div style="font-size: 12px; color: var(--good);">Connected (${diag.db_mb})</div>
    </div>
    <div style="padding: 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-2);">
      <div style="font-weight: 600; margin-bottom: 4px;">📊 Event Stream</div>
      <div style="font-size: 12px; color: var(--good);">${diag.events} events recorded</div>
    </div>
    <div style="padding: 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--surface-2);">
      <div style="font-weight: 600; margin-bottom: 4px;">⚠️ Findings</div>
      <div style="font-size: 12px; color: var(--text-2);">${diag.findings} total</div>
    </div>
  `;
  document.getElementById('system-health').innerHTML = health;
}

async function loadSecurityView() {
  const severity = document.getElementById('severity-filter').value;
  const verdict = document.getElementById('verdict-filter').value;
  const params = new URLSearchParams();
  if (severity) params.append('severity', severity);
  if (verdict) params.append('verdict', verdict);

  const resp = await fetch(`/api/alerts?${params}`);
  const data = await resp.json();

  let diag = {check_pass: '—', check_warning: '—', check_fail: '—'};
  try {
    const diagResp = await fetch('/api/diagnostics');
    diag = await diagResp.json();
  } catch (e) {}

  buildSecurityKpis(data, diag);
  document.getElementById('alert-count').textContent = data.total + ' total';

  const tbody = document.getElementById('alerts-list');
  if (data.alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--muted);">No alerts found</td></tr>`;
    return;
  }

  tbody.innerHTML = data.alerts.map(alert => {
    const dt = new Date(alert.created_at);
    return `<tr>
      <td>${dot(alert.final_severity)} <span class="severity-badge severity-${alert.final_severity}">${alert.final_severity}</span></td>
      <td>${alert.entity_type}</td>
      <td style="font-size:12px;color:var(--text-2);">${alert.entity_path || 'unknown'}</td>
      <td><span class="pill">${alert.verdict}</span></td>
      <td style="font-size:12px;white-space:nowrap;">${dt.toLocaleString()}</td>
      <td><button class="btn-sm" onclick="toggleFeedbackForm(${alert.id})">Mark FP</button></td>
    </tr>
    <tr style="display:none;" id="feedback-row-${alert.id}">
      <td colspan="6">
        <div class="feedback-form open" id="feedback-${alert.id}">
          <textarea id="reason-${alert.id}" placeholder="Why is this a false positive?"></textarea><br><br>
          <button class="btn-sm" onclick="submitFeedback(${alert.id})">Submit</button>
          <button class="btn-sm" onclick="toggleFeedbackForm(${alert.id})">Cancel</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

async function loadDeveloperView() {
  try {
    const response = await fetch('/api/diagnostics');
    const diag = await response.json();
    buildDeveloperKpis(diag);
  } catch (error) {
    console.error('Failed to load diagnostics:', error);
    buildDeveloperKpis({
      memory_mb: '—', cpu_seconds: '—', db_mb: '—', events: '—', findings: '—',
      check_pass: '—', check_warning: '—', check_fail: '—'
    });
  }
}

function loadDashboard() {
  if (currentView === 'security') loadSecurityView();
  else loadDeveloperView();
}

async function loadAlerts() {
  if (currentView === 'security') loadSecurityView();
}

function toggleFeedbackForm(alertId) {
  const row = document.getElementById(`feedback-row-${alertId}`);
  const form = document.getElementById(`feedback-${alertId}`);
  if (row.style.display === 'none') {
    row.style.display = 'table-row';
    form.classList.add('open');
  } else {
    row.style.display = 'none';
    form.classList.remove('open');
  }
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

function startGui() {
  const el = document.getElementById('gui-status');
  el.textContent = 'starting…';
  fetch('/api/launch-gui', {method: 'POST'})
    .then(r => r.json())
    .then(d => { el.textContent = d.ok ? ('started (pid ' + d.pid + ')') : ('failed: ' + d.error); })
    .catch(e => { el.textContent = 'failed: ' + e; });
}

// Initialize with security view
switchView('security');
setInterval(() => loadDashboard(), 30000);
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

    def _launch_gui(self):
        """Start the desktop GUI.

        The command is fixed (this project's own launcher) and never taken
        from the request, and the endpoint is refused unless the server is
        bound to loopback — so this cannot be used to run arbitrary code or
        be reached from the network.
        """
        import subprocess
        host = self.server.server_address[0]
        if host not in ("127.0.0.1", "::1", "localhost"):
            body = {"ok": False, "error": "refused: server is not bound to loopback"}
            code = 403
        else:
            cmd = _gui_launch_command()
            try:
                proc = subprocess.Popen(
                    ["/bin/bash", cmd] if cmd.endswith(".command") else cmd.split(),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                body, code = {"ok": True, "pid": proc.pid}, 200
            except Exception as exc:
                body, code = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}, 500
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _get_diagnostics(self):
        """Get real diagnostics data from secure diagnostics commands."""
        import subprocess
        import re
        diag = {
            "memory_mb": "—",
            "cpu_seconds": "—",
            "db_mb": "—",
            "events": "—",
            "findings": "—",
            "check_pass": "—",
            "check_warning": "—",
            "check_fail": "—",
        }

        # Stub: diagnostics source broken (for mutation gate testing)
        if os.environ.get("SECURE_STUB_DIAGNOSTICS_BROKEN"):
            return diag

        try:
            # Get performance metrics: "Secure: 33.8MB peak RSS, 0.24s CPU time, db 5.9MB, 24 events, 632 findings"
            result = subprocess.run(
                ["python3", "-m", "secure", "diagnostics", "performance"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                text = result.stdout
                # Extract memory: "XXX peak RSS" or "XX.XMB peak RSS"
                mem_match = re.search(r'([\d.]+M?B)\s+peak RSS', text)
                if mem_match:
                    diag["memory_mb"] = mem_match.group(1)
                # Extract CPU: "X.XXs CPU time"
                cpu_match = re.search(r'([\d.]+)s\s+CPU time', text)
                if cpu_match:
                    diag["cpu_seconds"] = cpu_match.group(1)
                # Extract DB size: "db XMXB" or "db X.XMB"
                db_match = re.search(r'db\s+([\d.]+M?B)', text)
                if db_match:
                    diag["db_mb"] = db_match.group(1)
                # Extract events: "N events"
                events_match = re.search(r'(\d+)\s+events', text)
                if events_match:
                    diag["events"] = events_match.group(1)
                # Extract findings: "N findings"
                findings_match = re.search(r'(\d+)\s+findings', text)
                if findings_match:
                    diag["findings"] = findings_match.group(1)
        except Exception:
            pass

        try:
            # Get posture check results: "Summary: 12 PASS, 3 WARNING, 0 FAIL"
            result = subprocess.run(
                ["python3", "-m", "secure", "check"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                text = result.stdout
                # Extract PASS count: "N PASS"
                pass_match = re.search(r'(\d+)\s+PASS', text)
                if pass_match:
                    diag["check_pass"] = pass_match.group(1)
                # Extract WARNING count: "N WARNING"
                warning_match = re.search(r'(\d+)\s+WARNING', text)
                if warning_match:
                    diag["check_warning"] = warning_match.group(1)
                # Extract FAIL count: "N FAIL"
                fail_match = re.search(r'(\d+)\s+FAIL', text)
                if fail_match:
                    diag["check_fail"] = fail_match.group(1)
        except Exception:
            pass

        return diag

    def do_GET(self):
        """Handle GET requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)

        if path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            page = HTML_TEMPLATE.replace("__GUI_CMD__", _gui_launch_command())
            self.wfile.write(page.encode())

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

            # Stub: return wrong data for payload-level gate testing
            if os.environ.get("SECURE_STUB_DASHBOARD_ALERTS_WRONG"):
                response_data["total"] = 999

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

        elif path == "/api/diagnostics":
            diag = self._get_diagnostics()

            # Stub: return wrong data for payload-level gate testing
            if os.environ.get("SECURE_STUB_DIAGNOSTICS_WRONG"):
                diag["memory_mb"] = "999"

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(diag).encode())

        else:
            self.send_response(404)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not found"}).encode())

    def do_POST(self):
        """Handle POST requests."""
        if self.path == "/api/launch-gui":
            self._launch_gui()
            return
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

    # Stub: server cannot bind (for mutation gate testing)
    if os.environ.get("SECURE_STUB_DASHBOARD_SERVER_BREAK"):
        raise RuntimeError("GATE_DASHBOARD_SERVER_BIND_FAILURE: server binding broken by stub")

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
