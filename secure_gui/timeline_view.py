"""Phase 61: Timeline view — chronological alert timeline.

Shows all detection events across all sensors in chronological order.
Severity color-coding, sensor grouping, and quick evidence access.
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, List, Optional


@dataclass
class TimelineEvent:
    """One event in the timeline."""
    timestamp: datetime
    sensor: str  # persistence, listening, connections, fileintegrity, checks, etc.
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    entity_type: str  # launchagent, listening_port, connection, file_change, etc.
    entity_path: str  # /path/to/entity
    verdict: str  # ACTIVE, SUPPRESSED_EXPECTED, DOWNGRADED_EXPECTED
    confidence: str  # CRITICAL, HIGH, MEDIUM, LOW
    summary: str  # Human-readable one-liner


class TimelineController:
    """Builds timeline from alert database."""

    def __init__(self, db_conn):
        self.db_conn = db_conn

    def fetch_recent_events(self, hours: int = 24) -> List[TimelineEvent]:
        """Fetch events from the last N hours, in chronological order."""
        cutoff = datetime.now() - timedelta(hours=hours)

        events = []

        # Query alert_decisions (Phase 53-56)
        cursor = self.db_conn.execute("""
            SELECT
                id, source_table, source_id, base_severity, final_severity,
                verdict, created_at, entity_type, entity_path
            FROM alert_decisions
            WHERE created_at >= ?
            ORDER BY created_at DESC
        """, (cutoff.isoformat(),))

        for row in cursor.fetchall():
            # Map source_table to sensor name
            source_map = {
                "anomaly_events": "baseline",
                "correlation_alerts": "correlation",
                "correlation_chain_alerts": "chain_correlation",
            }
            sensor = source_map.get(row[1], row[1])

            # Build summary
            summary = f"{row[8]} ({row[7]}): {row[5]} ({row[4]})"

            events.append(TimelineEvent(
                timestamp=datetime.fromisoformat(row[6]),
                sensor=sensor,
                severity=row[4],  # final_severity
                entity_type=row[7],
                entity_path=row[8] or "—",
                verdict=row[5],
                confidence="HIGH",  # TODO: fetch from explanation
                summary=summary,
            ))

        return events

    def events_by_sensor(self, events: List[TimelineEvent]) -> dict[str, List[TimelineEvent]]:
        """Group events by sensor."""
        grouped = {}
        for event in events:
            if event.sensor not in grouped:
                grouped[event.sensor] = []
            grouped[event.sensor].append(event)
        return grouped

    def events_by_hour(self, events: List[TimelineEvent]) -> dict[str, List[TimelineEvent]]:
        """Group events by hour (for timeline view)."""
        grouped = {}
        for event in events:
            hour = event.timestamp.strftime("%Y-%m-%d %H:00")
            if hour not in grouped:
                grouped[hour] = []
            grouped[hour].append(event)
        return grouped


def severity_color(severity: str) -> str:
    """Map severity to color."""
    colors = {
        "CRITICAL": "#d91e18",  # Red
        "HIGH": "#ff8000",      # Orange
        "MEDIUM": "#f9a603",    # Yellow-orange
        "LOW": "#0055cc",       # Blue
    }
    return colors.get(severity, "#cccccc")


def build_timeline_frame(
    root: tk.Widget,
    db_conn,
    on_event_selected: Optional[Callable[[TimelineEvent], None]] = None,
) -> tk.Frame:
    """
    Build timeline view frame.

    Returns a frame showing chronological events with severity coloring.
    """
    frame = tk.Frame(root, bg="#f5f5f5")

    # Title
    title = tk.Label(
        frame,
        text="Alert Timeline (Last 24 Hours)",
        font=("Monaco", 14, "bold"),
        bg="#f5f5f5",
        fg="#333",
    )
    title.pack(side=tk.TOP, fill=tk.X, padx=16, pady=12)

    # Controller
    controller = TimelineController(db_conn)
    events = controller.fetch_recent_events(hours=24)

    if not events:
        empty = tk.Label(
            frame,
            text="No alerts in the last 24 hours",
            font=("Monaco", 11),
            bg="#f5f5f5",
            fg="#999",
        )
        empty.pack(pady=20)
        return frame

    # Scrollable timeline
    canvas = tk.Canvas(frame, bg="#f5f5f5", highlightthickness=0)
    scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL, command=canvas.yview)
    scrollable_frame = tk.Frame(canvas, bg="#f5f5f5")

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    # Events by hour
    events_by_hour = controller.events_by_hour(events)

    for hour, hour_events in sorted(events_by_hour.items(), reverse=True):
        # Hour header
        hour_label = tk.Label(
            scrollable_frame,
            text=hour,
            font=("Monaco", 10, "bold"),
            bg="#e8e8e8",
            fg="#333",
        )
        hour_label.pack(fill=tk.X, padx=8, pady=(8, 4))

        # Events in this hour
        for event in hour_events:
            event_frame = tk.Frame(
                scrollable_frame,
                bg="white",
                relief=tk.FLAT,
                bd=1,
            )
            event_frame.pack(fill=tk.X, padx=8, pady=2)

            # Severity bar
            bar = tk.Frame(
                event_frame,
                bg=severity_color(event.severity),
                width=4,
                height=50,
            )
            bar.pack(side=tk.LEFT, fill=tk.Y, padx=0)

            # Content
            content = tk.Frame(event_frame, bg="white")
            content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=12, pady=8)

            # Timestamp + sensor
            header = tk.Label(
                content,
                text=f"{event.timestamp.strftime('%H:%M:%S')} • {event.sensor.upper()}",
                font=("Monaco", 9, "bold"),
                bg="white",
                fg="#333",
                justify=tk.LEFT,
            )
            header.pack(anchor="nw")

            # Summary
            summary_label = tk.Label(
                content,
                text=event.summary,
                font=("Monaco", 9),
                bg="white",
                fg="#666",
                justify=tk.LEFT,
                wraplength=400,
            )
            summary_label.pack(anchor="nw")

            # Verdict + confidence badge
            badge_text = f"{event.verdict} • {event.confidence}"
            badge = tk.Label(
                content,
                text=badge_text,
                font=("Monaco", 8),
                bg="white",
                fg="#999",
            )
            badge.pack(anchor="nw", pady=(4, 0))

            # Click handler
            if on_event_selected:
                event_frame.bind(
                    "<Button-1>",
                    lambda e, evt=event: on_event_selected(evt)
                )
                event_frame.config(cursor="hand2")

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    return frame
