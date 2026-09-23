"""Phase 61: Sensor status panel — shows active sensors and last run time."""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class SensorStatus:
    """Status of one sensor."""
    name: str
    is_active: bool
    last_run_at: Optional[datetime]
    test_count: int
    is_critical: bool


class SensorStatusController:
    """Determines sensor health status."""

    def __init__(self, db_conn):
        self.db_conn = db_conn
        self.critical_sensors = {
            "persistence", "listening", "connections",
            "fileintegrity", "checks"
        }

    def get_all_sensors(self) -> list[SensorStatus]:
        """Get status of all known sensors."""
        sensors_info = {
            "persistence": 97,
            "listening": 47,
            "connections": 40,
            "fileintegrity": 67,
            "checks": 51,
            "wifi": 53,
            "bluetooth": 53,
            "inventory": 68,
            "arpwatch": 27,
        }

        statuses = []

        for sensor_name, test_count in sensors_info.items():
            # Check if sensor has recent activity
            cursor = self.db_conn.execute("""
                SELECT MAX(created_at) FROM anomaly_events
                WHERE entity_type LIKE ?
            """, (f"%{sensor_name}%",))

            last_run_row = cursor.fetchone()
            last_run_at = None
            if last_run_row and last_run_row[0]:
                try:
                    last_run_at = datetime.fromisoformat(last_run_row[0])
                except (TypeError, ValueError):
                    pass

            is_active = sensor_name in {"persistence", "listening", "connections",
                                        "fileintegrity", "checks", "wifi", "bluetooth"}

            statuses.append(SensorStatus(
                name=sensor_name,
                is_active=is_active,
                last_run_at=last_run_at,
                test_count=test_count,
                is_critical=sensor_name in self.critical_sensors,
            ))

        return sorted(statuses, key=lambda s: (not s.is_critical, s.name))


def status_icon(is_active: bool) -> str:
    """Return status indicator."""
    return "✓" if is_active else "○"


def build_sensor_status_frame(
    root: tk.Widget,
    db_conn,
) -> tk.Frame:
    """
    Build sensor status panel.

    Shows all sensors, their active status, and last run time.
    """
    frame = tk.Frame(root, bg="#f5f5f5")

    # Title
    title = tk.Label(
        frame,
        text="Sensor Status",
        font=("Monaco", 14, "bold"),
        bg="#f5f5f5",
        fg="#333",
    )
    title.pack(side=tk.TOP, fill=tk.X, padx=16, pady=12)

    # Controller
    controller = SensorStatusController(db_conn)
    sensors = controller.get_all_sensors()

    # Scrollable list
    canvas = tk.Canvas(frame, bg="#f5f5f5", highlightthickness=0)
    scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL, command=canvas.yview)
    scrollable_frame = tk.Frame(canvas, bg="#f5f5f5")

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    # Section: Critical sensors
    critical_label = tk.Label(
        scrollable_frame,
        text="TIER-1 CRITICAL",
        font=("Monaco", 9, "bold"),
        bg="#ffe6e6",
        fg="#cc0000",
    )
    critical_label.pack(fill=tk.X, padx=8, pady=(8, 4))

    for sensor in [s for s in sensors if s.is_critical]:
        sensor_row = tk.Frame(scrollable_frame, bg="white", relief=tk.FLAT, bd=1)
        sensor_row.pack(fill=tk.X, padx=8, pady=1)

        # Status icon
        icon_label = tk.Label(
            sensor_row,
            text=status_icon(sensor.is_active),
            font=("Monaco", 12, "bold"),
            bg="white",
            fg="#00aa00" if sensor.is_active else "#999",
            width=2,
        )
        icon_label.pack(side=tk.LEFT, padx=8, pady=6)

        # Sensor info
        info_frame = tk.Frame(sensor_row, bg="white")
        info_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=6)

        name_label = tk.Label(
            info_frame,
            text=f"{sensor.name.upper()}",
            font=("Monaco", 9, "bold"),
            bg="white",
            fg="#333",
        )
        name_label.pack(anchor="nw")

        if sensor.last_run_at:
            age_str = _format_age(sensor.last_run_at)
            detail = f"Last run: {age_str} • {sensor.test_count} tests"
        else:
            detail = f"Never run • {sensor.test_count} tests"

        detail_label = tk.Label(
            info_frame,
            text=detail,
            font=("Monaco", 8),
            bg="white",
            fg="#666",
        )
        detail_label.pack(anchor="nw")

    # Section: Active non-critical sensors
    active_label = tk.Label(
        scrollable_frame,
        text="ACTIVE (NON-CRITICAL)",
        font=("Monaco", 9, "bold"),
        bg="#e6f2ff",
        fg="#0055cc",
    )
    active_label.pack(fill=tk.X, padx=8, pady=(12, 4))

    for sensor in [s for s in sensors if s.is_active and not s.is_critical]:
        sensor_row = tk.Frame(scrollable_frame, bg="white", relief=tk.FLAT, bd=1)
        sensor_row.pack(fill=tk.X, padx=8, pady=1)

        icon_label = tk.Label(
            sensor_row,
            text="✓",
            font=("Monaco", 12, "bold"),
            bg="white",
            fg="#00aa00",
            width=2,
        )
        icon_label.pack(side=tk.LEFT, padx=8, pady=6)

        info_frame = tk.Frame(sensor_row, bg="white")
        info_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=6)

        name_label = tk.Label(
            info_frame,
            text=f"{sensor.name.upper()}",
            font=("Monaco", 9, "bold"),
            bg="white",
            fg="#333",
        )
        name_label.pack(anchor="nw")

        if sensor.last_run_at:
            age_str = _format_age(sensor.last_run_at)
            detail = f"Last run: {age_str}"
        else:
            detail = "Never run"

        detail_label = tk.Label(
            info_frame,
            text=detail,
            font=("Monaco", 8),
            bg="white",
            fg="#666",
        )
        detail_label.pack(anchor="nw")

    # Section: Inactive sensors
    inactive_sensors = [s for s in sensors if not s.is_active]
    if inactive_sensors:
        inactive_label = tk.Label(
            scrollable_frame,
            text="INACTIVE",
            font=("Monaco", 9, "bold"),
            bg="#f0f0f0",
            fg="#999",
        )
        inactive_label.pack(fill=tk.X, padx=8, pady=(12, 4))

        for sensor in inactive_sensors:
            sensor_row = tk.Frame(scrollable_frame, bg="white", relief=tk.FLAT, bd=1)
            sensor_row.pack(fill=tk.X, padx=8, pady=1)

            icon_label = tk.Label(
                sensor_row,
                text="○",
                font=("Monaco", 12, "bold"),
                bg="white",
                fg="#ccc",
                width=2,
            )
            icon_label.pack(side=tk.LEFT, padx=8, pady=6)

            info_frame = tk.Frame(sensor_row, bg="white")
            info_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=6)

            name_label = tk.Label(
                info_frame,
                text=f"{sensor.name.upper()}",
                font=("Monaco", 9),
                bg="white",
                fg="#999",
            )
            name_label.pack(anchor="nw")

    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    return frame


def _format_age(dt: datetime) -> str:
    """Format time since dt."""
    from datetime import timezone as tz

    # Ensure both are timezone-aware UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz.utc)

    now = datetime.now(tz.utc)
    delta = now - dt
    seconds = delta.total_seconds()

    if seconds < 60:
        return f"{int(seconds)}s ago"
    elif seconds < 3600:
        return f"{int(seconds / 60)}m ago"
    elif seconds < 86400:
        return f"{int(seconds / 3600)}h ago"
    else:
        return f"{int(seconds / 86400)}d ago"
