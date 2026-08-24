"""
logging_setup.py — structured logging, using only the Python standard
library (the `logging` module).

"Structured" here means: every log line is a single JSON object, with
consistent fields (timestamp, level, logger name, message, plus any
extra context you attach). That makes logs easy to grep, parse, or
later feed into a real log-analysis tool — which matters a lot for a
security-focused app, where "what happened and when" is the whole
point.

What's in this file:
    - JsonFormatter: turns a Python LogRecord into one JSON line.
    - setup_logging(): configures the root logger to write JSON to a
      log file AND plain, readable text to the console at the same
      time, so you get both a machine-readable audit trail and a
      human-friendly view while developing.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from secure.permissions import harden_dir, harden_file


class JsonFormatter(logging.Formatter):
    """Formats each log record as a single line of JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Anything passed via logger.info("msg", extra={"user": "x"})
        # shows up as extra attributes on the record. We surface the
        # common ones here; feel free to extend this list later.
        for key in ("event", "component"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, sort_keys=True)


def setup_logging(log_path: Path, level: str = "INFO") -> logging.Logger:
    """Configure the root logger and return it.

    Call this once, near the start of the program (the CLI does this
    for you). After that, any module can just do:

        import logging
        logger = logging.getLogger(__name__)
        logger.info("something happened")

    and it will automatically go through the handlers set up here.
    """
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    harden_dir(log_path.parent)

    root_logger = logging.getLogger()
    root_logger.setLevel(level.upper())

    # Avoid adding duplicate handlers if setup_logging() is called
    # more than once (e.g. in tests).
    root_logger.handlers.clear()

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(JsonFormatter())
    root_logger.addHandler(file_handler)
    # secure.log is an activity record for this Mac (see
    # docs/THREAT_MODEL.md) — Phase 29 Stage 4 restricts it to the
    # owning user, best-effort, same as config.json/secure.db.
    harden_file(log_path)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    root_logger.addHandler(console_handler)

    return root_logger
