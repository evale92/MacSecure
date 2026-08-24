"""
secure/validate/sandbox.py — builds the throwaway, temp-file
AppConfig + Database every validation scenario runs against. This is
the ONE mechanism that makes secure/validate/__init__.py's rule 1
("sandbox-only, always") actually true rather than just documented —
see tests/test_validate_sandbox.py's own isolation assertions.

Deliberately the same pattern tests/test_detect_validate.py's
`chain_scoring` fixtures already established for exactly this reason
(a validation/test run must never write synthetic security findings
into an operator's real data): `tempfile.TemporaryDirectory()` + the
real `AppConfig`/`Database` classes for schema init, discarded
immediately after use via the context manager below.
"""

from __future__ import annotations

import contextlib
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from secure.config import AppConfig
from secure.storage.database import Database


@dataclass
class Sandbox:
    """One throwaway app_dir + open database connection. `cfg` is a
    real AppConfig rooted at the temp dir — any scenario that needs a
    config-driven path (sigma_rules_dir_path(), etc.) gets a real,
    isolated one for free, never the operator's actual config.json.
    """

    cfg: AppConfig
    conn: sqlite3.Connection


@contextlib.contextmanager
def sandbox() -> Iterator[Sandbox]:
    """Context manager yielding a Sandbox backed by a real temp
    directory, deleted the moment the `with` block exits — the temp
    directory (and the sqlite file inside it) never outlives one
    `secure validate run` invocation, and is never the operator's own
    ~/.secure.
    """
    with tempfile.TemporaryDirectory(prefix="secure-validate-") as tmp:
        tmp_path = Path(tmp)
        cfg = AppConfig(app_dir=str(tmp_path))
        with Database(tmp_path / "sandbox.db") as db:
            yield Sandbox(cfg=cfg, conn=db.conn)
