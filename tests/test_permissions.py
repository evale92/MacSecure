"""
Tests for secure/permissions.py and its wiring into config.py,
storage/database.py, and logging_setup.py (Phase 29 Stage 4: secrets
hardening).

Run with:  pytest
"""

import stat
from pathlib import Path

from secure.config import default_config, save_config
from secure.logging_setup import setup_logging
from secure.permissions import DIR_MODE, FILE_MODE, harden_dir, harden_file
from secure.storage.database import Database, connect


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_harden_file_restricts_to_owner_only(tmp_path: Path):
    target = tmp_path / "secret.txt"
    target.write_text("shh")
    # Start deliberately permissive, so the test actually proves the
    # helper changed something rather than happening to match a default.
    target.chmod(0o644)

    harden_file(target)

    assert _mode(target) == FILE_MODE


def test_harden_dir_restricts_to_owner_only(tmp_path: Path):
    target = tmp_path / "adir"
    target.mkdir()
    target.chmod(0o755)

    harden_dir(target)

    assert _mode(target) == DIR_MODE


def test_harden_file_on_missing_path_never_raises(tmp_path: Path):
    # Best-effort per the module's own docstring — a caller that
    # forgets to create the file first should never crash the app.
    harden_file(tmp_path / "does_not_exist.txt")


def test_harden_dir_on_missing_path_never_raises(tmp_path: Path):
    harden_dir(tmp_path / "does_not_exist_dir")


def test_save_config_hardens_file_and_app_dir(tmp_path: Path):
    app_dir = tmp_path / "secure_home"
    cfg = default_config()
    cfg.app_dir = str(app_dir)
    cfg.virustotal_api_key = "fake-key-for-test-only"

    path = save_config(cfg)

    assert _mode(path) == FILE_MODE
    assert _mode(app_dir) == DIR_MODE


def test_database_connect_hardens_db_file_and_app_dir(tmp_path: Path):
    app_dir = tmp_path / "secure_home"
    db_path = app_dir / "secure.db"

    conn = connect(db_path)
    conn.close()

    assert _mode(db_path) == FILE_MODE
    assert _mode(app_dir) == DIR_MODE


def test_database_context_manager_hardens_db_file(tmp_path: Path):
    db_path = tmp_path / "secure_home" / "secure.db"

    with Database(db_path) as db:
        db.conn.execute("SELECT 1")

    assert _mode(db_path) == FILE_MODE


def test_setup_logging_hardens_log_file_and_app_dir(tmp_path: Path):
    app_dir = tmp_path / "secure_home"
    log_path = app_dir / "secure.log"

    logger = setup_logging(log_path, level="INFO")
    logger.info("test message")
    for handler in logger.handlers:
        handler.flush()

    assert _mode(log_path) == FILE_MODE
    assert _mode(app_dir) == DIR_MODE
