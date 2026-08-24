"""
Tests for secure/validate/sandbox.py — Phase 27 Stage 7. The single
mechanism that makes secure/validate/__init__.py's rule 1
("sandbox-only, always") actually true: every scenario's fixture
injection happens against a throwaway temp-file database/AppConfig
that's gone the instant the `with sandbox()` block exits, never the
operator's real ~/.secure.

Run with:  pytest
"""

from __future__ import annotations

from pathlib import Path

from secure.config import AppConfig
from secure.storage.models import add_watch_path, list_watch_paths
from secure.validate.sandbox import sandbox


def test_sandbox_yields_a_real_appconfig_and_open_connection():
    with sandbox() as sb:
        assert isinstance(sb.cfg, AppConfig)
        assert sb.conn is not None
        # A real, usable connection against a real (if temp) schema.
        sb.conn.execute("SELECT 1").fetchone()


def test_sandbox_app_dir_is_a_temp_directory_not_the_repo_or_home():
    with sandbox() as sb:
        app_dir = sb.cfg.app_dir_path()
        assert app_dir.exists()
        assert "secure-validate-" in str(app_dir)
        assert str(Path.home()) not in str(app_dir) or "secure-validate-" in str(app_dir)


def test_sandbox_directory_is_deleted_after_the_context_exits():
    with sandbox() as sb:
        app_dir = sb.cfg.app_dir_path()
        assert app_dir.exists()
    assert not app_dir.exists()


def test_two_sandboxes_are_fully_isolated_from_each_other():
    with sandbox() as sb1:
        db_path_1 = sb1.cfg.app_dir_path()
        add_watch_path(sb1.conn, "/tmp/only-in-sandbox-1", sensitivity="normal")

        with sandbox() as sb2:
            db_path_2 = sb2.cfg.app_dir_path()
            assert db_path_1 != db_path_2
            assert list_watch_paths(sb2.conn) == []  # sb1's write never leaked into sb2's database
