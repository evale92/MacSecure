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

from secure.config import DEFAULT_APP_DIR, AppConfig
from secure.storage.models import add_watch_path, list_watch_paths
from secure.validate.sandbox import sandbox

REPO_ROOT = Path(__file__).resolve().parents[1]


def _isolation_violations(app_dir: Path) -> "list[str]":
    """Every way a candidate app_dir would NOT be isolated from the
    operator, as a list rather than a bare bool so the check can carry
    its own positive control — see
    test_isolation_check_rejects_paths_that_are_not_isolated below.

    That control is the point. This assertion was previously written
    as `str(Path.home()) not in str(app_dir) or "secure-validate-" in
    str(app_dir)`, whose right-hand side the line above it had already
    asserted, so the whole `or` was a tautology: an app_dir of
    `~/.secure/secure-validate-leak` — the exact thing
    secure/validate/sandbox.py's docstring says can never happen —
    satisfied it.
    """
    resolved = app_dir.resolve()
    real_app_dir = DEFAULT_APP_DIR.expanduser().resolve()
    violations = []
    if resolved == real_app_dir or real_app_dir in resolved.parents:
        violations.append(f"inside the operator's real app dir {real_app_dir}")
    if resolved == REPO_ROOT or REPO_ROOT in resolved.parents:
        violations.append(f"inside the repository checkout {REPO_ROOT}")
    return violations


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
        assert _isolation_violations(app_dir) == []


def test_isolation_check_rejects_paths_that_are_not_isolated():
    """Positive control for the assertion above: prove the check bites.

    Without this, `_isolation_violations` could quietly degrade back
    into something that returns `[]` for everything and the test above
    would still be green — which is exactly how the `or` it replaced
    passed for years while checking nothing.
    """
    assert _isolation_violations(DEFAULT_APP_DIR / "secure-validate-leak") != []
    assert _isolation_violations(REPO_ROOT / "secure-validate-leak") != []


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
