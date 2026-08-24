"""
Tests for secure/config.py.

Run with:  pytest
"""

from pathlib import Path

from secure.config import default_config, load_config, save_config


def test_default_config_has_expected_fields():
    cfg = default_config()
    assert cfg.database_filename == "secure.db"
    assert cfg.log_filename == "secure.log"
    assert cfg.log_level == "INFO"
    assert cfg.device_role == "workstation"
    assert cfg.device_name  # auto-detected, just needs to be non-empty


def test_device_role_round_trips(tmp_path: Path):
    app_dir = tmp_path / "server_home"
    cfg = default_config()
    cfg.app_dir = str(app_dir)
    cfg.device_role = "server"

    save_config(cfg)
    loaded = load_config(app_dir)

    assert loaded.device_role == "server"


def test_save_and_load_round_trip(tmp_path: Path):
    app_dir = tmp_path / "secure_home"
    cfg = default_config()
    cfg.app_dir = str(app_dir)
    cfg.log_level = "DEBUG"

    save_config(cfg)
    loaded = load_config(app_dir)

    assert loaded.log_level == "DEBUG"
    assert loaded.database_filename == cfg.database_filename


def test_load_config_creates_file_if_missing(tmp_path: Path):
    app_dir = tmp_path / "fresh_home"
    assert not (app_dir / "config.json").exists()

    load_config(app_dir)

    assert (app_dir / "config.json").exists()
