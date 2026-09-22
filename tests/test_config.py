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


def test_ollama_host_rejects_remote_addresses(tmp_path: Path):
    from secure.config import AppConfig
    import pytest

    app_dir = tmp_path / "config_home"

    invalid_hosts = [
        "http://192.168.1.100:11434",
        "https://api.example.com",
        "http://ollama.internal:11434",
        "http://10.0.0.1:8000",
    ]

    for host in invalid_hosts:
        with pytest.raises(ValueError, match="ollama_host must be localhost only"):
            cfg = default_config()
            cfg.app_dir = str(app_dir)
            cfg.ollama_host = host
            cfg.__post_init__()


def test_local_llm_host_rejects_remote_addresses(tmp_path: Path):
    from secure.config import AppConfig
    import pytest

    app_dir = tmp_path / "config_home"

    invalid_hosts = [
        "http://192.168.1.100:8000",
        "https://llm.example.com",
    ]

    for host in invalid_hosts:
        with pytest.raises(ValueError, match="local_llm_host must be localhost only"):
            cfg = default_config()
            cfg.app_dir = str(app_dir)
            cfg.local_llm_host = host
            cfg.__post_init__()


def test_localhost_addresses_accepted_for_ai_hosts(tmp_path: Path):
    app_dir = tmp_path / "config_home"

    valid_hosts = [
        "http://127.0.0.1:11434",
        "http://localhost:11434",
        "https://localhost:8000",
        "http://127.0.0.1:8000/v1",
        "http://localhost:1234/v1",
    ]

    for host in valid_hosts:
        cfg = default_config()
        cfg.app_dir = str(app_dir)
        cfg.ollama_host = host
        cfg.__post_init__()  # Should not raise
        assert cfg.ollama_host == host
