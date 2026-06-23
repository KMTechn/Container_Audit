import json

import pytest

from tools import check_release_config


def write_settings(config_dir, payload):
    config_dir.mkdir()
    (config_dir / "container_audit_settings.json").write_text(
        json.dumps(payload, ensure_ascii=False),
        encoding="utf-8",
    )


def test_release_config_accepts_safe_default_settings(tmp_path):
    config_dir = tmp_path / "config"
    write_settings(
        config_dir,
        {
            "scale_factor": 1.0,
            "column_widths_validator": {},
            "paned_window_sash_positions": {"0": 500},
            "enable_internal_test_commands": False,
        },
    )

    check_release_config.validate_release_config(config_dir)


def test_release_config_rejects_enabled_internal_test_commands(tmp_path):
    config_dir = tmp_path / "config"
    write_settings(config_dir, {"enable_internal_test_commands": True})

    with pytest.raises(ValueError, match="enable_internal_test_commands"):
        check_release_config.validate_release_config(config_dir)


def test_release_config_rejects_runtime_local_artifacts(tmp_path):
    config_dir = tmp_path / "config"
    write_settings(config_dir, {"scale_factor": 1.0})
    (config_dir / "worker_registry.json").write_text("{}", encoding="utf-8")
    (config_dir / "parked_trays").mkdir()

    with pytest.raises(ValueError, match="runtime-local artifacts"):
        check_release_config.validate_release_config(config_dir)


def test_release_config_rejects_unknown_files_and_directories(tmp_path):
    config_dir = tmp_path / "config"
    write_settings(config_dir, {"scale_factor": 1.0})
    (config_dir / "credential.json").write_text("{}", encoding="utf-8")
    (config_dir / ".secret").write_text("secret", encoding="utf-8")
    (config_dir / "nested").mkdir()

    with pytest.raises(ValueError) as exc_info:
        check_release_config.validate_release_config(config_dir)

    message = str(exc_info.value)
    assert "unknown files" in message
    assert ".secret" in message
    assert "credential.json" in message
    assert "nested" in message


def test_release_config_rejects_unknown_settings_keys(tmp_path):
    config_dir = tmp_path / "config"
    write_settings(config_dir, {"scale_factor": 1.0, "experimental_flag": False})

    with pytest.raises(ValueError, match="unknown keys: experimental_flag"):
        check_release_config.validate_release_config(config_dir)


def test_release_config_rejects_malformed_settings_shape(tmp_path):
    config_dir = tmp_path / "config"
    write_settings(
        config_dir,
        {
            "scale_factor": "bad",
            "column_widths_validator": {"item": True},
        },
    )

    with pytest.raises(ValueError, match="scale_factor"):
        check_release_config.validate_release_config(config_dir)
