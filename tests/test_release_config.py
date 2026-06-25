import json

import pytest

from tools import build_release_config
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


def test_release_config_rejects_forbidden_markers_inside_allowed_settings(tmp_path):
    config_dir = tmp_path / "config"
    write_settings(
        config_dir,
        {
            "scale_factor": 1.0,
            "column_widths_validator": {
                "endpoint_url": 120,
            },
            "paned_window_sash_positions": {
                "debug_fault_injection": 1,
            },
        },
    )

    with pytest.raises(ValueError, match="forbidden release marker"):
        check_release_config.validate_release_config(config_dir)


@pytest.mark.parametrize(
    "marker",
    [
        "secret",
        "api_key",
        "hmac",
        "producer",
        "credential",
        "http://localhost:8089",
        "https://175.45.200.171/api/producer-ingest/v1/source-file",
    ],
)
def test_release_config_rejects_secret_and_endpoint_markers_even_when_shape_is_valid(tmp_path, marker):
    config_dir = tmp_path / "config"
    write_settings(
        config_dir,
        {
            "scale_factor": 1.0,
            "column_widths_validator": {
                f"summary_tree_{marker}": 120,
            },
        },
    )

    with pytest.raises(ValueError, match="forbidden release marker"):
        check_release_config.validate_release_config(config_dir)


def test_build_release_config_copies_only_valid_settings_and_excludes_runtime_artifacts(tmp_path):
    source_config = tmp_path / "runtime-config"
    write_settings(
        source_config,
        {
            "scale_factor": 1.0,
            "column_widths_validator": {"summary_tree_item_code": 120},
            "paned_window_sash_positions": {"0": 500},
        },
    )
    (source_config / "parked_trays").mkdir()
    (source_config / "parked_trays" / "parked_tray_1.json").write_text("{}", encoding="utf-8")
    (source_config / "validator_settings.json").write_text("{}", encoding="utf-8")
    (source_config / "credential.json").write_text('{"secret": "do-not-copy"}', encoding="utf-8")

    output_config = tmp_path / "release-config"

    result = build_release_config.build_release_config(source_config, output_config)

    assert result == output_config
    assert sorted(child.name for child in output_config.iterdir()) == ["container_audit_settings.json"]
    assert not (output_config / "parked_trays").exists()
    assert not (output_config / "validator_settings.json").exists()
    assert not (output_config / "credential.json").exists()
    check_release_config.validate_release_config(output_config)


def test_build_release_config_fails_closed_when_settings_contains_forbidden_marker(tmp_path):
    source_config = tmp_path / "runtime-config"
    write_settings(
        source_config,
        {
            "scale_factor": 1.0,
            "column_widths_validator": {
                "https://175.45.200.171/api/producer-ingest/v1/source-file": 120,
            },
        },
    )

    with pytest.raises(ValueError, match="forbidden release marker"):
        build_release_config.build_release_config(source_config, tmp_path / "release-config")
