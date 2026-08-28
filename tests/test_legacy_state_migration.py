from __future__ import annotations

import json
from pathlib import Path

import pytest

from legacy_state_migration import (
    MIGRATION_MARKER_NAME,
    migrate_legacy_code_root_state,
)


def _write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_legacy_runtime_state_is_hash_copied_without_mutating_code_root(tmp_path):
    code_root = tmp_path / "code"
    state_root = tmp_path / "state"
    _write(code_root / "config" / "worker_registry.json", b'{"workers": []}\n')
    _write(code_root / "config" / "best_time_records.json", b'{"2026-08-28": 5.5}\n')
    _write(
        code_root / "config" / "container_audit_settings.json",
        (
            b'{"scale_factor": 1.4, "column_widths_validator": {"item": 120}, '
            b'"update_settings": {"provider": "legacy-runtime"}}\n'
        ),
    )
    _write(
        code_root / "config" / "parked_trays" / "parked_legacy.json",
        b'{"worker_name": "legacy"}\n',
    )
    before = _snapshot(code_root)

    report = migrate_legacy_code_root_state(
        application_path=code_root,
        config_dir=state_root / "config",
        parked_trays_dir=state_root / "parked_trays",
    )

    assert report["status"] == "PASS"
    assert report["source_policy"] == "READ_ONLY_NO_DELETE"
    assert (state_root / "config" / "worker_registry.json").read_bytes() == before[
        "config/worker_registry.json"
    ]
    assert (state_root / "config" / "best_time_records.json").read_bytes() == before[
        "config/best_time_records.json"
    ]
    assert (state_root / "parked_trays" / "parked_legacy.json").read_bytes() == before[
        "config/parked_trays/parked_legacy.json"
    ]
    migrated_settings = json.loads(
        (state_root / "config" / "container_audit_settings.json").read_text(
            encoding="utf-8"
        )
    )
    assert migrated_settings == {
        "scale_factor": 1.4,
        "column_widths_validator": {"item": 120},
    }
    assert "update_settings" not in migrated_settings
    assert (state_root / "config" / MIGRATION_MARKER_NAME).is_file()
    assert _snapshot(code_root) == before


def test_existing_current_user_state_wins_and_completed_migration_is_reused(tmp_path):
    code_root = tmp_path / "code"
    state_root = tmp_path / "state"
    source = b'{"workers": [{"name": "legacy"}]}\n'
    current = b'{"workers": [{"name": "current-user"}]}\n'
    _write(code_root / "config" / "worker_registry.json", source)
    _write(state_root / "config" / "worker_registry.json", current)
    before = _snapshot(code_root)

    first = migrate_legacy_code_root_state(
        application_path=code_root,
        config_dir=state_root / "config",
        parked_trays_dir=state_root / "parked_trays",
    )
    second = migrate_legacy_code_root_state(
        application_path=code_root,
        config_dir=state_root / "config",
        parked_trays_dir=state_root / "parked_trays",
    )

    assert first["files"][0]["action"] == "PRESERVED_EXISTING"
    assert second["status"] == "REUSED"
    assert (state_root / "config" / "worker_registry.json").read_bytes() == current
    assert _snapshot(code_root) == before


@pytest.mark.parametrize("placement", ["inside", "ancestor"])
def test_migration_rejects_destinations_inside_or_around_code_root(
    tmp_path,
    placement,
):
    code_root = tmp_path / "code"
    code_root.mkdir()
    config_dir = (
        code_root / "config-user"
        if placement == "inside"
        else tmp_path
    )

    with pytest.raises(ValueError, match="outside the code root"):
        migrate_legacy_code_root_state(
            application_path=code_root,
            config_dir=config_dir,
            parked_trays_dir=tmp_path / "parked",
        )


def test_invalid_migration_marker_fails_closed(tmp_path):
    code_root = tmp_path / "code"
    config_root = tmp_path / "state" / "config"
    code_root.mkdir()
    _write(config_root / MIGRATION_MARKER_NAME, json.dumps({"status": "UNKNOWN"}).encode())

    with pytest.raises(ValueError, match="marker is invalid"):
        migrate_legacy_code_root_state(
            application_path=code_root,
            config_dir=config_root,
            parked_trays_dir=tmp_path / "state" / "parked_trays",
        )
