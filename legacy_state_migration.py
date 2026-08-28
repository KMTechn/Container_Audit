"""Read-only migration of legacy runtime state out of the application tree."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any
import uuid

from storage_policy import (
    BEST_TIME_RECORDS_FILE_NAME,
    CONFIG_DIR_NAME,
    PARKED_TRAYS_DIR_NAME,
    SETTINGS_FILE_NAME,
    WORKER_REGISTRY_FILE_NAME,
    path_is_within,
)
from storage_utils import atomic_write_json


MIGRATION_SCHEMA = "container-audit-code-state-migration-v1"
MIGRATION_MARKER_NAME = "legacy-code-root-state-migration.json"
MAX_LEGACY_STATE_FILE_BYTES = 8 * 1024 * 1024
MAX_LEGACY_PARKED_FILES = 10_000
MAX_LEGACY_PARKED_BYTES = 64 * 1024 * 1024


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_file_once(source: Path, destination: Path) -> dict[str, Any]:
    """Copy one bounded regular file without ever changing or deleting *source*."""

    if source.is_symlink() or not source.is_file():
        raise ValueError(f"legacy state source is not a regular file: {source}")
    size = source.stat().st_size
    if size < 0 or size > MAX_LEGACY_STATE_FILE_BYTES:
        raise ValueError(f"legacy state source size is invalid: {source}")
    source_hash = _file_sha256(source)
    if destination.exists():
        if destination.is_symlink() or not destination.is_file():
            raise ValueError(f"current-user state target is not a regular file: {destination}")
        return {
            "name": destination.name,
            "action": "PRESERVED_EXISTING",
            "source_size": size,
            "source_sha256": source_hash,
        }

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.{uuid.uuid4().hex}.migration"
    )
    try:
        with source.open("rb") as source_handle, temporary.open("xb") as target_handle:
            for chunk in iter(lambda: source_handle.read(1024 * 1024), b""):
                target_handle.write(chunk)
            target_handle.flush()
            os.fsync(target_handle.fileno())
        # os.rename is intentionally non-replacing on Windows, the production
        # platform. A concurrently created user-state file must win.
        os.rename(temporary, destination)
        if destination.stat().st_size != size or _file_sha256(destination) != source_hash:
            raise OSError(f"legacy state exact readback failed: {destination}")
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    return {
        "name": destination.name,
        "action": "COPIED_READ_ONLY_SOURCE",
        "source_size": size,
        "source_sha256": source_hash,
    }


def _safe_int_mapping(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    return {
        key: item
        for key, item in value.items()
        if isinstance(key, str)
        and isinstance(item, int)
        and not isinstance(item, bool)
        and item >= 0
    }


def _seed_legacy_ui_settings_once(
    source: Path,
    destination: Path,
) -> dict[str, Any]:
    """Seed only UI preferences; packaged update authority never becomes state."""

    if source.is_symlink() or not source.is_file():
        raise ValueError(f"legacy settings source is not a regular file: {source}")
    size = source.stat().st_size
    if size <= 0 or size > MAX_LEGACY_STATE_FILE_BYTES:
        raise ValueError(f"legacy settings source size is invalid: {source}")
    source_hash = _file_sha256(source)
    if destination.exists():
        if destination.is_symlink() or not destination.is_file():
            raise ValueError(
                f"current-user settings target is not a regular file: {destination}"
            )
        return {
            "name": destination.name,
            "kind": "ui_settings",
            "action": "PRESERVED_EXISTING",
            "source_size": size,
            "source_sha256": source_hash,
        }
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {
            "name": destination.name,
            "kind": "ui_settings",
            "action": "SKIPPED_INVALID",
            "source_size": size,
            "source_sha256": source_hash,
        }
    if not isinstance(raw, dict):
        raw = {}
    settings: dict[str, Any] = {}
    scale_factor = raw.get("scale_factor")
    if isinstance(scale_factor, (int, float)) and not isinstance(scale_factor, bool):
        settings["scale_factor"] = max(0.7, min(2.5, float(scale_factor)))
    column_widths = _safe_int_mapping(raw.get("column_widths_validator"))
    if column_widths:
        settings["column_widths_validator"] = column_widths
    sash_positions = _safe_int_mapping(raw.get("paned_window_sash_positions"))
    if sash_positions:
        settings["paned_window_sash_positions"] = sash_positions
    if not settings:
        return {
            "name": destination.name,
            "kind": "ui_settings",
            "action": "SKIPPED_NO_UI_STATE",
            "source_size": size,
            "source_sha256": source_hash,
        }
    atomic_write_json(
        destination,
        settings,
        indent=4,
        ensure_ascii=False,
        trailing_newline=True,
    )
    if json.loads(destination.read_text(encoding="utf-8")) != settings:
        raise OSError(f"current-user settings readback failed: {destination}")
    return {
        "name": destination.name,
        "kind": "ui_settings",
        "action": "SEEDED_SANITIZED_UI_SETTINGS",
        "source_size": size,
        "source_sha256": source_hash,
    }


def migrate_legacy_code_root_state(
    *,
    application_path: str | os.PathLike[str],
    config_dir: str | os.PathLike[str],
    parked_trays_dir: str | os.PathLike[str],
) -> dict[str, Any]:
    """Seed current-user state from legacy code-root files exactly once.

    The legacy tree is a read-only source. Files are copied with exact hash
    readback, existing current-user files always win, and nothing in the code
    root is renamed, deleted, normalized, or quarantined.
    """

    code_root = Path(application_path).expanduser().resolve(strict=False)
    selected_config_dir = Path(config_dir).expanduser().resolve(strict=False)
    selected_parked_dir = Path(parked_trays_dir).expanduser().resolve(strict=False)
    for destination_root in (selected_config_dir, selected_parked_dir):
        if path_is_within(destination_root, code_root) or path_is_within(
            code_root,
            destination_root,
        ):
            raise ValueError("legacy state migration target must be outside the code root")

    selected_config_dir.mkdir(parents=True, exist_ok=True)
    selected_parked_dir.mkdir(parents=True, exist_ok=True)
    marker = selected_config_dir / MIGRATION_MARKER_NAME
    if marker.exists():
        if marker.is_symlink() or not marker.is_file():
            raise ValueError("legacy state migration marker is not a regular file")
        try:
            if marker.stat().st_size > MAX_LEGACY_STATE_FILE_BYTES:
                raise ValueError("legacy state migration marker size is invalid")
            marker_payload = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("legacy state migration marker is invalid") from exc
        if (
            not isinstance(marker_payload, dict)
            or marker_payload.get("schema_version") != MIGRATION_SCHEMA
            or marker_payload.get("status") != "PASS"
        ):
            raise ValueError("legacy state migration marker is invalid")
        return {
            "schema_version": MIGRATION_SCHEMA,
            "status": "REUSED",
            "marker_path": str(marker),
        }

    legacy_config_dir = code_root / CONFIG_DIR_NAME
    migrated: list[dict[str, Any]] = []
    legacy_settings = legacy_config_dir / SETTINGS_FILE_NAME
    if legacy_settings.exists():
        migrated.append(
            _seed_legacy_ui_settings_once(
                legacy_settings,
                selected_config_dir / SETTINGS_FILE_NAME,
            )
        )
    for name in (
        WORKER_REGISTRY_FILE_NAME,
        BEST_TIME_RECORDS_FILE_NAME,
    ):
        source = legacy_config_dir / name
        if not source.exists():
            continue
        migrated.append(_copy_file_once(source, selected_config_dir / name))

    legacy_parked_dir = code_root / CONFIG_DIR_NAME / PARKED_TRAYS_DIR_NAME
    parked_sources: list[Path] = []
    if legacy_parked_dir.exists():
        if legacy_parked_dir.is_symlink() or not legacy_parked_dir.is_dir():
            raise ValueError("legacy parked-tray source is not a regular directory")
        parked_sources = sorted(legacy_parked_dir.glob("*.json"), key=lambda path: path.name.casefold())
        if len(parked_sources) > MAX_LEGACY_PARKED_FILES:
            raise ValueError("legacy parked-tray file count exceeds the migration bound")
        total_bytes = sum(path.stat().st_size for path in parked_sources)
        if total_bytes > MAX_LEGACY_PARKED_BYTES:
            raise ValueError("legacy parked-tray bytes exceed the migration bound")
    folded_names: set[str] = set()
    for source in parked_sources:
        folded = source.name.casefold()
        if folded in folded_names:
            raise ValueError("legacy parked-tray filenames collide case-insensitively")
        folded_names.add(folded)
        entry = _copy_file_once(source, selected_parked_dir / source.name)
        entry["kind"] = "parked_tray"
        migrated.append(entry)

    report = {
        "schema_version": MIGRATION_SCHEMA,
        "status": "PASS",
        "captured_at": _now(),
        "source_policy": "READ_ONLY_NO_DELETE",
        "source_code_root": str(code_root),
        "config_root": str(selected_config_dir),
        "parked_trays_root": str(selected_parked_dir),
        "files": migrated,
    }
    atomic_write_json(marker, report, indent=2, ensure_ascii=False, trailing_newline=True)
    return {**report, "marker_path": str(marker)}


__all__ = [
    "MIGRATION_MARKER_NAME",
    "MIGRATION_SCHEMA",
    "migrate_legacy_code_root_state",
]
