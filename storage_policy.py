from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


DATA_ROOT_ENV = "CONTAINER_AUDIT_DATA_ROOT"
DEFAULT_VENDOR_DIR = "KMTech"
DEFAULT_APP_DIR = "ContainerAudit"
DEFAULT_DIRECT_SYNC_APP_DIR = "container_audit"
EVENTS_DIR_NAME = "events"
DIRECT_SYNC_DIR_NAME = "direct_sync"
LEGACY_SYNCTHING_ROOT = Path("C:/Sync")


@dataclass(frozen=True)
class ContainerAuditStoragePaths:
    data_root: Path
    events_dir: Path
    direct_sync_root: Path
    queue_dir: Path
    spool_dir: Path
    status_dir: Path
    logs_dir: Path
    producer_manifest_path: Path
    credential_path: Path
    client_state_db_path: Path
    operator_pause_path: Path
    status_path: Path


def _resolve_path(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def is_legacy_syncthing_path(path: Path | str) -> bool:
    candidate = _resolve_path(Path(path))
    legacy_root = _resolve_path(LEGACY_SYNCTHING_ROOT)
    try:
        return candidate == legacy_root or legacy_root in candidate.parents
    except RuntimeError:
        return False


def _default_data_root(application_path: Optional[str] = None) -> Path:
    env_root = os.getenv(DATA_ROOT_ENV)
    if env_root:
        return _resolve_path(Path(env_root))

    local_app_data = os.getenv("LOCALAPPDATA")
    if local_app_data:
        return _resolve_path(Path(local_app_data) / DEFAULT_VENDOR_DIR / DEFAULT_APP_DIR)

    program_data = os.getenv("PROGRAMDATA")
    if program_data:
        return _resolve_path(Path(program_data) / DEFAULT_VENDOR_DIR / DEFAULT_APP_DIR)

    if application_path:
        return _resolve_path(Path(application_path) / "runtime_data")

    return _resolve_path(Path.cwd() / "runtime_data")


def _default_direct_sync_root(data_root: Path, application_path: Optional[str] = None) -> Path:
    if os.getenv(DATA_ROOT_ENV):
        return data_root / DIRECT_SYNC_DIR_NAME

    program_data = os.getenv("PROGRAMDATA")
    if program_data:
        return _resolve_path(Path(program_data) / DEFAULT_VENDOR_DIR / "DirectSync" / DEFAULT_DIRECT_SYNC_APP_DIR)

    if application_path:
        return _resolve_path(Path(application_path) / "runtime_data" / DIRECT_SYNC_DIR_NAME)

    return _resolve_path(Path.cwd() / "runtime_data" / DIRECT_SYNC_DIR_NAME)


def build_container_audit_storage_paths(
    *,
    application_path: Optional[str] = None,
    data_root: Optional[Path | str] = None,
) -> ContainerAuditStoragePaths:
    root = _resolve_path(Path(data_root)) if data_root is not None else _default_data_root(application_path)
    if is_legacy_syncthing_path(root):
        raise ValueError(
            f"{DATA_ROOT_ENV} must not point at the legacy Syncthing folder "
            f"({LEGACY_SYNCTHING_ROOT}) for HTTPS-direct deployments."
        )

    events_dir = root / EVENTS_DIR_NAME
    direct_sync_root = _default_direct_sync_root(root, application_path)
    if is_legacy_syncthing_path(direct_sync_root):
        raise ValueError(
            f"Container_Audit direct-sync root must not point at the legacy Syncthing folder "
            f"({LEGACY_SYNCTHING_ROOT}) for HTTPS-direct deployments."
        )
    status_dir = direct_sync_root / "status"

    return ContainerAuditStoragePaths(
        data_root=root,
        events_dir=events_dir,
        direct_sync_root=direct_sync_root,
        queue_dir=direct_sync_root / "queue",
        spool_dir=direct_sync_root / "spool",
        status_dir=status_dir,
        logs_dir=direct_sync_root / "logs",
        producer_manifest_path=direct_sync_root / "producer_manifest.json",
        credential_path=direct_sync_root / "credential.json",
        client_state_db_path=direct_sync_root / "client_state.sqlite3",
        operator_pause_path=direct_sync_root / "operator_pause.json",
        status_path=status_dir / "status.json",
    )


def ensure_container_audit_storage_dirs(paths: ContainerAuditStoragePaths) -> None:
    for directory in (
        paths.data_root,
        paths.events_dir,
        paths.direct_sync_root,
        paths.queue_dir,
        paths.spool_dir,
        paths.status_dir,
        paths.logs_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)
