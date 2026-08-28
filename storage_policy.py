from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional


DATA_ROOT_ENV = "CONTAINER_AUDIT_DATA_ROOT"
DEFAULT_VENDOR_DIR = "KMTech"
DEFAULT_APP_DIR = "ContainerAudit"
DEFAULT_DIRECT_SYNC_APP_DIR = "container_audit"
ITEM_CATALOG_DIAGNOSTIC_FILENAME = "item_catalog_startup_diagnostic.json"
EVENTS_DIR_NAME = "events"
DIRECT_SYNC_DIR_NAME = "direct_sync"
CONFIG_DIR_NAME = "config"
PARKED_TRAYS_DIR_NAME = "parked_trays"
SETTINGS_FILE_NAME = "container_audit_settings.json"
WORKER_REGISTRY_FILE_NAME = "worker_registry.json"
BEST_TIME_RECORDS_FILE_NAME = "best_time_records.json"
LEGACY_SYNCTHING_ROOT = Path("C:/Sync")


@dataclass(frozen=True)
class ContainerAuditStoragePaths:
    data_root: Path
    events_dir: Path
    config_dir: Path
    settings_path: Path
    worker_registry_path: Path
    best_time_records_path: Path
    parked_trays_dir: Path
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
    item_catalog_diagnostic_path: Path


def _resolve_path(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def is_legacy_syncthing_path(path: Path | str) -> bool:
    candidate = _resolve_path(Path(path))
    legacy_root = _resolve_path(LEGACY_SYNCTHING_ROOT)
    try:
        return candidate == legacy_root or legacy_root in candidate.parents
    except RuntimeError:
        return False


def path_is_within(path: Path | str, root: Path | str) -> bool:
    """Return whether *path* is *root* or one of its descendants."""

    candidate = os.path.normcase(str(_resolve_path(Path(path))))
    selected_root = os.path.normcase(str(_resolve_path(Path(root))))
    try:
        return os.path.commonpath((candidate, selected_root)) == selected_root
    except ValueError:
        return False


def _absolute_environment_path(value: str, purpose: str) -> Path:
    candidate = Path(str(value or "").strip()).expanduser()
    if not candidate.is_absolute():
        raise ValueError(f"{purpose} must be an absolute current-user path")
    resolved = _resolve_path(candidate)
    if resolved == Path(resolved.anchor):
        raise ValueError(f"{purpose} must not be a filesystem root")
    return resolved


def current_user_data_home(environ: Mapping[str, str] | None = None) -> Path:
    """Resolve an absolute per-user data home without falling back to code/ProgramData."""

    values = os.environ if environ is None else environ
    local_app_data = str(values.get("LOCALAPPDATA") or "").strip()
    if local_app_data:
        return _absolute_environment_path(local_app_data, "LOCALAPPDATA")

    user_profile = str(values.get("USERPROFILE") or "").strip()
    if user_profile:
        return _absolute_environment_path(user_profile, "USERPROFILE") / "AppData" / "Local"

    if os.name != "nt":
        xdg_data_home = str(values.get("XDG_DATA_HOME") or "").strip()
        if xdg_data_home:
            return _absolute_environment_path(xdg_data_home, "XDG_DATA_HOME")
    try:
        home = Path.home()
    except (OSError, RuntimeError) as exc:
        raise ValueError("current-user data home is unavailable") from exc
    suffix = Path("AppData") / "Local" if os.name == "nt" else Path(".local") / "share"
    return _resolve_path(home / suffix)


def _default_data_root(environ: Mapping[str, str]) -> Path:
    env_root = str(environ.get(DATA_ROOT_ENV) or "").strip()
    if env_root:
        return _absolute_environment_path(env_root, DATA_ROOT_ENV)

    return current_user_data_home(environ) / DEFAULT_VENDOR_DIR / DEFAULT_APP_DIR


def _default_direct_sync_root(
    data_root: Path,
    *,
    explicit_data_root: bool,
    environ: Mapping[str, str],
) -> Path:
    if explicit_data_root:
        return data_root / DIRECT_SYNC_DIR_NAME
    return _resolve_path(
        current_user_data_home(environ)
        / DEFAULT_VENDOR_DIR
        / "DirectSync"
        / DEFAULT_DIRECT_SYNC_APP_DIR
    )


def build_container_audit_storage_paths(
    *,
    application_path: Optional[str] = None,
    data_root: Optional[Path | str] = None,
    environ: Mapping[str, str] | None = None,
) -> ContainerAuditStoragePaths:
    values = os.environ if environ is None else environ
    explicit_data_root = data_root is not None or bool(str(values.get(DATA_ROOT_ENV) or "").strip())
    if data_root is not None:
        selected = Path(data_root).expanduser()
        if not selected.is_absolute():
            raise ValueError("data_root must be an absolute current-user path")
        root = _resolve_path(selected)
        if root == Path(root.anchor):
            raise ValueError("data_root must not be a filesystem root")
    else:
        root = _default_data_root(values)
    if is_legacy_syncthing_path(root):
        raise ValueError(
            f"{DATA_ROOT_ENV} must not point at the legacy Syncthing folder "
            f"({LEGACY_SYNCTHING_ROOT}) for HTTPS-direct deployments."
        )

    events_dir = root / EVENTS_DIR_NAME
    config_dir = root / CONFIG_DIR_NAME
    parked_trays_dir = root / PARKED_TRAYS_DIR_NAME
    direct_sync_root = _default_direct_sync_root(
        root,
        explicit_data_root=explicit_data_root,
        environ=values,
    )
    if is_legacy_syncthing_path(direct_sync_root):
        raise ValueError(
            f"Container_Audit direct-sync root must not point at the legacy Syncthing folder "
            f"({LEGACY_SYNCTHING_ROOT}) for HTTPS-direct deployments."
        )
    if application_path:
        code_root = _resolve_path(Path(application_path))
        runtime_targets = (
            root,
            events_dir,
            config_dir,
            parked_trays_dir,
            direct_sync_root,
        )
        if any(
            path_is_within(target, code_root) or path_is_within(code_root, target)
            for target in runtime_targets
        ):
            raise ValueError(
                f"{DATA_ROOT_ENV} and derived runtime state must be outside the "
                "read-only application code root and must not contain it."
            )
    status_dir = direct_sync_root / "status"

    return ContainerAuditStoragePaths(
        data_root=root,
        events_dir=events_dir,
        config_dir=config_dir,
        settings_path=config_dir / SETTINGS_FILE_NAME,
        worker_registry_path=config_dir / WORKER_REGISTRY_FILE_NAME,
        best_time_records_path=config_dir / BEST_TIME_RECORDS_FILE_NAME,
        parked_trays_dir=parked_trays_dir,
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
        item_catalog_diagnostic_path=status_dir / ITEM_CATALOG_DIAGNOSTIC_FILENAME,
    )


def ensure_container_audit_storage_dirs(paths: ContainerAuditStoragePaths) -> None:
    for directory in (
        paths.data_root,
        paths.events_dir,
        paths.config_dir,
        paths.parked_trays_dir,
        paths.direct_sync_root,
        paths.queue_dir,
        paths.spool_dir,
        paths.status_dir,
        paths.logs_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)
