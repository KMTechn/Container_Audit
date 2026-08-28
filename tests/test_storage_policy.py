import csv
import datetime
import json
from pathlib import Path

import pytest

from Container_Audit import ContainerAudit
from session_history import load_session_history
from storage_policy import (
    DATA_ROOT_ENV,
    build_container_audit_storage_paths,
    is_legacy_syncthing_path,
)


def test_default_storage_paths_keep_business_and_direct_sync_in_current_user_scope(monkeypatch, tmp_path):
    local_app_data = tmp_path / "LocalAppData"
    program_data = tmp_path / "ProgramData"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setenv("PROGRAMDATA", str(program_data))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    paths = build_container_audit_storage_paths(application_path=str(tmp_path / "app"))

    assert paths.data_root == (local_app_data / "KMTech" / "ContainerAudit").resolve()
    assert paths.events_dir == paths.data_root / "events"
    assert paths.config_dir == paths.data_root / "config"
    assert paths.settings_path == paths.config_dir / "container_audit_settings.json"
    assert paths.worker_registry_path == paths.config_dir / "worker_registry.json"
    assert paths.best_time_records_path == paths.config_dir / "best_time_records.json"
    assert paths.parked_trays_dir == paths.data_root / "parked_trays"
    assert paths.direct_sync_root == (local_app_data / "KMTech" / "DirectSync" / "container_audit").resolve()
    assert paths.queue_dir == paths.direct_sync_root / "queue"
    assert (
        paths.item_catalog_diagnostic_path
        == paths.status_dir / "item_catalog_startup_diagnostic.json"
    )
    assert not is_legacy_syncthing_path(paths.data_root)
    assert not is_legacy_syncthing_path(paths.events_dir)
    assert not is_legacy_syncthing_path(paths.direct_sync_root)


def test_syncthing_data_root_is_rejected_by_default(monkeypatch, tmp_path):
    monkeypatch.setenv(DATA_ROOT_ENV, r"C:\Sync")

    with pytest.raises(ValueError, match="legacy Syncthing folder"):
        build_container_audit_storage_paths(application_path=str(tmp_path / "app"))


def test_syncthing_child_data_root_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv(DATA_ROOT_ENV, r"C:\Sync\ContainerAudit")

    with pytest.raises(ValueError, match="legacy Syncthing folder"):
        build_container_audit_storage_paths(application_path=str(tmp_path / "app"))


def test_container_audit_setup_uses_local_events_folder(monkeypatch, tmp_path):
    local_app_data = tmp_path / "LocalAppData"
    program_data = tmp_path / "ProgramData"
    application_path = tmp_path / "app"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setenv("PROGRAMDATA", str(program_data))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    app = ContainerAudit.__new__(ContainerAudit)
    app.application_path = str(application_path)

    app._setup_paths_and_dirs()

    expected_root = (local_app_data / "KMTech" / "ContainerAudit").resolve()
    expected_events = expected_root / "events"
    assert Path(app.data_root) == expected_root
    assert Path(app.save_folder) == expected_events
    assert Path(app.direct_sync_scan_source_dir) == expected_events
    assert Path(app.direct_sync_program_data_root) == (local_app_data / "KMTech" / "DirectSync" / "container_audit").resolve()
    assert expected_events.is_dir()
    assert Path(app.config_folder).is_dir()
    assert Path(app.parked_trays_dir).is_dir()
    assert Path(app.config_folder) == expected_root / "config"
    assert Path(app.parked_trays_dir) == expected_root / "parked_trays"
    assert not (application_path / "config").exists()


def test_missing_local_app_data_uses_user_profile_not_programdata_or_code(monkeypatch, tmp_path):
    user_profile = tmp_path / "Users" / "operator"
    program_data = tmp_path / "ProgramData"
    app_root = tmp_path / "app"
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("USERPROFILE", str(user_profile))
    monkeypatch.setenv("PROGRAMDATA", str(program_data))

    paths = build_container_audit_storage_paths(application_path=str(app_root))

    expected_home = (user_profile / "AppData" / "Local").resolve()
    assert paths.data_root == expected_home / "KMTech" / "ContainerAudit"
    assert paths.direct_sync_root == expected_home / "KMTech" / "DirectSync" / "container_audit"
    assert program_data.resolve() not in paths.data_root.parents
    assert app_root.resolve() not in paths.data_root.parents


@pytest.mark.parametrize("relative", ["runtime-state", ".\\runtime-state"])
def test_explicit_state_root_must_be_absolute(monkeypatch, tmp_path, relative):
    monkeypatch.setenv(DATA_ROOT_ENV, relative)

    with pytest.raises(ValueError, match="absolute"):
        build_container_audit_storage_paths(application_path=str(tmp_path / "app"))


@pytest.mark.parametrize("placement", ["same", "child", "ancestor"])
def test_runtime_state_and_code_root_must_be_disjoint(monkeypatch, tmp_path, placement):
    app_root = tmp_path / "apps" / "Container_Audit" / "current"
    if placement == "same":
        state_root = app_root
    elif placement == "child":
        state_root = app_root / "runtime-state"
    else:
        state_root = app_root.parent
    monkeypatch.setenv(DATA_ROOT_ENV, str(state_root))

    with pytest.raises(ValueError, match="read-only application code root"):
        build_container_audit_storage_paths(application_path=str(app_root))


def test_explicit_state_root_keeps_all_derived_writes_in_that_user_scope(monkeypatch, tmp_path):
    app_root = tmp_path / "app"
    state_root = tmp_path / "operator-state"
    monkeypatch.setenv(DATA_ROOT_ENV, str(state_root))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "ambient-local"))

    paths = build_container_audit_storage_paths(application_path=str(app_root))

    assert paths.data_root == state_root.resolve()
    assert paths.events_dir == state_root.resolve() / "events"
    assert paths.config_dir == state_root.resolve() / "config"
    assert paths.parked_trays_dir == state_root.resolve() / "parked_trays"
    assert paths.direct_sync_root == state_root.resolve() / "direct_sync"


def test_today_history_loads_offline_from_local_events_folder(monkeypatch, tmp_path):
    local_app_data = tmp_path / "LocalAppData"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)
    paths = build_container_audit_storage_paths(application_path=str(tmp_path / "app"))
    paths.events_dir.mkdir(parents=True)

    today = datetime.date(2026, 6, 25)
    worker = "offline_worker"
    item_code = "1234567890123"
    master_label = f"PHS=1|CLC={item_code}|WID=W1|SPC=SPEC|FPB=F1|OBD=20260625|PJT=P1|QT=2"
    log_path = paths.events_dir / f"이적작업이벤트로그_{worker}_{today:%Y%m%d}.csv"
    details = {
        "master_label_code": master_label,
        "item_code": item_code,
        "item_name": "Offline item",
        "spec": "SPEC",
        "scan_count": 2,
        "barcode_count": 2,
        "tray_capacity": 2,
        "product_barcodes": [f"{item_code}00001", f"{item_code}00002"],
        "work_time_sec": 12.5,
        "has_error_or_reset": False,
        "is_partial_submission": False,
        "is_restored_session": False,
        "is_test_tray": False,
    }
    with log_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-25T09:00:00",
                "worker_name": worker,
                "event": "TRAY_COMPLETE",
                "details": json.dumps(details, ensure_ascii=False),
            }
        )

    history = load_session_history(
        save_folder=paths.events_dir,
        worker_name=worker,
        today=today,
        tray_size=60,
    )

    assert history.log_file_path == str(log_path)
    assert history.total_tray_count == 1
    assert history.work_summary[item_code]["count"] == 1
