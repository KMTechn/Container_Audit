from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import direct_sync_auto_bootstrap
import current_user_onboarding as onboarding_module
from best_time_records import BestTimeRecordStore
from Container_Audit import ContainerAudit
from current_user_onboarding import (
    onboard_current_user,
    resolve_current_user_onboarding_paths,
    verify_bootstrap_integrity,
)
from direct_sync_push import manifest_hash
from event_log_store import append_event_log_entry
from parked_tray_store import ParkedTrayStore
from worker_registry import WorkerRegistry


pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="the production code-root ACL qualification requires Windows icacls",
)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _code_inventory(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _write_integrity_record(app_root: Path) -> None:
    files = []
    for path in sorted(
        (candidate for candidate in app_root.rglob("*") if candidate.is_file()),
        key=lambda candidate: candidate.relative_to(app_root).as_posix(),
    ):
        payload = path.read_bytes()
        files.append(
            {
                "path": path.relative_to(app_root).as_posix(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    aggregate = hashlib.sha256(
        "".join(
            f"{item['sha256']} {item['size']} {item['path']}\n"
            for item in files
        ).encode("utf-8")
    ).hexdigest()
    _write_json(
        app_root / "bootstrap-integrity.json",
        {
            "schema_version": "container-audit-bootstrap-integrity-v1",
            "status": "PASS",
            "code_root": str(app_root.resolve()),
            "file_count": len(files),
            "aggregate_sha256": aggregate,
            "files": files,
        },
    )


def _current_user_sid() -> str:
    result = subprocess.run(
        ["whoami.exe", "/user", "/fo", "csv", "/nh"],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    rows = list(csv.reader(result.stdout.splitlines()))
    if len(rows) != 1 or len(rows[0]) < 2 or not rows[0][1].startswith("S-1-"):
        raise AssertionError("could not resolve the current Windows SID")
    return rows[0][1]


def _icacls(path: Path, *arguments: str) -> None:
    result = subprocess.run(
        ["icacls.exe", str(path), *arguments],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        diagnostic = (result.stdout + result.stderr)[-4000:]
        raise AssertionError(f"icacls failed ({result.returncode}): {diagnostic}")


def _ready_state(paths) -> None:
    source_host_id = "container-audit-readonly-user"
    producer_install_id = "container-audit-readonly-install"
    identity = {
        "schema_version": "container-audit-producer-identity-v1",
        "producer_id": source_host_id,
        "source_host_id": source_host_id,
        "producer_install_id": producer_install_id,
        "enrollment_contract_version": "producer-self-enrollment-v2",
        "possession_key_contract_version": "producer-machine-possession-key-v1",
        "possession_key_fingerprint": (
            "EIEjk1nsv9vwrOp-3GrBvZz2WZPvy48vdViRVd6Llvg"
        ),
    }
    manifest = {
        "schema_version": "producer-onboarding-manifest-v1",
        "pc_identity": {
            "pc_id": "CONTAINER-READONLY-PC",
            "source_host_id": source_host_id,
            "producer_install_id": producer_install_id,
        },
        "apps": ["ContainerAudit"],
        "streams": [],
    }
    _write_json(paths.identity_path, identity)
    _write_json(paths.producer_manifest_path, manifest)
    _write_json(
        paths.credential_path,
        {
            "credential_schema_version": "producer-ingest-credential-reference-v1",
            "producer_id": source_host_id,
            "dpapi_scope": "current_user",
        },
    )
    _write_json(
        paths.registration_report_path,
        {
            "status": "SELF_ENROLLMENT_REGISTERED",
            "server_registration_verified": True,
            "manifest_hash_verified": True,
            "persisted_manifest_hash_verified": True,
            "manifest_hash": manifest_hash(manifest),
            "possession_key_verified": True,
            "enrollment_contract_version": "producer-self-enrollment-v2",
        },
    )
    _write_json(
        paths.logistics_profile_path,
        {
            "profile_version": 1,
            "source_host_id": source_host_id,
            "credential_scope": "current_user",
        },
    )
    paths.logistics_secret_path.parent.mkdir(parents=True, exist_ok=True)
    paths.logistics_secret_path.write_bytes(b"current-user-dpapi-fixture")


def _profile_loader(path: Path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    return SimpleNamespace(
        source_host_id=payload["source_host_id"],
        tls_ca_bundle_path="",
    )


def _credential_loader(_path: Path):
    return SimpleNamespace(producer_id="container-audit-readonly-user")


def test_runtime_operates_with_code_root_denied_write_and_preserves_inventory(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        onboarding_module,
        "_possession_key_readback",
        lambda _identity: {
            "status": "READY",
            "contract_version": "producer-machine-possession-key-v1",
            "scope": "current_user",
            "fingerprint": (
                "EIEjk1nsv9vwrOp-3GrBvZz2WZPvy48vdViRVd6Llvg"
            ),
            "export_policy": 0,
            "private_export_status": "0x80090029",
        },
    )
    app_root = tmp_path / "hardened-code"
    state_root = tmp_path / "current-user-state"
    (app_root / "config").mkdir(parents=True)
    (app_root / "Container_Audit.exe").write_bytes(b"immutable-executable")
    _write_json(
        app_root / "config" / "container_audit_settings.json",
        {
            "scale_factor": 1.0,
            "update_settings": {
                "mode": "signed_manifest",
                "provider": "private_cloudflare_r2",
            },
        },
    )
    _write_integrity_record(app_root)
    expected_code_inventory = _code_inventory(app_root)
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(state_root)}
    paths = resolve_current_user_onboarding_paths(app_root, environ=environment)
    sid = _current_user_sid()
    acl_added = False

    try:
        # Generic W also contains SYNCHRONIZE on Windows and can therefore
        # block read handles. Deny the concrete mutation rights while retaining
        # the RX production contract needed for integrity verification.
        _icacls(
            app_root,
            "/deny",
            f"*{sid}:(OI)(CI)(WD,AD,WA,WEA,DC)",
            "/T",
            "/C",
        )
        acl_added = True
        with pytest.raises(OSError):
            (app_root / "runtime-write-must-fail.txt").write_text(
                "forbidden",
                encoding="utf-8",
            )

        registration_calls = []

        def register(selected_paths):
            registration_calls.append(selected_paths)
            _ready_state(selected_paths)
            return 0

        onboarding_kwargs = {
            "environ": environment,
            "require_bootstrap_integrity": True,
            "registration_runner": register,
            "profile_loader": _profile_loader,
            "credential_loader": _credential_loader,
            "ledger_factory": lambda path: (
                path.parent.mkdir(parents=True, exist_ok=True),
                path.write_bytes(b"SQLite format 3\x00"),
            ),
            "autostart_installer": lambda _root: {
                "status": "PASS",
                "principal": "current_user",
            },
            "relay_launcher": lambda _root: {
                "status": "START_REQUESTED",
                "process_id": 123,
            },
        }
        first = onboard_current_user(app_root, **onboarding_kwargs)
        second = onboard_current_user(app_root, **onboarding_kwargs)

        assert first["action"] == "CREATED"
        assert second["action"] == "REUSED"
        assert len(registration_calls) == 1

        monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(state_root))
        application = ContainerAudit.__new__(ContainerAudit)
        application.application_path = str(app_root)
        application._setup_paths_and_dirs()
        assert application.load_app_settings()["scale_factor"] == 1.0
        application.scale_factor = 1.25
        application.column_widths = {"item": 120}
        application.paned_window_sash_positions = [300]
        application.internal_test_commands_enabled = False
        application.save_settings()

        registry = WorkerRegistry(str(application.storage_paths.worker_registry_path))
        registry.register("READONLY-WORKER")
        registry.mark_recent("READONLY-WORKER")
        BestTimeRecordStore(
            application.storage_paths.best_time_records_path
        ).update_best_time({}, 12.5)
        parked_path = ParkedTrayStore(
            application.storage_paths.parked_trays_dir
        ).save_state(
            {"item_name": "readonly qualification", "scanned_barcodes": []},
            worker_name="RW",
            master_label="L",
        )
        event_path = application.storage_paths.events_dir / "qualification.csv"
        append_event_log_entry(
            str(event_path),
            {
                "timestamp": "2026-08-28T00:00:00+09:00",
                "worker_name": "READONLY-WORKER",
                "event": "READONLY_ROOT_QUALIFICATION",
                "details": "{}",
            },
            durable=True,
        )

        monkeypatch.setattr(
            direct_sync_auto_bootstrap,
            "run_session_direct_sync_once",
            lambda **_kwargs: {"status": "PASS", "returncode": 0},
        )
        sync_report = direct_sync_auto_bootstrap.run_direct_sync_auto_bootstrap(
            app_root=app_root,
            direct_sync_root=application.storage_paths.direct_sync_root,
            scan_source_dir=application.storage_paths.events_dir,
        )

        assert sync_report["status"] == "PASS"
        assert application.storage_paths.settings_path.is_file()
        assert application.storage_paths.worker_registry_path.is_file()
        assert application.storage_paths.best_time_records_path.is_file()
        assert parked_path.is_file()
        assert event_path.is_file()
        assert application.storage_paths.item_catalog_diagnostic_path.parent.is_dir()
        for state_path in (
            application.storage_paths.settings_path,
            application.storage_paths.worker_registry_path,
            application.storage_paths.best_time_records_path,
            parked_path,
            event_path,
            paths.ledger_path,
        ):
            assert state_path.resolve().is_relative_to(state_root.resolve())
        assert verify_bootstrap_integrity(paths, required=True)["status"] == "PASS"
        assert _code_inventory(app_root) == expected_code_inventory
    finally:
        if acl_added:
            _icacls(app_root, "/remove:d", f"*{sid}", "/T", "/C")

    assert _code_inventory(app_root) == expected_code_inventory
