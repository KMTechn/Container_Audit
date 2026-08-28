import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import current_user_onboarding as onboarding_module
from current_user_onboarding import (
    CurrentUserOnboardingError,
    ENROLLMENT_TLS_CA_BUNDLE_PATH_ENV,
    inspect_current_user_state,
    onboard_current_user,
    remove_current_user_setup,
    resolve_current_user_onboarding_paths,
    verify_bootstrap_integrity,
)
from direct_sync_push import manifest_hash


TEST_POSSESSION_FINGERPRINT = "EIEjk1nsv9vwrOp-3GrBvZz2WZPvy48vdViRVd6Llvg"


class _FakeExistingPossessionKey:
    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        return None

    def descriptor(self):
        return SimpleNamespace(
            contract_version=onboarding_module.POSSESSION_KEY_CONTRACT_VERSION,
            scope=onboarding_module.SCOPE_CURRENT_USER,
            fingerprint=TEST_POSSESSION_FINGERPRINT,
            export_policy=0,
        )

    def assert_non_exportable(self):
        return SimpleNamespace(private_export_status_hex="0x80090029")


@pytest.fixture(autouse=True)
def _fake_existing_possession_key(monkeypatch):
    monkeypatch.setattr(
        onboarding_module.PersistentPossessionKey,
        "open_existing",
        classmethod(
            lambda _cls, *args, **kwargs: _FakeExistingPossessionKey()
        ),
    )


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _ready_state(paths, *, source_host_id="container-audit-user-1"):
    identity = {
        "schema_version": "container-audit-producer-identity-v1",
        "producer_id": source_host_id,
        "source_host_id": source_host_id,
        "producer_install_id": "container-audit-install-1",
        "enrollment_contract_version": (
            onboarding_module.SELF_ENROLLMENT_CONTRACT_VERSION
        ),
        "possession_key_contract_version": (
            onboarding_module.POSSESSION_KEY_CONTRACT_VERSION
        ),
        "possession_key_fingerprint": TEST_POSSESSION_FINGERPRINT,
    }
    manifest = {
        "schema_version": "producer-onboarding-manifest-v1",
        "pc_identity": {
            "pc_id": "CONTAINER-PC01",
            "source_host_id": source_host_id,
            "producer_install_id": identity["producer_install_id"],
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
            "possession_key_verified": True,
            "enrollment_contract_version": (
                onboarding_module.SELF_ENROLLMENT_CONTRACT_VERSION
            ),
            "manifest_hash": manifest_hash(manifest),
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
    return identity


def _profile_loader(path: Path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    return SimpleNamespace(
        source_host_id=payload["source_host_id"],
        tls_ca_bundle_path=payload.get("tls_ca_bundle_path", ""),
    )


def _credential_loader(_path: Path):
    return SimpleNamespace(producer_id="container-audit-user-1")


def _ledger_factory(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"SQLite format 3\x00")


def _autostart(_app_root):
    return {"status": "PASS", "principal": "current_user"}


def _relay_start(_app_root):
    return {"status": "START_REQUESTED", "process_id": 123}


def test_state_absent_partial_and_existing_are_distinguished(tmp_path):
    paths = resolve_current_user_onboarding_paths(
        tmp_path / "app",
        environ={"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")},
    )
    assert inspect_current_user_state(
        paths,
        profile_loader=_profile_loader,
        credential_loader=_credential_loader,
    )["status"] == "ABSENT"
    _write_json(paths.identity_path, {"source_host_id": "partial"})
    partial = inspect_current_user_state(
        paths,
        profile_loader=_profile_loader,
        credential_loader=_credential_loader,
    )
    assert partial["status"] == "RECOVERY_REQUIRED"
    paths.identity_path.unlink()
    _ready_state(paths)
    ready = inspect_current_user_state(
        paths,
        profile_loader=_profile_loader,
        credential_loader=_credential_loader,
    )
    assert ready["status"] == "READY"
    assert ready["source_host_id"] == "container-audit-user-1"
    assert ready["possession_key"]["scope"] == "current_user"
    assert ready["possession_key"]["fingerprint"] == (
        TEST_POSSESSION_FINGERPRINT
    )


def test_admin_recovery_report_is_terminal_not_retryable(tmp_path):
    paths = resolve_current_user_onboarding_paths(
        tmp_path / "app",
        environ={"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")},
    )
    _write_json(
        paths.registration_report_path,
        {
            "status": onboarding_module.ADMIN_RECOVERY_ACTION,
            "recovery_action": onboarding_module.ADMIN_RECOVERY_ACTION,
            "enrollment_error_code": "admin_recovery_required",
            "blocked_reason": "existing legacy producer requires audited recovery",
        },
    )

    state = inspect_current_user_state(paths)

    assert state["status"] == "RECOVERY_REQUIRED"
    assert state["recovery_action"] == onboarding_module.ADMIN_RECOVERY_ACTION
    assert state["enrollment_error_code"] == "admin_recovery_required"


def test_legacy_complete_state_requires_admin_recovery_without_opening_key(
    tmp_path, monkeypatch
):
    paths = resolve_current_user_onboarding_paths(
        tmp_path / "app",
        environ={"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")},
    )
    _ready_state(paths)
    identity = json.loads(paths.identity_path.read_text(encoding="utf-8"))
    for field in (
        "enrollment_contract_version",
        "possession_key_contract_version",
        "possession_key_fingerprint",
    ):
        identity.pop(field)
    _write_json(paths.identity_path, identity)
    monkeypatch.setattr(
        onboarding_module.PersistentPossessionKey,
        "open_existing",
        classmethod(
            lambda _cls, *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("legacy state must not open or create a new key")
            )
        ),
    )

    state = inspect_current_user_state(
        paths,
        profile_loader=_profile_loader,
        credential_loader=_credential_loader,
    )

    assert state["status"] == "RECOVERY_REQUIRED"
    assert state["recovery_action"] == onboarding_module.ADMIN_RECOVERY_ACTION
    assert "legacy producer identity" in state["reason"]


def test_first_run_creates_state_and_second_run_reuses_identity(tmp_path):
    app_root = tmp_path / "hardened-app"
    app_root.mkdir()
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "user-state")}
    paths = resolve_current_user_onboarding_paths(app_root, environ=environment)
    registration_calls = []

    def register(selected_paths):
        registration_calls.append(selected_paths)
        _ready_state(selected_paths)
        return 0

    kwargs = {
        "environ": environment,
        "require_bootstrap_integrity": False,
        "registration_runner": register,
        "profile_loader": _profile_loader,
        "credential_loader": _credential_loader,
        "ledger_factory": _ledger_factory,
        "autostart_installer": _autostart,
        "relay_launcher": _relay_start,
    }

    first = onboard_current_user(app_root, **kwargs)
    identity_before = paths.identity_path.read_bytes()
    second = onboard_current_user(app_root, **kwargs)

    assert first["status"] == second["status"] == "READY"
    assert first["action"] == "CREATED"
    assert second["action"] == "REUSED"
    assert len(registration_calls) == 1
    assert paths.identity_path.read_bytes() == identity_before
    assert paths.ledger_path.is_file()
    assert first["state_scope"] == "current_user"
    assert first["system_scheduled_task_required"] is False


def test_integrity_required_first_run_and_rerun_leave_code_root_exactly_unchanged(tmp_path):
    app_root = tmp_path / "hardened-app"
    (app_root / "config").mkdir(parents=True)
    (app_root / "Container_Audit.exe").write_bytes(b"main")
    (app_root / "config" / "container_audit_settings.json").write_text(
        '{"scale_factor": 1.0}\n',
        encoding="utf-8",
    )
    entries = []
    for path in sorted(
        (candidate for candidate in app_root.rglob("*") if candidate.is_file()),
        key=lambda candidate: candidate.relative_to(app_root).as_posix(),
    ):
        payload = path.read_bytes()
        entries.append(
            {
                "path": path.relative_to(app_root).as_posix(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    aggregate = hashlib.sha256(
        "".join(
            f"{item['sha256']} {item['size']} {item['path']}\n"
            for item in entries
        ).encode("utf-8")
    ).hexdigest()
    _write_json(
        app_root / "bootstrap-integrity.json",
        {
            "schema_version": "container-audit-bootstrap-integrity-v1",
            "status": "PASS",
            "code_root": str(app_root.resolve()),
            "file_count": len(entries),
            "aggregate_sha256": aggregate,
            "files": entries,
        },
    )
    before = {
        path.relative_to(app_root).as_posix(): path.read_bytes()
        for path in app_root.rglob("*")
        if path.is_file()
    }
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "user-state")}
    paths = resolve_current_user_onboarding_paths(app_root, environ=environment)
    registration_calls = []

    def register(selected_paths):
        registration_calls.append(selected_paths)
        _ready_state(selected_paths)
        return 0

    kwargs = {
        "environ": environment,
        "require_bootstrap_integrity": True,
        "registration_runner": register,
        "profile_loader": _profile_loader,
        "credential_loader": _credential_loader,
        "ledger_factory": _ledger_factory,
        "autostart_installer": _autostart,
        "relay_launcher": _relay_start,
    }

    first = onboard_current_user(app_root, **kwargs)
    after_first = {
        path.relative_to(app_root).as_posix(): path.read_bytes()
        for path in app_root.rglob("*")
        if path.is_file()
    }
    second = onboard_current_user(app_root, **kwargs)
    after_second = {
        path.relative_to(app_root).as_posix(): path.read_bytes()
        for path in app_root.rglob("*")
        if path.is_file()
    }

    assert first["action"] == "CREATED"
    assert second["action"] == "REUSED"
    assert len(registration_calls) == 1
    assert before == after_first == after_second
    assert verify_bootstrap_integrity(paths, required=True)["status"] == "PASS"


@pytest.mark.parametrize(
    "override_name,relative_value",
    [
        ("CONTAINER_AUDIT_DATA_ROOT", "state"),
        ("CONTAINER_AUDIT_LOGISTICS_PROFILE_PATH", "config/runtime-profile.json"),
    ],
)
def test_onboarding_rejects_code_root_state_overrides_before_writing(
    tmp_path,
    override_name,
    relative_value,
):
    app_root = tmp_path / "hardened-app"
    app_root.mkdir()
    sentinel = app_root / "Container_Audit.exe"
    sentinel.write_bytes(b"immutable")
    environment = {
        "CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "user-state"),
        override_name: str(app_root / relative_value),
        "TEMP": str(tmp_path / "safe-report-root"),
    }

    with pytest.raises(CurrentUserOnboardingError, match="read-only application code root"):
        resolve_current_user_onboarding_paths(app_root, environ=environment)

    assert sentinel.read_bytes() == b"immutable"
    assert list(app_root.rglob("*")) == [sentinel]


def test_explicit_onboarding_root_is_self_contained_without_ambient_home(tmp_path):
    app_root = tmp_path / "app"
    state_root = tmp_path / "state"
    paths = resolve_current_user_onboarding_paths(
        app_root,
        environ={"CONTAINER_AUDIT_DATA_ROOT": str(state_root)},
    )

    assert paths.data_root == state_root.resolve()
    assert paths.direct_sync_root == state_root.resolve() / "direct_sync"
    assert paths.logistics_profile_path == state_root.resolve() / "logistics-profile" / "runtime-profile.json"
    assert paths.bootstrap_tls_ca_bundle_path == state_root.resolve() / "bootstrap" / "ca-bundle.pem"


def test_registration_runner_forwards_bootstrap_tls_ca_bundle(tmp_path, monkeypatch):
    app_root = tmp_path / "app"
    app_root.mkdir()
    local_app_data = tmp_path / "LocalAppData"
    environment = {"LOCALAPPDATA": str(local_app_data)}
    paths = resolve_current_user_onboarding_paths(app_root, environ=environment)
    paths.bootstrap_tls_ca_bundle_path.parent.mkdir(parents=True)
    paths.bootstrap_tls_ca_bundle_path.write_bytes(b"private-ca-fixture")
    captured = {}

    def fake_registration(arguments):
        captured["arguments"] = list(arguments)
        return 0

    monkeypatch.setattr(
        "tools.register_container_audit_worker_pc.main",
        fake_registration,
    )

    result = onboarding_module._registration_runner(
        paths,
        server_base_url="https://worker.example.invalid",
        environ=environment,
    )

    assert result == 0
    arguments = captured["arguments"]
    ca_index = arguments.index("--tls-ca-bundle-path")
    assert arguments[ca_index + 1] == str(paths.bootstrap_tls_ca_bundle_path)


def test_ready_profile_adds_configured_ca_without_registration(tmp_path, monkeypatch):
    app_root = tmp_path / "app"
    app_root.mkdir()
    ca_source = tmp_path / "private-ca.cert.pem"
    ca_source.write_bytes(b"private-ca-fixture")
    environment = {
        "CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state"),
        ENROLLMENT_TLS_CA_BUNDLE_PATH_ENV: str(ca_source),
    }
    paths = resolve_current_user_onboarding_paths(app_root, environ=environment)
    _ready_state(paths)
    upgrades = []

    def fake_upgrade(**kwargs):
        upgrades.append(kwargs)
        payload = json.loads(paths.logistics_profile_path.read_text(encoding="utf-8"))
        payload["tls_ca_bundle_path"] = str(
            paths.logistics_profile_path.parent / "tls" / "ca-bundle.pem"
        )
        _write_json(paths.logistics_profile_path, payload)
        return {"status": "upgraded"}

    monkeypatch.setattr(
        "tools.install_logistics_runtime_profile.install_tls_ca_bundle_for_existing_profile",
        fake_upgrade,
    )

    report = onboard_current_user(
        app_root,
        environ=environment,
        require_bootstrap_integrity=False,
        registration_runner=lambda _paths: (_ for _ in ()).throw(
            AssertionError("ready profile must not be registered again")
        ),
        profile_loader=_profile_loader,
        credential_loader=_credential_loader,
        ledger_factory=_ledger_factory,
        autostart_installer=_autostart,
        relay_launcher=_relay_start,
    )

    assert report["status"] == "READY"
    assert report["action"] == "REUSED"
    assert report["state_readback"]["tls_private_ca_configured"] is True
    assert len(upgrades) == 1
    assert upgrades[0]["tls_ca_bundle_path"] == str(ca_source)


def test_missing_registration_result_is_unknown_not_success(tmp_path):
    app_root = tmp_path / "app"
    app_root.mkdir()
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")}

    with pytest.raises(CurrentUserOnboardingError) as caught:
        onboard_current_user(
            app_root,
            environ=environment,
            require_bootstrap_integrity=False,
            registration_runner=lambda _paths: None,
            profile_loader=_profile_loader,
            credential_loader=_credential_loader,
            ledger_factory=_ledger_factory,
            autostart_installer=_autostart,
            relay_launcher=_relay_start,
        )

    assert caught.value.status == "UNKNOWN"
    report = json.loads(caught.value.report_path.read_text(encoding="utf-8"))
    assert report["status"] == "UNKNOWN"
    assert report["action"] == "UNKNOWN"


def test_missing_bootstrap_integrity_is_diagnostic_warning_not_startup_failure(tmp_path):
    app_root = tmp_path / "downloaded-app"
    app_root.mkdir()
    (app_root / "Container_Audit.exe").write_bytes(b"main")
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")}
    paths = resolve_current_user_onboarding_paths(app_root, environ=environment)

    def register(selected_paths):
        _ready_state(selected_paths)
        return 0

    report = onboard_current_user(
        app_root,
        environ=environment,
        require_bootstrap_integrity=True,
        registration_runner=register,
        profile_loader=_profile_loader,
        credential_loader=_credential_loader,
        ledger_factory=_ledger_factory,
        autostart_installer=_autostart,
        relay_launcher=_relay_start,
    )

    assert report["status"] == "READY"
    assert report["action"] == "CREATED"
    assert report["bootstrap_integrity"] == "absent"
    assert report["bootstrap_integrity_detail"]["status"] == "ABSENT"
    persisted = json.loads(paths.onboarding_report_path.read_text(encoding="utf-8"))
    assert persisted["bootstrap_integrity"] == "absent"


def test_bootstrap_integrity_verifies_exact_inventory(tmp_path):
    app_root = tmp_path / "hardened-app"
    app_root.mkdir()
    executable = app_root / "Container_Audit.exe"
    runtime = app_root / "runtime.dll"
    executable.write_bytes(b"main")
    runtime.write_bytes(b"runtime")
    entries = []
    for path in (executable, runtime):
        payload = path.read_bytes()
        entries.append(
            {
                "path": path.name,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    aggregate = hashlib.sha256(
        "".join(
            f"{item['sha256']} {item['size']} {item['path']}\n"
            for item in entries
        ).encode("utf-8")
    ).hexdigest()
    _write_json(
        app_root / "bootstrap-integrity.json",
        {
            "schema_version": "container-audit-bootstrap-integrity-v1",
            "status": "PASS",
            "code_root": ".",
            "file_count": len(entries),
            "aggregate_sha256": aggregate,
            "files": entries,
        },
    )
    paths = resolve_current_user_onboarding_paths(
        app_root,
        environ={"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")},
    )

    assert verify_bootstrap_integrity(paths, required=True)["status"] == "PASS"
    runtime.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="integrity failed"):
        verify_bootstrap_integrity(paths, required=True)


def test_public_remove_clears_user_persistence_but_preserves_data(tmp_path):
    app_root = tmp_path / "app"
    app_root.mkdir()
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")}
    paths = resolve_current_user_onboarding_paths(app_root, environ=environment)
    _ready_state(paths)
    paths.ledger_path.parent.mkdir(parents=True)
    paths.ledger_path.write_bytes(b"preserve")
    observed = []

    report = remove_current_user_setup(
        app_root,
        environ=environment,
        autostart_remover=lambda: observed.append("hkcu") or {"status": "ABSENT"},
        relay_stopper=lambda root: observed.append(Path(root)) or {"status": "ABSENT"},
    )

    assert report["status"] == "PASS_DATA_PRESERVED"
    assert report["data_preserved"] is True
    assert observed == ["hkcu", paths.direct_sync_root]
    assert paths.identity_path.is_file()
    assert paths.logistics_profile_path.is_file()
    assert paths.ledger_path.read_bytes() == b"preserve"


def test_public_remove_does_not_downgrade_lost_relay_result(tmp_path):
    app_root = tmp_path / "app"
    app_root.mkdir()
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")}

    with pytest.raises(CurrentUserOnboardingError) as caught:
        remove_current_user_setup(
            app_root,
            environ=environment,
            autostart_remover=lambda: {"status": "ABSENT"},
            relay_stopper=lambda _root: {"status": "UNKNOWN"},
        )

    assert caught.value.status == "UNKNOWN"
    report = json.loads(caught.value.report_path.read_text(encoding="utf-8"))
    assert report["status"] == "UNKNOWN"
