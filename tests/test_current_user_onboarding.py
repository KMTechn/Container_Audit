from datetime import datetime, timezone
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
    restore_current_user_lifecycle_after_replacement,
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
        classmethod(lambda _cls, *args, **kwargs: _FakeExistingPossessionKey()),
    )


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def test_pinned_json_binds_the_exact_bytes_that_are_parsed(tmp_path):
    path = tmp_path / "pinned.json"
    content = b'{"status":"PASS","count":1}\n'
    path.write_bytes(content)

    value = onboarding_module._read_pinned_json(
        path,
        "test receipt",
        expected_sha256=hashlib.sha256(content).hexdigest(),
        maximum_bytes=1024,
    )

    assert value == {"status": "PASS", "count": 1}
    with pytest.raises(ValueError, match="SHA-256 differs"):
        onboarding_module._read_pinned_json(
            path,
            "test receipt",
            expected_sha256="0" * 64,
            maximum_bytes=1024,
        )


def test_pinned_json_rejects_duplicate_keys_and_oversized_input(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate_content = b'{"status":"PASS","status":"FAIL"}'
    duplicate.write_bytes(duplicate_content)
    with pytest.raises(ValueError, match="not valid UTF-8 JSON"):
        onboarding_module._read_pinned_json(
            duplicate,
            "test receipt",
            expected_sha256=hashlib.sha256(duplicate_content).hexdigest(),
            maximum_bytes=1024,
        )

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * 17)
    with pytest.raises(ValueError, match="size is invalid"):
        onboarding_module._read_pinned_json(
            oversized,
            "test receipt",
            expected_sha256=hashlib.sha256(b"x" * 17).hexdigest(),
            maximum_bytes=16,
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


def _replacement_autostart(app_root):
    return {
        "status": "PASS",
        "principal": "current_user",
        "registry_hive": "HKEY_CURRENT_USER",
        "registry_key": onboarding_module.USER_RELAY_RUN_KEY,
        "registry_value": onboarding_module.USER_RELAY_RUN_VALUE,
        "command": onboarding_module._replacement_user_relay_command_line(
            Path(app_root)
        ),
    }


def _relay_start(_app_root):
    return {"status": "START_REQUESTED", "process_id": 123}


def _limited_execution_context():
    return {
        "status": "PASS",
        "token_elevated": False,
        "integrity_level": "MEDIUM",
    }


def test_replacement_relay_launcher_uses_canonical_restored_runtime(
    tmp_path,
    monkeypatch,
):
    code_root = tmp_path / "current"
    app_root = code_root / "app"
    (code_root / "runtime").mkdir(parents=True)
    app_root.mkdir()
    (code_root / "runtime" / "pythonw.exe").write_bytes(b"portable-pythonw")
    (app_root / "main.py").write_text("# restored app\n", encoding="utf-8")
    observed = {}

    class Process:
        pid = 321

    def fake_popen(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return Process()

    monkeypatch.setattr(onboarding_module.subprocess, "Popen", fake_popen)

    result = onboarding_module._start_replacement_user_relay_process(app_root)

    expected = [
        str((code_root / "runtime" / "pythonw.exe").resolve()),
        "-I",
        "-B",
        str((app_root / "main.py").resolve()),
        onboarding_module.USER_RELAY_MODE,
    ]
    assert result == {"status": "START_REQUESTED", "process_id": 321}
    assert observed["command"] == expected
    assert onboarding_module._replacement_user_relay_command_line(app_root) == (
        onboarding_module.subprocess.list2cmdline(expected)
    )
    assert observed["kwargs"]["cwd"] == str(app_root.resolve())
    assert observed["kwargs"]["close_fds"] is True


def _replacement_identity(seed: str, *, source_digit: str) -> dict:
    return {
        "file_count": 7,
        "aggregate_sha256": seed * 64,
        "integrity_sha256": chr(ord(seed) + 1) * 64,
        "manifest_sha256": chr(ord(seed) + 2) * 64,
        "source_commit": source_digit * 40,
        "source_tree": chr(ord(source_digit) + 1) * 40,
        "owner_sid": "S-1-5-32-544",
        "access_rules_protected": True,
        "acl_sddl_sha256": chr(ord(seed) + 3) * 64,
        "reparse_count": 0,
    }


def _replacement_lifecycle_fixture(tmp_path):
    install_parent = tmp_path / "apps" / "Container_Audit"
    code_root = install_parent / "current"
    app_root = code_root / "app"
    failed_root = install_parent / (".current.failed." + "a" * 32)
    (code_root / "runtime").mkdir(parents=True)
    (code_root / "tools").mkdir()
    app_root.mkdir()
    failed_root.mkdir()
    (code_root / "runtime" / "pythonw.exe").write_bytes(b"portable-pythonw")
    (app_root / "main.py").write_text("# restored app\n", encoding="utf-8")
    writer_contract = code_root / "tools" / "container_writer_session_contract.json"
    writer_contract.write_text(
        '{"schema_version":"writer-contract-test"}\n', encoding="utf-8"
    )
    writer_sha256 = hashlib.sha256(writer_contract.read_bytes()).hexdigest()
    old_identity = _replacement_identity("1", source_digit="a")
    new_identity = _replacement_identity("5", source_digit="c")
    manifest_path = code_root / "portable-manifest.json"
    _write_json(
        manifest_path,
        {
            "schema": "container-audit-portable-tree-v1",
            "entrypoint": "runtime/pythonw.exe app/main.py",
            "source_commit": old_identity["source_commit"],
            "source_tree": old_identity["source_tree"],
            "writer_session_contract_sha256": writer_sha256,
        },
    )
    transaction_id = "a" * 32
    session_id = "d" * 32
    attempt_id = "e" * 32
    session_started_at_utc = datetime.now(timezone.utc).isoformat()
    orchestrator_sha256 = "f" * 64
    receipt_path = tmp_path / "audit" / "replacement.json"
    receipt = {
        "schema_version": "container-audit-verified-replacement-v1",
        "status": "OLD_PRESERVED_NEW_VERIFIED",
        "app_id": "container_audit",
        "transaction_id": transaction_id,
        "created_at": "2026-08-30T00:00:00+00:00",
        "helper_sha256": "8" * 64,
        "integrity_helper_sha256": "9" * 64,
        "receipt_path": str(receipt_path.resolve()),
        "install_root": str(code_root.resolve()),
        "install_parent": str(install_parent.resolve()),
        "rollback_root": str(
            (install_parent / f".current.rollback.{transaction_id}").resolve()
        ),
        "failed_root": str(failed_root.resolve()),
        "parent_acl": {
            "owner_sid": "S-1-5-32-544",
            "access_rules_protected": True,
            "sddl_sha256": "b" * 64,
        },
        "old": old_identity,
        "new": new_identity,
        "identity_or_credential_copied": False,
    }
    _write_json(receipt_path, receipt)
    receipt_sha256 = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    environment = {"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "owner-state")}
    paths = resolve_current_user_onboarding_paths(app_root, environ=environment)
    _ready_state(paths)
    paths.ledger_path.parent.mkdir(parents=True)
    paths.ledger_path.write_bytes(b"SQLite format 3\x00owner-ledger-sentinel")
    stop_path = onboarding_module.user_relay_stop_path(paths.direct_sync_root)
    stop_path.parent.mkdir(parents=True)
    stop_path.write_text("quiescent\n", encoding="utf-8")

    def identity_reader(tree_root, declared_root):
        assert Path(declared_root).resolve() == code_root.resolve()
        selected = Path(tree_root).resolve()
        if selected == code_root.resolve():
            return dict(old_identity)
        if selected == failed_root.resolve():
            return dict(new_identity)
        raise AssertionError(f"unexpected replacement tree: {selected}")

    return SimpleNamespace(
        app_root=app_root,
        code_root=code_root,
        failed_root=failed_root,
        environment=environment,
        paths=paths,
        stop_path=stop_path,
        transaction_id=transaction_id,
        session_id=session_id,
        attempt_id=attempt_id,
        session_started_at_utc=session_started_at_utc,
        orchestrator_sha256=orchestrator_sha256,
        receipt_path=receipt_path,
        receipt_sha256=receipt_sha256,
        writer_sha256=writer_sha256,
        old_identity=old_identity,
        new_identity=new_identity,
        identity_reader=identity_reader,
    )


def _owner_bytes(paths) -> dict[str, bytes]:
    return {
        name: path.read_bytes()
        for name, path in onboarding_module._owner_artifact_paths(paths).items()
    }


def test_replacement_lifecycle_restores_only_bound_actions_and_preserves_owner_state(
    tmp_path,
    monkeypatch,
):
    fixture = _replacement_lifecycle_fixture(tmp_path)
    owner_before = _owner_bytes(fixture.paths)
    calls = []

    def forbidden(*_args, **_kwargs):
        raise AssertionError("registration/network/ledger creation is forbidden")

    monkeypatch.setattr(onboarding_module, "_registration_runner", forbidden)
    monkeypatch.setattr(onboarding_module, "_create_ledger", forbidden)

    report = restore_current_user_lifecycle_after_replacement(
        fixture.app_root,
        code_root=fixture.code_root,
        producer_code_root=fixture.failed_root,
        session_id=fixture.session_id,
        attempt_id=fixture.attempt_id,
        session_started_at_utc=fixture.session_started_at_utc,
        orchestrator_sha256=fixture.orchestrator_sha256,
        replacement_transaction_id=fixture.transaction_id,
        replacement_receipt_path=fixture.receipt_path,
        replacement_receipt_sha256=fixture.receipt_sha256,
        writer_contract_sha256=fixture.writer_sha256,
        environ=fixture.environment,
        execution_context_inspector=_limited_execution_context,
        profile_loader=_profile_loader,
        credential_loader=_credential_loader,
        code_identity_reader=fixture.identity_reader,
        autostart_installer=lambda root: calls.append(("autostart", Path(root)))
        or _replacement_autostart(root),
        autostart_remover=lambda: (_ for _ in ()).throw(
            AssertionError("success must not run containment")
        ),
        relay_launcher=lambda root: calls.append(("relay", Path(root)))
        or {"status": "START_REQUESTED", "process_id": 123},
        relay_stopper=lambda _root: (_ for _ in ()).throw(
            AssertionError("success must not run containment")
        ),
    )

    persisted = json.loads(
        (fixture.paths.status_dir / "replacement_lifecycle_restore.json").read_text(
            encoding="utf-8"
        )
    )
    assert report == persisted
    assert report["schema"] == "container-audit-replacement-lifecycle-restore-v1"
    assert report["status"] == "READY"
    assert report["action"] == "REUSED"
    assert report["app_id"] == "container_audit"
    assert report["replacement_transaction_id"] == fixture.transaction_id
    assert report["replacement_receipt_path"] == str(fixture.receipt_path)
    assert report["replacement_receipt_sha256"] == fixture.receipt_sha256
    assert report["writer_contract_sha256"] == fixture.writer_sha256
    assert report["session_id"] == fixture.session_id
    assert report["attempt_id"] == fixture.attempt_id
    assert report["session_started_at_utc"] == fixture.session_started_at_utc
    assert report["orchestrator_sha256"] == fixture.orchestrator_sha256
    assert report["execution_context"] == _limited_execution_context()
    assert report["producer_code_root"] == str(fixture.failed_root.resolve())
    assert report["restored_code_identity"] == fixture.old_identity
    assert report["failed_new_code_identity"] == fixture.new_identity
    assert report["owner_state_readback"]["status"] == "READY"
    assert report["owner_state_preserved_exact"] is True
    assert report["owner_artifact_paths"] == {
        name: str(path.resolve())
        for name, path in onboarding_module._owner_artifact_paths(
            fixture.paths
        ).items()
    }
    assert report["registration_attempted"] is False
    assert report["network_attempted"] is False
    assert report["ledger_opened"] is False
    assert report["identity_or_credential_copied"] is False
    assert report["secret_values_recorded"] is False
    assert report["failure"] == ""
    assert (
        report["owner_artifact_fingerprints_before"]
        == report["owner_artifact_fingerprints_after"]
    )
    assert _owner_bytes(fixture.paths) == owner_before
    assert calls == [
        ("autostart", fixture.app_root.resolve()),
        ("relay", fixture.app_root.resolve()),
    ]
    assert not fixture.stop_path.exists()


@pytest.mark.parametrize("collision", ["identity", "replacement_receipt"])
def test_replacement_lifecycle_rejects_protected_report_path_before_mutation(
    tmp_path,
    collision,
):
    fixture = _replacement_lifecycle_fixture(tmp_path)
    owner_before = _owner_bytes(fixture.paths)
    report_path = (
        fixture.paths.identity_path
        if collision == "identity"
        else fixture.receipt_path
    )
    actions = []

    with pytest.raises(CurrentUserOnboardingError):
        restore_current_user_lifecycle_after_replacement(
            fixture.app_root,
            code_root=fixture.code_root,
            report_path=report_path,
            producer_code_root=fixture.failed_root,
            session_id=fixture.session_id,
            attempt_id=fixture.attempt_id,
            session_started_at_utc=fixture.session_started_at_utc,
            orchestrator_sha256=fixture.orchestrator_sha256,
            replacement_transaction_id=fixture.transaction_id,
            replacement_receipt_path=fixture.receipt_path,
            replacement_receipt_sha256=fixture.receipt_sha256,
            writer_contract_sha256=fixture.writer_sha256,
            environ=fixture.environment,
            execution_context_inspector=_limited_execution_context,
            autostart_installer=lambda _root: actions.append("autostart") or {},
            relay_launcher=lambda _root: actions.append("relay") or {},
        )

    assert actions == []
    assert _owner_bytes(fixture.paths) == owner_before
    assert fixture.stop_path.is_file()


def test_replacement_lifecycle_rejects_existing_report_before_mutation(tmp_path):
    fixture = _replacement_lifecycle_fixture(tmp_path)
    report_path = tmp_path / "audit" / "preexisting-report.json"
    report_path.write_text("preexisting\n", encoding="utf-8")
    actions = []

    with pytest.raises(CurrentUserOnboardingError):
        restore_current_user_lifecycle_after_replacement(
            fixture.app_root,
            code_root=fixture.code_root,
            report_path=report_path,
            producer_code_root=fixture.failed_root,
            session_id=fixture.session_id,
            attempt_id=fixture.attempt_id,
            session_started_at_utc=fixture.session_started_at_utc,
            orchestrator_sha256=fixture.orchestrator_sha256,
            replacement_transaction_id=fixture.transaction_id,
            replacement_receipt_path=fixture.receipt_path,
            replacement_receipt_sha256=fixture.receipt_sha256,
            writer_contract_sha256=fixture.writer_sha256,
            environ=fixture.environment,
            execution_context_inspector=_limited_execution_context,
            autostart_installer=lambda _root: actions.append("autostart") or {},
            relay_launcher=lambda _root: actions.append("relay") or {},
        )

    assert actions == []
    assert report_path.read_text(encoding="utf-8") == "preexisting\n"
    assert fixture.stop_path.is_file()


def test_replacement_lifecycle_rejects_elevated_execution_context_before_mutation(
    tmp_path,
):
    fixture = _replacement_lifecycle_fixture(tmp_path)
    owner_before = _owner_bytes(fixture.paths)
    actions = []

    with pytest.raises(CurrentUserOnboardingError) as caught:
        restore_current_user_lifecycle_after_replacement(
            fixture.app_root,
            code_root=fixture.code_root,
            producer_code_root=fixture.failed_root,
            session_id=fixture.session_id,
            attempt_id=fixture.attempt_id,
            session_started_at_utc=fixture.session_started_at_utc,
            orchestrator_sha256=fixture.orchestrator_sha256,
            replacement_transaction_id=fixture.transaction_id,
            replacement_receipt_path=fixture.receipt_path,
            replacement_receipt_sha256=fixture.receipt_sha256,
            writer_contract_sha256=fixture.writer_sha256,
            environ=fixture.environment,
            execution_context_inspector=lambda: {
                "status": "PASS",
                "token_elevated": True,
                "integrity_level": "HIGH",
            },
            autostart_installer=lambda _root: actions.append("autostart") or {},
            relay_launcher=lambda _root: actions.append("relay") or {},
        )

    report = json.loads(caught.value.report_path.read_text(encoding="utf-8"))
    assert report["failure_code"] == "EXECUTION_CONTEXT_FAILED"
    assert report["containment_status"] == "NOT_REQUIRED"
    assert report["owner_state_preserved_exact"] is True
    assert _owner_bytes(fixture.paths) == owner_before
    assert actions == []
    assert fixture.stop_path.is_file()


def test_replacement_lifecycle_late_report_collision_is_not_overwritten_and_contains(
    tmp_path,
):
    fixture = _replacement_lifecycle_fixture(tmp_path)
    report_path = tmp_path / "audit" / "late-collision.json"
    owner_before = _owner_bytes(fixture.paths)
    calls = []

    def collide_then_start(root):
        calls.append(("relay", Path(root)))
        report_path.write_text("collision-sentinel\n", encoding="utf-8")
        return {"status": "START_REQUESTED", "process_id": 123}

    def stop_relay(root):
        calls.append(("stop", Path(root)))
        fixture.stop_path.parent.mkdir(parents=True, exist_ok=True)
        fixture.stop_path.write_text("contained\n", encoding="utf-8")
        return {"status": "ABSENT"}

    with pytest.raises(CurrentUserOnboardingError) as caught:
        restore_current_user_lifecycle_after_replacement(
            fixture.app_root,
            code_root=fixture.code_root,
            report_path=report_path,
            producer_code_root=fixture.failed_root,
            session_id=fixture.session_id,
            attempt_id=fixture.attempt_id,
            session_started_at_utc=fixture.session_started_at_utc,
            orchestrator_sha256=fixture.orchestrator_sha256,
            replacement_transaction_id=fixture.transaction_id,
            replacement_receipt_path=fixture.receipt_path,
            replacement_receipt_sha256=fixture.receipt_sha256,
            writer_contract_sha256=fixture.writer_sha256,
            environ=fixture.environment,
            execution_context_inspector=_limited_execution_context,
            profile_loader=_profile_loader,
            credential_loader=_credential_loader,
            code_identity_reader=fixture.identity_reader,
            autostart_installer=_replacement_autostart,
            autostart_remover=lambda: calls.append(("remove", None))
            or {"status": "ABSENT"},
            relay_launcher=collide_then_start,
            relay_stopper=stop_relay,
        )

    assert caught.value.status == "FAILED"
    assert report_path.read_text(encoding="utf-8") == "collision-sentinel\n"
    assert fixture.stop_path.is_file()
    assert _owner_bytes(fixture.paths) == owner_before
    assert calls == [
        ("relay", fixture.app_root.resolve()),
        ("remove", None),
        ("stop", fixture.paths.direct_sync_root),
    ]


@pytest.mark.parametrize(
    "state_status", ["ABSENT", "ABSENT_RETRYABLE", "RECOVERY_REQUIRED", "UNKNOWN"]
)
def test_replacement_lifecycle_requires_exact_ready_before_mutation(
    tmp_path,
    state_status,
):
    fixture = _replacement_lifecycle_fixture(tmp_path)
    actions = []

    with pytest.raises(CurrentUserOnboardingError) as caught:
        restore_current_user_lifecycle_after_replacement(
            fixture.app_root,
            code_root=fixture.code_root,
            producer_code_root=fixture.failed_root,
            session_id=fixture.session_id,
            attempt_id=fixture.attempt_id,
            session_started_at_utc=fixture.session_started_at_utc,
            orchestrator_sha256=fixture.orchestrator_sha256,
            replacement_transaction_id=fixture.transaction_id,
            replacement_receipt_path=fixture.receipt_path,
            replacement_receipt_sha256=fixture.receipt_sha256,
            writer_contract_sha256=fixture.writer_sha256,
            environ=fixture.environment,
            execution_context_inspector=_limited_execution_context,
            state_inspector=lambda *_args, **_kwargs: {"status": state_status},
            code_identity_reader=fixture.identity_reader,
            autostart_installer=lambda _root: actions.append("autostart")
            or {"status": "PASS"},
            relay_launcher=lambda _root: actions.append("relay")
            or {"status": "START_REQUESTED"},
        )

    report = json.loads(caught.value.report_path.read_text(encoding="utf-8"))
    assert caught.value.status == "FAILED"
    assert report["status"] == "FAILED"
    assert report["failure_code"] == "OWNER_STATE_READBACK_FAILED"
    assert report["containment_status"] == "NOT_REQUIRED"
    assert report["owner_state_preserved_exact"] is True
    assert report["registration_attempted"] is False
    assert report["network_attempted"] is False
    assert report["ledger_opened"] is False
    assert actions == []
    assert fixture.stop_path.is_file()


@pytest.mark.parametrize(
    "binding", ["receipt_sha256", "transaction_id", "session_id", "restored_identity"]
)
def test_replacement_lifecycle_rejects_inexact_transaction_or_code_before_mutation(
    tmp_path,
    binding,
):
    fixture = _replacement_lifecycle_fixture(tmp_path)
    actions = []
    receipt_sha256 = fixture.receipt_sha256
    transaction_id = fixture.transaction_id
    session_id = fixture.session_id
    identity_reader = fixture.identity_reader
    if binding == "receipt_sha256":
        receipt_sha256 = "f" * 64
    elif binding == "transaction_id":
        transaction_id = "b" * 32
    elif binding == "session_id":
        session_id = "g" * 32
    else:

        def mismatched_identity_reader(*_args):
            return dict(fixture.new_identity)

        identity_reader = mismatched_identity_reader

    with pytest.raises(CurrentUserOnboardingError) as caught:
        restore_current_user_lifecycle_after_replacement(
            fixture.app_root,
            code_root=fixture.code_root,
            producer_code_root=fixture.failed_root,
            session_id=session_id,
            attempt_id=fixture.attempt_id,
            session_started_at_utc=fixture.session_started_at_utc,
            orchestrator_sha256=fixture.orchestrator_sha256,
            replacement_transaction_id=transaction_id,
            replacement_receipt_path=fixture.receipt_path,
            replacement_receipt_sha256=receipt_sha256,
            writer_contract_sha256=fixture.writer_sha256,
            environ=fixture.environment,
            execution_context_inspector=_limited_execution_context,
            profile_loader=_profile_loader,
            credential_loader=_credential_loader,
            code_identity_reader=identity_reader,
            autostart_installer=lambda _root: actions.append("autostart")
            or {"status": "PASS"},
            relay_launcher=lambda _root: actions.append("relay")
            or {"status": "START_REQUESTED"},
        )

    report = json.loads(caught.value.report_path.read_text(encoding="utf-8"))
    assert report["status"] == "FAILED"
    assert report["containment_status"] == "NOT_REQUIRED"
    assert report["owner_state_preserved_exact"] is True
    assert actions == []
    assert fixture.stop_path.is_file()


def test_replacement_lifecycle_action_failure_is_contained_and_reported(tmp_path):
    fixture = _replacement_lifecycle_fixture(tmp_path)
    owner_before = _owner_bytes(fixture.paths)
    calls = []

    def stop_relay(root):
        calls.append(("stop", Path(root)))
        fixture.stop_path.parent.mkdir(parents=True, exist_ok=True)
        fixture.stop_path.write_text("contained\n", encoding="utf-8")
        return {"status": "ABSENT"}

    with pytest.raises(CurrentUserOnboardingError) as caught:
        restore_current_user_lifecycle_after_replacement(
            fixture.app_root,
            code_root=fixture.code_root,
            producer_code_root=fixture.failed_root,
            session_id=fixture.session_id,
            attempt_id=fixture.attempt_id,
            session_started_at_utc=fixture.session_started_at_utc,
            orchestrator_sha256=fixture.orchestrator_sha256,
            replacement_transaction_id=fixture.transaction_id,
            replacement_receipt_path=fixture.receipt_path,
            replacement_receipt_sha256=fixture.receipt_sha256,
            writer_contract_sha256=fixture.writer_sha256,
            environ=fixture.environment,
            execution_context_inspector=_limited_execution_context,
            profile_loader=_profile_loader,
            credential_loader=_credential_loader,
            code_identity_reader=fixture.identity_reader,
            autostart_installer=lambda root: calls.append(("autostart", Path(root)))
            or _replacement_autostart(root),
            autostart_remover=lambda: calls.append(("remove", None))
            or {"status": "ABSENT"},
            relay_launcher=lambda root: (_ for _ in ()).throw(
                RuntimeError(f"relay launch failed for {root}")
            ),
            relay_stopper=stop_relay,
        )

    report = json.loads(caught.value.report_path.read_text(encoding="utf-8"))
    assert report["status"] == "FAILED"
    assert report["failure_code"] == "RELAY_START_FAILED"
    assert report["containment_status"] == "PASS_SAFE_QUIESCENT"
    assert report["owner_state_preserved_exact"] is True
    assert report["registration_attempted"] is False
    assert report["network_attempted"] is False
    assert report["ledger_opened"] is False
    assert report["identity_or_credential_copied"] is False
    assert _owner_bytes(fixture.paths) == owner_before
    assert fixture.stop_path.is_file()
    assert calls == [
        ("autostart", fixture.app_root.resolve()),
        ("remove", None),
        ("stop", fixture.paths.direct_sync_root),
    ]


def test_replacement_tree_identity_reads_exact_portable_inventory(tmp_path):
    code_root = tmp_path / "current"
    (code_root / "runtime").mkdir(parents=True)
    (code_root / "app").mkdir()
    (code_root / "tools").mkdir()
    (code_root / "runtime" / "pythonw.exe").write_bytes(b"runtime")
    (code_root / "app" / "main.py").write_bytes(b"main")
    contract = code_root / "tools" / "container_writer_session_contract.json"
    contract.write_bytes(b"{}\n")
    _write_json(
        code_root / "portable-manifest.json",
        {
            "schema": "container-audit-portable-tree-v1",
            "entrypoint": "runtime/pythonw.exe app/main.py",
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "writer_session_contract_sha256": hashlib.sha256(
                contract.read_bytes()
            ).hexdigest(),
        },
    )
    entries = []
    for path in sorted(
        (candidate for candidate in code_root.rglob("*") if candidate.is_file()),
        key=lambda candidate: candidate.relative_to(code_root).as_posix(),
    ):
        payload = path.read_bytes()
        entries.append(
            {
                "path": path.relative_to(code_root).as_posix(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    aggregate = hashlib.sha256(
        "".join(
            f"{item['sha256']} {item['size']} {item['path']}\n" for item in entries
        ).encode("utf-8")
    ).hexdigest()
    _write_json(
        code_root / "bootstrap-integrity.json",
        {
            "schema_version": "container-audit-bootstrap-integrity-v1",
            "status": "PASS",
            "code_root": str(code_root.resolve()),
            "file_count": len(entries),
            "aggregate_sha256": aggregate,
            "files": entries,
        },
    )
    acl = {
        "owner_sid": "S-1-5-32-544",
        "access_rules_protected": True,
        "acl_sddl_sha256": "c" * 64,
    }

    identity = onboarding_module._read_replacement_tree_identity(
        code_root,
        code_root,
        acl_identity_reader=lambda _path: acl,
    )

    assert identity["file_count"] == len(entries)
    assert identity["aggregate_sha256"] == aggregate
    assert identity["source_commit"] == "a" * 40
    assert identity["source_tree"] == "b" * 40
    assert identity["owner_sid"] == acl["owner_sid"]
    assert identity["reparse_count"] == 0
    (code_root / "app" / "main.py").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="integrity failed"):
        onboarding_module._read_replacement_tree_identity(
            code_root,
            code_root,
            acl_identity_reader=lambda _path: acl,
        )


def test_replacement_lifecycle_cli_forwards_all_public_bindings(tmp_path, monkeypatch):
    observed = {}
    report_path = tmp_path / "status" / "replacement_lifecycle_restore.json"

    def fake_restore(app_root, **kwargs):
        observed["app_root"] = app_root
        observed.update(kwargs)
        return {"status": "READY", "action": "REUSED"}

    monkeypatch.setattr(
        onboarding_module,
        "restore_current_user_lifecycle_after_replacement",
        fake_restore,
    )
    monkeypatch.setattr(
        onboarding_module,
        "resolve_current_user_onboarding_paths",
        lambda _root: SimpleNamespace(status_dir=report_path.parent),
    )
    app_root = tmp_path / "current" / "app"
    code_root = tmp_path / "current"
    receipt_path = tmp_path / "receipt.json"

    result = onboarding_module.replacement_lifecycle_restore_main(
        [
            "--app-root",
            str(app_root),
            "--code-root",
            str(code_root),
            "--replacement-transaction-id",
            "a" * 32,
            "--replacement-receipt-path",
            str(receipt_path),
            "--replacement-receipt-sha256",
            "b" * 64,
            "--writer-contract-sha256",
            "c" * 64,
            "--report-path",
            str(report_path),
            "--session-id",
            "d" * 32,
            "--attempt-id",
            "e" * 32,
            "--session-started-at-utc",
            "2026-08-30T00:00:00+00:00",
            "--orchestrator-sha256",
            "f" * 64,
        ]
    )

    assert result == 0
    assert observed == {
        "app_root": str(app_root),
        "code_root": str(code_root),
        "replacement_transaction_id": "a" * 32,
        "replacement_receipt_path": str(receipt_path),
        "replacement_receipt_sha256": "b" * 64,
        "writer_contract_sha256": "c" * 64,
        "report_path": str(report_path),
        "session_id": "d" * 32,
        "attempt_id": "e" * 32,
        "session_started_at_utc": "2026-08-30T00:00:00+00:00",
        "orchestrator_sha256": "f" * 64,
    }


def test_state_absent_partial_and_existing_are_distinguished(tmp_path):
    paths = resolve_current_user_onboarding_paths(
        tmp_path / "app",
        environ={"CONTAINER_AUDIT_DATA_ROOT": str(tmp_path / "state")},
    )
    assert (
        inspect_current_user_state(
            paths,
            profile_loader=_profile_loader,
            credential_loader=_credential_loader,
        )["status"]
        == "ABSENT"
    )
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
    assert ready["possession_key"]["fingerprint"] == (TEST_POSSESSION_FINGERPRINT)


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


def test_integrity_required_first_run_and_rerun_leave_code_root_exactly_unchanged(
    tmp_path,
):
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
            f"{item['sha256']} {item['size']} {item['path']}\n" for item in entries
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

    with pytest.raises(
        CurrentUserOnboardingError, match="read-only application code root"
    ):
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
    assert (
        paths.logistics_profile_path
        == state_root.resolve() / "logistics-profile" / "runtime-profile.json"
    )
    assert (
        paths.bootstrap_tls_ca_bundle_path
        == state_root.resolve() / "bootstrap" / "ca-bundle.pem"
    )


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


def test_missing_bootstrap_integrity_is_diagnostic_warning_not_startup_failure(
    tmp_path,
):
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
            f"{item['sha256']} {item['size']} {item['path']}\n" for item in entries
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
