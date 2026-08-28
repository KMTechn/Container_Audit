import hashlib
import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from storage_policy import DATA_ROOT_ENV
from tools import register_container_audit_worker_pc as registration


REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_STREAM_CATALOG = (
    REPO_ROOT / "kmtech_factory_contracts" / "bundle" / "v1" / "catalogs" / "canonical-stream-catalog.json"
)
GUI_ORDER_RAW_EVENT_NAMES = [
    "CONTAINER_AUDIT_OBSERVED",
    "TRANSFER_WAITING_OBSERVED",
    "WORK_START",
    "MASTER_LABEL_SCANNED",
    "MASTER_LABEL_SCANNED_NEW",
    "MASTER_LABEL_SCANNED_OLD",
    "SCAN_OK",
    "SCAN_FAIL_DUPLICATE",
    "TRAY_COMPLETE",
    "POST_REVIEW_REQUIRED",
    "TRAY_DISCARDED_BY_OPERATOR",
    "TRAY_RESET",
    "TRAY_RESTORE",
    "MASTER_LABEL_REPLACEMENT_APPLIED",
    "PHS_REPLACEMENT_WAITING_MARKED",
    "PHS_RECONCILIATION_ACTION_RESOLVED",
    "PHS_RECONCILIATION_LABEL_EXCHANGED",
    "WORK_END",
]
TEST_MACHINE_GUID = "00112233-4455-6677-8899-aabbccddeeff"
TEST_USER_SID = "S-1-5-21-100-200-300-1001"
TEST_POSSESSION_FINGERPRINT = "EIEjk1nsv9vwrOp-3GrBvZz2WZPvy48vdViRVd6Llvg"
TEST_POSSESSION_PUBLIC_JWK = {
    "crv": "P-256",
    "kty": "EC",
    "x": "ftdPP0FoUhV62ssO6cL7HqpHkBIBrG_8AtnYvilamcc",
    "y": "IHDnlSA-nqN6SQxMtpQ580nxmwRaJ2dJfEFm7Mk7-IQ",
}


class _FakePossessionKey:
    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        return None

    def descriptor(self):
        return SimpleNamespace(
            contract_version=registration.POSSESSION_KEY_CONTRACT_VERSION,
            scope=registration.SCOPE_CURRENT_USER,
            created=True,
            public_jwk=dict(TEST_POSSESSION_PUBLIC_JWK),
            fingerprint=TEST_POSSESSION_FINGERPRINT,
            export_policy=0,
        )

    def assert_non_exportable(self):
        return SimpleNamespace(private_export_status_hex="0x80090029")

    def sign_es256(self, value):
        assert isinstance(value, bytes)
        return b"\x01" * 64


@pytest.fixture(autouse=True)
def _fake_persistent_possession_key(monkeypatch):
    monkeypatch.setattr(
        registration.PersistentPossessionKey,
        "provision_initial",
        classmethod(lambda _cls, *args, **kwargs: _FakePossessionKey()),
    )
    monkeypatch.setattr(
        registration.PersistentPossessionKey,
        "open_existing",
        classmethod(lambda _cls, *args, **kwargs: _FakePossessionKey()),
    )


def _v2_response_binding():
    return {
        "contract_version": registration.SELF_ENROLLMENT_CONTRACT_VERSION,
        "identity_action": "CREATED",
        "authorization_state": "OPERATION_PENDING",
        "credential_epoch": 1,
        "possession_key": {
            "contract_version": registration.POSSESSION_KEY_CONTRACT_VERSION,
            "fingerprint": TEST_POSSESSION_FINGERPRINT,
        },
    }


def _generated_install_id(*, user_sid=TEST_USER_SID, app_id=registration.INSTALL_IDENTITY_APP_ID):
    return registration.derive_path_independent_install_id(
        machine_guid=TEST_MACHINE_GUID,
        user_sid=user_sid,
        app_id=app_id,
    )


def _catalog_container_audit_raw_event_names():
    catalog = json.loads(CANONICAL_STREAM_CATALOG.read_text(encoding="utf-8"))
    for stream in catalog["streams"]:
        if stream.get("app_id") == "container_audit" and stream.get("stream_id") == "container_audit_events":
            return list(stream["raw_event_names"])
    raise AssertionError("canonical-stream-catalog.json missing container_audit_events")


def test_worker_pc_registration_frozen_default_app_root_uses_executable_directory(tmp_path, monkeypatch):
    frozen_exe = tmp_path / "release" / "Container_Audit_DirectSync_Install.exe"
    frozen_exe.parent.mkdir()
    frozen_exe.write_bytes(b"exe")
    monkeypatch.setattr(registration.sys, "frozen", True, raising=False)
    monkeypatch.setattr(registration.sys, "executable", str(frozen_exe))

    assert registration._default_app_root() == str(frozen_exe.parent.resolve())


def test_worker_pc_registration_writes_manifest_and_secret_ref_only(tmp_path, monkeypatch):
    local_app_data = tmp_path / "LocalAppData"
    program_data = tmp_path / "ProgramData"
    report_path = tmp_path / "registration-report.json"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setenv("PROGRAMDATA", str(program_data))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    exit_code = registration.main(
        [
            "--hostname",
            "PC-01",
            "--key-id",
            "server-issued-key-01",
            "--secret-ref",
            "wincred:KMTech.DirectSync.ContainerAudit.PC-01",
            "--report-path",
            str(report_path),
        ]
    )

    assert exit_code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    manifest_path = Path(report["producer_manifest_path"])
    credential_path = Path(report["credential_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    credential = json.loads(credential_path.read_text(encoding="utf-8"))
    expected_root = (local_app_data / "KMTech" / "ContainerAudit").resolve()
    expected_direct_sync_root = (local_app_data / "KMTech" / "DirectSync" / "container_audit").resolve()

    assert report["status"] == "LOCAL_REGISTRATION_WRITTEN_PENDING_SECRET"
    assert report["raw_secret_written"] is False
    assert report["secret_bootstrap_verified"] is False
    assert manifest["schema_version"] == "producer-onboarding-manifest-v1"
    assert manifest["pc_identity"]["source_host_id"] == "container-audit-pc-01"
    raw_event_names = manifest["streams"][0]["raw_event_names"]
    catalog_names = _catalog_container_audit_raw_event_names()
    assert len(catalog_names) == 18
    assert raw_event_names == catalog_names
    assert manifest["sync"]["sync_transport"] == "http_push"
    assert manifest["sync"]["sync_dir"] == (expected_root / "events").as_posix()
    assert manifest["paths"]["data_dir"] == expected_direct_sync_root.as_posix()
    assert report["local_storage"]["events_dir"] == str(expected_root / "events")
    assert report["local_storage"]["direct_sync_root"] == str(expected_direct_sync_root)
    assert report["local_storage"]["syncthing_dependency"] is False
    assert credential["key_id"] == "server-issued-key-01"
    assert credential["secret_ref"] == "wincred:KMTech.DirectSync.ContainerAudit.PC-01"
    assert "secret" not in credential


def test_worker_pc_registration_emits_catalog_order_raw_event_names_not_gui_order(tmp_path, monkeypatch):
    local_app_data = tmp_path / "LocalAppData"
    program_data = tmp_path / "ProgramData"
    report_path = tmp_path / "registration-catalog-order-report.json"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setenv("PROGRAMDATA", str(program_data))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    exit_code = registration.main(
        [
            "--hostname",
            "PC-CATALOG",
            "--key-id",
            "server-issued-key-catalog",
            "--secret-ref",
            "wincred:KMTech.DirectSync.ContainerAudit.PC-CATALOG",
            "--report-path",
            str(report_path),
        ]
    )

    assert exit_code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    manifest = json.loads(Path(report["producer_manifest_path"]).read_text(encoding="utf-8"))
    catalog_names = _catalog_container_audit_raw_event_names()
    raw_event_names = manifest["streams"][0]["raw_event_names"]

    assert len(catalog_names) == 18
    assert raw_event_names == catalog_names
    assert raw_event_names == registration._container_audit_catalog_raw_event_names()
    assert set(raw_event_names) == set(GUI_ORDER_RAW_EVENT_NAMES)
    assert raw_event_names != GUI_ORDER_RAW_EVENT_NAMES
    assert raw_event_names[1] == "MASTER_LABEL_REPLACEMENT_APPLIED"
    assert raw_event_names[-1] == "WORK_START"


def test_worker_pc_registration_self_enrolls_and_bootstraps_wincred(tmp_path, monkeypatch):
    local_app_data = tmp_path / "LocalAppData"
    program_data = tmp_path / "ProgramData"
    report_path = tmp_path / "registration-self-enroll-report.json"
    captured = {}
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setenv("PROGRAMDATA", str(program_data))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                **_v2_response_binding(),
                "status": "enrolled",
                "producer_id": "server-producer-pc-02",
                "key_id": "server-key-pc-02",
                "secret": "server-issued-secret-pc-02",
                "secret_fingerprint_sha256": "f" * 64,
                "active_manifest_hashes": [
                    registration.manifest_hash(captured["json"]["manifest"])
                ],
                "server_binding": {
                    "producer_manifest_path": "/var/lib/worker-analysis/producers/server-producer-pc-02/producer_manifest.json",
                    "registry_path": "/var/lib/worker-analysis/producers/server-producer-pc-02/source_registry.json",
                },
            }

    def fake_post(url, *, json, headers, timeout, **kwargs):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        captured["request_kwargs"] = kwargs
        return FakeResponse()

    def fake_write_wincred(target_name, secret):
        captured["wincred_target"] = target_name
        captured["wincred_secret"] = secret

    monkeypatch.setattr(registration, "_post_enrollment_request", fake_post)
    monkeypatch.setattr(registration, "_write_wincred_secret", fake_write_wincred)

    exit_code = registration.main(
        [
            "--hostname",
            "PC-02",
            "--key-id",
            "install-request-key-pc-02",
            "--secret-ref",
            "wincred:KMTech.DirectSync.ContainerAudit.PC-02",
            "--self-enroll",
            "--enrollment-token",
            "install-token",
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--report-path",
            str(report_path),
        ]
    )

    assert exit_code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    credential = json.loads(Path(report["credential_path"]).read_text(encoding="utf-8"))

    assert report["status"] == "SELF_ENROLLMENT_REGISTERED"
    assert report["server_registration_verified"] is True
    assert report["manifest_hash_verified"] is True
    assert report["persisted_manifest_hash_verified"] is True
    assert report["manifest_hash"] == registration.manifest_hash(captured["json"]["manifest"])
    assert report["secret_bootstrap_verified"] is True
    assert report["raw_secret_written"] is False
    assert report["producer_id"] == "server-producer-pc-02"
    assert report["key_id"] == "server-key-pc-02"
    assert credential["producer_id"] == "server-producer-pc-02"
    assert credential["key_id"] == "server-key-pc-02"
    assert "secret" not in credential
    assert captured["url"] == "https://worker.example.invalid/api/producer-ingest/v2/enroll"
    assert captured["headers"]["X-Producer-Enrollment-Token"] == "install-token"
    assert captured["json"]["contract_version"] == "producer-self-enrollment-v2"
    assert captured["json"]["possession_public_jwk"] == TEST_POSSESSION_PUBLIC_JWK
    assert captured["json"]["producer_id"] == "container-audit-pc-02"
    assert captured["json"]["key_id"] == "install-request-key-pc-02"
    assert captured["json"]["manifest"]["schema_version"] == "producer-onboarding-manifest-v1"
    assert captured["wincred_target"] == "KMTech.DirectSync.ContainerAudit.PC-02"
    assert captured["wincred_secret"] == "server-issued-secret-pc-02"
    assert report["identity_action"] == "CREATED"
    assert report["authorization_state"] == "OPERATION_PENDING"
    assert report["possession_key_scope"] == "current_user"
    assert report["possession_key_fingerprint"] == TEST_POSSESSION_FINGERPRINT
    assert report["possession_key_export_policy"] == 0
    assert report["possession_private_export_status"] == "0x80090029"


def test_worker_pc_registration_self_enrolls_without_token_for_server_ip_allowlist(tmp_path, monkeypatch):
    local_app_data = tmp_path / "LocalAppData"
    program_data = tmp_path / "ProgramData"
    report_path = tmp_path / "registration-self-enroll-ip-allowlist-report.json"
    captured = {}
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setenv("PROGRAMDATA", str(program_data))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)
    monkeypatch.delenv(registration.DEFAULT_ENROLLMENT_TOKEN_ENV, raising=False)

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                **_v2_response_binding(),
                "status": "enrolled",
                "producer_id": "producer-pc-ip",
                "key_id": "server-key-pc-ip",
                "secret": "server-issued-secret-pc-ip",
                "secret_fingerprint_sha256": "a" * 64,
                "active_manifest_hashes": [
                    registration.manifest_hash(captured["json"]["manifest"])
                ],
                "server_binding": {
                    "producer_manifest_path": "/var/lib/worker-analysis/producers/producer-pc-ip/producer_manifest.json",
                    "registry_path": "/var/lib/worker-analysis/producers/producer-pc-ip/source_registry.json",
                },
            }

    def fake_post(url, *, json, headers, timeout, **kwargs):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        captured["request_kwargs"] = kwargs
        return FakeResponse()

    def fake_write_dpapi_secret(data_dir, target_name, secret):
        captured["dpapi_data_dir"] = str(data_dir)
        captured["dpapi_target"] = target_name
        captured["dpapi_secret"] = secret
        return Path(data_dir) / "secrets" / f"{target_name}.dpapi"

    monkeypatch.setattr(registration, "_post_enrollment_request", fake_post)
    monkeypatch.setattr(registration, "_write_dpapi_secret", fake_write_dpapi_secret)

    exit_code = registration.main(
        [
            "--hostname",
            "PC-IP",
            "--self-enroll",
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--report-path",
            str(report_path),
        ]
    )

    assert exit_code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    credential = json.loads(Path(report["credential_path"]).read_text(encoding="utf-8"))

    assert report["status"] == "SELF_ENROLLMENT_REGISTERED"
    assert report["enrollment_authorization_mode"] == "server_ip_allowlist"
    assert captured["headers"] == {}
    assert credential["producer_id"] == "producer-pc-ip"
    assert credential["key_id"] == "server-key-pc-ip"
    assert credential["secret_ref"] == "dpapi:KMTech.DirectSync.ContainerAudit.pc-ip"
    expected_direct_sync_root = local_app_data / "KMTech" / "DirectSync" / "container_audit"
    assert credential["secret_data_dir"] == str(expected_direct_sync_root)
    assert "secret" not in credential
    assert captured["dpapi_data_dir"] == str(expected_direct_sync_root)
    assert captured["dpapi_target"] == "KMTech.DirectSync.ContainerAudit.pc-ip"
    assert captured["dpapi_secret"] == "server-issued-secret-pc-ip"


def test_worker_pc_registration_current_user_scope_flows_to_both_profiles(
    tmp_path, monkeypatch
):
    local_app_data = tmp_path / "LocalAppData"
    report_path = tmp_path / "registration-current-user.json"
    profile_path = tmp_path / "profiles" / "Container_Audit" / "runtime-profile.json"
    tls_ca_bundle_path = tmp_path / "private-ca.cert.pem"
    tls_ca_bundle_path.write_bytes(b"private-ca-fixture")
    captured = {}
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                **_v2_response_binding(),
                "status": "enrolled",
                "producer_id": "producer-current-user",
                "key_id": "key-current-user",
                "secret": "secret-current-user",
                "active_manifest_hashes": [
                    registration.manifest_hash(captured["manifest"])
                ],
                "machine_credential_bundle": {"fixture": True},
            }

    def fake_post(_url, *, json, **kwargs):
        captured["manifest"] = json["manifest"]
        captured["request_kwargs"] = kwargs
        return FakeResponse()

    def fake_profile(_bundle, **kwargs):
        captured["profile_kwargs"] = kwargs
        return {"status": "installed", "created_paths": []}

    def fake_dpapi(data_dir, target_name, secret, *, credential_scope):
        captured["dpapi"] = {
            "data_dir": str(data_dir),
            "target_name": target_name,
            "secret": secret,
            "credential_scope": credential_scope,
        }
        path = Path(data_dir) / "secrets" / f"{target_name}.dpapi"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"protected")
        return path

    monkeypatch.setattr(registration, "_post_enrollment_request", fake_post)
    monkeypatch.setattr(
        registration,
        "ensure_runtime_profile_from_enrollment_bundle",
        fake_profile,
    )
    monkeypatch.setattr(registration, "_write_dpapi_secret", fake_dpapi)

    exit_code = registration.main(
        [
            "--hostname",
            "PC-CURRENT-USER",
            "--self-enroll",
            "--require-machine-credential-bundle",
            "--credential-scope",
            "current_user",
            "--logistics-profile-path",
            str(profile_path),
            "--tls-ca-bundle-path",
            str(tls_ca_bundle_path),
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--report-path",
            str(report_path),
        ]
    )

    assert exit_code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    credential = json.loads(Path(report["credential_path"]).read_text(encoding="utf-8"))
    assert credential["dpapi_scope"] == "current_user"
    assert captured["dpapi"]["credential_scope"] == "current_user"
    assert captured["profile_kwargs"]["credential_scope"] == "current_user"
    assert captured["profile_kwargs"]["profile_path"] == str(profile_path)
    assert captured["profile_kwargs"]["tls_ca_bundle_path"] == str(
        tls_ca_bundle_path
    )
    assert captured["request_kwargs"]["verify"] == str(tls_ca_bundle_path)
    assert captured["request_kwargs"]["allow_redirects"] is False
    assert credential["tls_ca_bundle_path"] == str(
        profile_path.resolve().parent / "tls" / "ca-bundle.pem"
    )
    assert report["enrollment_transport_trust_env"] is False


def test_enrollment_transport_ignores_environment_ca_and_passes_explicit_verify(
    monkeypatch,
):
    captured = {}
    sentinel = object()
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", r"C:\wrong\ambient-ca.pem")

    class FakeSession:
        trust_env = True

        def __enter__(self):
            captured["session"] = self
            return self

        def __exit__(self, _exc_type, _exc, _traceback):
            return None

        def post(self, url, **kwargs):
            captured["url"] = url
            captured["kwargs"] = kwargs
            return sentinel

    monkeypatch.setattr(registration.requests, "Session", FakeSession)

    response = registration._post_enrollment_request(
        "https://worker.example.invalid/api/producer-ingest/v2/enroll",
        json={"contract_version": "producer-self-enrollment-v2"},
        headers={},
        timeout=30,
        allow_redirects=False,
        verify=r"C:\approved\private-ca.pem",
    )

    assert response is sentinel
    assert captured["session"].trust_env is False
    assert captured["kwargs"]["verify"] == r"C:\approved\private-ca.pem"
    assert captured["kwargs"]["allow_redirects"] is False


@pytest.mark.skipif(os.name != "nt", reason="CurrentUser DPAPI is Windows-only")
def test_worker_pc_registration_current_user_dpapi_roundtrip():
    protected = registration._dpapi_protect_current_user("PRODUCER-USER-SECRET")

    assert protected != b"PRODUCER-USER-SECRET"
    assert registration._dpapi_unprotect_current_user(protected) == (
        "PRODUCER-USER-SECRET"
    )


def test_worker_pc_registration_blocks_manifest_hash_mismatch_before_secret_write(tmp_path, monkeypatch):
    report_path = tmp_path / "registration-manifest-hash-mismatch.json"
    writes = []
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "ProgramData"))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                **_v2_response_binding(),
                "status": "enrolled",
                "producer_id": "producer-pc-hash",
                "key_id": "server-key-pc-hash",
                "secret": "server-issued-secret-pc-hash",
                "active_manifest_hashes": ["0" * 64],
            }

    monkeypatch.setattr(
        registration,
        "_post_enrollment_request",
        lambda *args, **kwargs: FakeResponse(),
    )
    monkeypatch.setattr(
        registration,
        "_write_dpapi_secret",
        lambda *args, **kwargs: writes.append((args, kwargs)),
    )

    exit_code = registration.main(
        [
            "--hostname",
            "PC-HASH",
            "--self-enroll",
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert exit_code == 2
    assert report["status"] == "BLOCKED"
    assert "does not authorize the requested manifest hash" in report["blocked_reason"]
    assert writes == []


def test_worker_pc_registration_preserves_existing_machine_profile(tmp_path, monkeypatch):
    report_path = tmp_path / "registration-preserve-profile.json"
    captured = {}
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "ProgramData"))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                **_v2_response_binding(),
                "status": "enrolled",
                "producer_id": "producer-pc-preserve",
                "key_id": "server-key-pc-preserve",
                "secret": "server-issued-secret-pc-preserve",
                "active_manifest_hashes": [
                    registration.manifest_hash(captured["manifest"])
                ],
                "machine_credential_bundle": {"must_not_be_applied": True},
            }

    def fake_post(_url, *, json, **_kwargs):
        captured["manifest"] = json["manifest"]
        return FakeResponse()

    monkeypatch.setattr(registration, "_post_enrollment_request", fake_post)
    monkeypatch.setattr(
        registration,
        "ensure_runtime_profile_from_enrollment_bundle",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("existing machine profile must not be replaced")
        ),
    )
    monkeypatch.setattr(
        registration,
        "_write_dpapi_secret",
        lambda data_dir, target_name, secret: Path(data_dir) / "secrets" / f"{target_name}.dpapi",
    )

    exit_code = registration.main(
        [
            "--hostname",
            "PC-PRESERVE",
            "--self-enroll",
            "--preserve-existing-machine-profile",
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert report["status"] == "SELF_ENROLLMENT_REGISTERED"
    assert report["manifest_hash_verified"] is True
    assert report["persisted_manifest_hash_verified"] is True
    assert report["machine_profile_mode"] == "preserved_existing"
    assert report["machine_profiles"] == {}


def test_manifest_hash_verification_uses_canonical_json_and_fails_closed(tmp_path, capsys):
    manifest_path = tmp_path / "producer_manifest.json"
    manifest = {
        "pc_identity": {"source_host_id": "sensitive-fixture-id"},
        "apps": ["ContainerAudit"],
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    canonical_hash = registration.manifest_hash(manifest)
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() != canonical_hash

    success = registration.main(
        ["--manifest-path", str(manifest_path), "--verify-manifest-hash", canonical_hash]
    )
    success_output = capsys.readouterr().out
    failure = registration.main(
        ["--manifest-path", str(manifest_path), "--verify-manifest-hash", "0" * 64]
    )
    failure_output = capsys.readouterr().out

    assert success == 0
    assert success_output.strip() == "manifest_hash_verification=PASS"
    assert failure == 2
    assert failure_output.strip() == "manifest_hash_verification=FAIL"
    assert "sensitive-fixture-id" not in success_output + failure_output


def test_worker_pc_registration_blocks_cross_origin_self_enroll_before_token_post(tmp_path, monkeypatch):
    report_path = tmp_path / "registration-self-enroll-blocked-report.json"
    calls = []
    writes = []
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "ProgramData"))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    def fake_post(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("self-enroll request must not be sent to an unsafe URL")

    def fake_write_wincred(target_name, secret):
        writes.append((target_name, secret))

    monkeypatch.setattr(registration, "_post_enrollment_request", fake_post)
    monkeypatch.setattr(registration, "_write_wincred_secret", fake_write_wincred)

    exit_code = registration.main(
        [
            "--hostname",
            "PC-03",
            "--self-enroll",
            "--enrollment-token",
            "install-token",
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--enrollment-url",
            "http://127.0.0.1/enroll",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert exit_code == 2
    assert calls == []
    assert writes == []
    assert report["status"] == "BLOCKED"
    assert report["raw_secret_written"] is False
    assert "enrollment_url must be HTTPS, same-origin" in report["blocked_reason"]


def test_worker_pc_registration_blocks_explicit_syncthing_output_paths_before_writes(tmp_path, monkeypatch):
    report_path = tmp_path / "registration-output-path-blocked.json"
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "ProgramData"))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    exit_code = registration.main(
        [
            "--manifest-path",
            r"C:\Sync\producer_manifest.json",
            "--credential-path",
            r"C:\Sync\credential.json",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert exit_code == 2
    assert report["status"] == "BLOCKED"
    assert report["raw_secret_written"] is False
    assert report["output_path_policy"]["status"] == "FAIL"
    assert "manifest_path must not point at the legacy Syncthing folder" in report["blocked_reason"]
    assert "credential_path must not point at the legacy Syncthing folder" in report["blocked_reason"]


def test_worker_pc_registration_blocks_syncthing_report_path_without_writing_there(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "ProgramData"))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)

    exit_code = registration.main(["--report-path", r"C:\Sync\registration-report.json"])

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert exit_code == 2
    assert report["status"] == "BLOCKED"
    assert report["raw_secret_written"] is False
    assert "report_path must not point at the legacy Syncthing folder" in report["blocked_reason"]


def _self_enroll_env(tmp_path, monkeypatch):
    local_app_data = tmp_path / "LocalAppData"
    program_data = tmp_path / "ProgramData"
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setenv("PROGRAMDATA", str(program_data))
    monkeypatch.delenv(DATA_ROOT_ENV, raising=False)
    monkeypatch.setattr(registration, "_current_machine_guid", lambda: TEST_MACHINE_GUID)
    monkeypatch.setattr(registration, "_current_user_sid", lambda: TEST_USER_SID)
    return local_app_data, program_data


def test_path_independent_install_identity_fixed_vector_and_collision_boundaries():
    install_id = _generated_install_id()

    assert install_id == "container-audit-install-2cee67264192f4c9657e849f28723681"
    assert _generated_install_id(user_sid="S-1-5-21-100-200-300-1002") != install_id
    assert _generated_install_id(app_id="defect_inspection") != install_id


def test_worker_pc_registration_generated_install_id_ignores_app_and_state_paths(
    tmp_path, monkeypatch
):
    _self_enroll_env(tmp_path, monkeypatch)

    def run_probe(name, app_root, state_root):
        report_path = tmp_path / f"{name}.json"
        monkeypatch.setenv(DATA_ROOT_ENV, str(state_root))
        assert registration.main(
            [
                "--app-root",
                str(app_root),
                "--hostname",
                "PATH-PROBE",
                "--report-path",
                str(report_path),
            ]
        ) == 0
        return json.loads(report_path.read_text(encoding="utf-8"))["producer_install_id"]

    first_state = tmp_path / "state-a"
    first = run_probe("path-a", tmp_path / "release-a", first_state)
    second = run_probe("path-b", tmp_path / "release-b", tmp_path / "state-b")
    shutil.rmtree(first_state)
    recreated = run_probe("path-a-recreated", tmp_path / "release-a", first_state)

    assert first == second == recreated == _generated_install_id()


def _identity_payload(
    producer_id,
    source_host_id,
    producer_install_id,
    *,
    possession_bound=False,
):
    payload = {
        "schema_version": registration.PRODUCER_IDENTITY_SCHEMA_VERSION,
        "producer_id": producer_id,
        "source_host_id": source_host_id,
        "producer_install_id": producer_install_id,
    }
    if possession_bound:
        payload.update(
            {
                "enrollment_contract_version": (
                    registration.SELF_ENROLLMENT_CONTRACT_VERSION
                ),
                "possession_key_contract_version": (
                    registration.POSSESSION_KEY_CONTRACT_VERSION
                ),
                "possession_key_fingerprint": TEST_POSSESSION_FINGERPRINT,
            }
        )
    return payload


def _fake_enroll_post(captured, status="enrolled", status_code=200, error_code=""):
    class FakeResponse:
        def json(self):
            if status_code >= 400:
                return {
                    "status": "rejected",
                    "committed": False,
                    "retryable": False,
                    "error": {"code": error_code or str(status_code), "message": error_code},
                }
            return {
                **_v2_response_binding(),
                "status": status,
                "producer_id": captured["json"]["producer_id"],
                "key_id": captured["json"]["key_id"],
                "secret": "server-issued-secret-identity",
                "secret_fingerprint_sha256": "b" * 64,
                "active_manifest_hashes": [
                    registration.manifest_hash(captured["json"]["manifest"])
                ],
            }

        @property
        def status_code(self):
            return status_code

    def fake_post(_url, *, json, headers=None, timeout=None, **_kwargs):
        captured["url"] = _url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        return FakeResponse()

    return fake_post


def _write_admin_recovery_authorization(
    path,
    *,
    producer_id,
    authorization_id="recovery-fixture-01",
    audit_event_id="authz-audit-fixture-01",
    expires_at="2999-01-01T00:00:00Z",
):
    path.write_text(
        json.dumps(
            {
                "contract_version": (
                    registration.ADMIN_RECOVERY_AUTHORIZATION_CONTRACT_VERSION
                ),
                "authorization_id": authorization_id,
                "producer_id": producer_id,
                "recovery_token": "recovery-token-fixture",
                "nonce": "recovery-nonce-fixture",
                "expires_at": expires_at,
                "audience": registration.ADMIN_RECOVERY_AUDIENCE,
                "audit_event_id": audit_event_id,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def test_worker_pc_registration_admin_recovery_is_explicit_signed_and_cleans_secret(
    tmp_path, monkeypatch
):
    local_app_data, _program_data = _self_enroll_env(tmp_path, monkeypatch)
    report_path = tmp_path / "registration-admin-recovery-report.json"
    recovery_secret_path = tmp_path / "protected-recovery.json"
    ca_path = tmp_path / "private-ca.cert.pem"
    ca_path.write_bytes(b"private-ca-fixture")
    producer_id = "container-audit-recovery"
    _write_admin_recovery_authorization(
        recovery_secret_path,
        producer_id=producer_id,
    )
    captured = {}

    class FakeResponse:
        status_code = 200

        def json(self):
            proof = captured["json"]["proof"]
            return {
                "contract_version": (
                    registration.ADMIN_RECOVERY_COMPLETE_CONTRACT_VERSION
                ),
                "status": "recovered",
                "identity_action": "REATTACHED",
                "recovery_action": "ADMIN_RECOVERY",
                "authorization_state": "OPERATION_PENDING",
                "credential_epoch": 2,
                "producer_id": proof["producer_id"],
                "producer_install_id": proof["producer_install_id"],
                "source_host_id": proof["source_host_id"],
                "key_id": "server-recovery-key-02",
                "secret": "server-recovery-secret-02",
                "secret_fingerprint_sha256": "c" * 64,
                "active_manifest_hashes": [proof["manifest_hash"]],
                "possession_key": {
                    "contract_version": (
                        registration.POSSESSION_KEY_CONTRACT_VERSION
                    ),
                    "fingerprint": TEST_POSSESSION_FINGERPRINT,
                },
            }

    def fake_post(url, *, json, headers, timeout, **kwargs):
        captured.update(
            {
                "url": url,
                "json": json,
                "headers": headers,
                "timeout": timeout,
                "kwargs": kwargs,
            }
        )
        return FakeResponse()

    def fake_write_dpapi_secret(data_dir, target_name, secret):
        captured["dpapi_secret"] = secret
        return Path(data_dir) / "secrets" / f"{target_name}.dpapi"

    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "ambient-wrong-ca.pem"))
    monkeypatch.setattr(registration, "_post_enrollment_request", fake_post)
    monkeypatch.setattr(registration, "_write_dpapi_secret", fake_write_dpapi_secret)

    exit_code = registration.main(
        [
            "--hostname",
            "RECOVERY",
            "--admin-recovery-secret-file",
            str(recovery_secret_path),
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--tls-ca-bundle-path",
            str(ca_path),
            "--preserve-existing-machine-profile",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    identity_path = (
        local_app_data
        / "KMTech"
        / "DirectSync"
        / "container_audit"
        / "producer_identity.json"
    )
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    proof = captured["json"]["proof"]

    assert exit_code == 0
    assert report["status"] == "ADMIN_RECOVERY_REGISTERED"
    assert report["registration_action"] == "admin_recovery"
    assert report["admin_recovery_verified"] is True
    assert report["admin_recovery_secret_file_deleted"] is True
    assert report["enrollment_contract_version"] == (
        registration.SELF_ENROLLMENT_CONTRACT_VERSION
    )
    assert report["registration_contract_version"] == (
        registration.ADMIN_RECOVERY_COMPLETE_CONTRACT_VERSION
    )
    assert report["credential_epoch"] == 2
    assert not recovery_secret_path.exists()
    assert identity["possession_key_fingerprint"] == TEST_POSSESSION_FINGERPRINT
    assert captured["url"] == (
        "https://worker.example.invalid/api/producer-ingest/v2/recover"
    )
    assert captured["kwargs"]["verify"] == str(ca_path)
    assert captured["json"]["contract_version"] == (
        registration.ADMIN_RECOVERY_COMPLETE_CONTRACT_VERSION
    )
    assert captured["json"]["new_possession_public_jwk"] == (
        TEST_POSSESSION_PUBLIC_JWK
    )
    assert proof == {
        "contract_version": registration.ADMIN_RECOVERY_PROOF_CONTRACT_VERSION,
        "authorization_id": "recovery-fixture-01",
        "nonce": "recovery-nonce-fixture",
        "expires_at": "2999-01-01T00:00:00Z",
        "audience": registration.ADMIN_RECOVERY_AUDIENCE,
        "producer_id": producer_id,
        "producer_install_id": _generated_install_id(),
        "source_host_id": producer_id,
        "manifest_hash": registration.manifest_hash(captured["json"]["manifest"]),
        "new_possession_key_fingerprint": TEST_POSSESSION_FINGERPRINT,
    }
    assert len(captured["json"]["signature"]) == 86
    assert captured["dpapi_secret"] == "server-recovery-secret-02"


def test_worker_pc_registration_rejected_admin_recovery_retains_protected_secret(
    tmp_path, monkeypatch
):
    _self_enroll_env(tmp_path, monkeypatch)
    report_path = tmp_path / "registration-admin-recovery-rejected.json"
    recovery_secret_path = tmp_path / "protected-recovery.json"
    _write_admin_recovery_authorization(
        recovery_secret_path,
        producer_id="container-audit-recovery-bad",
    )

    class RejectedResponse:
        status_code = 409

        def json(self):
            return {
                "status": "rejected",
                "error": {
                    "code": "recovery_proof_invalid",
                    "message": "recovery proof invalid",
                },
            }

    monkeypatch.setattr(
        registration,
        "_post_enrollment_request",
        lambda *args, **kwargs: RejectedResponse(),
    )

    exit_code = registration.main(
        [
            "--hostname",
            "RECOVERY-BAD",
            "--admin-recovery-secret-file",
            str(recovery_secret_path),
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert exit_code == 2
    assert report["status"] == registration.ADMIN_RECOVERY_ACTION
    assert report["enrollment_error_code"] == "recovery_proof_invalid"
    assert recovery_secret_path.is_file()


class _SimulatedRecoveryPowerLoss(BaseException):
    pass


class _TwoPhaseResponse:
    def __init__(self, payload, status_code=200):
        self._payload = dict(payload)
        self.status_code = status_code

    def json(self):
        return dict(self._payload)


class _FakeRecoveryTwoPhaseServer:
    def __init__(self):
        self.state = "NONE"
        self.old_credential_active = True
        self.new_credential_active = False
        self.prepare_calls = 0
        self.commit_calls = 0
        self.status_calls = 0
        self.expire_on_status_call = None
        self.fail_on_status_call = None
        self.prepare_expires_at = "2999-01-01T00:00:00Z"
        self._prepared = None

    def _commit_payload(self):
        prepared = self._prepared
        return {
            "contract_version": (
                registration.ADMIN_RECOVERY_2PC_COMMIT_RESPONSE_CONTRACT_VERSION
            ),
            "status": "recovered",
            "recovery_state": "COMMITTED",
            "identity_action": "REATTACHED",
            "recovery_action": "ADMIN_RECOVERY",
            "authorization_state": "OPERATION_PENDING",
            "prepare_id": prepared["prepare_id"],
            "client_request_id": prepared["client_request_id"],
            "commit_id": prepared["commit_id"],
            "producer_id": prepared["producer_id"],
            "producer_install_id": prepared["producer_install_id"],
            "source_host_id": prepared["source_host_id"],
            "key_id": prepared["key_id"],
            "secret_fingerprint_sha256": prepared[
                "secret_fingerprint_sha256"
            ],
            "credential_epoch": prepared["proposed_credential_epoch"],
            "committed_at": "2026-08-29T00:00:30Z",
            "possession_key": {
                "contract_version": registration.POSSESSION_KEY_CONTRACT_VERSION,
                "fingerprint": TEST_POSSESSION_FINGERPRINT,
            },
        }

    def post(self, url, *, json, **_kwargs):
        if url.endswith(registration.ADMIN_RECOVERY_2PC_PREPARE_PATH):
            self.prepare_calls += 1
            proof = json["proof"]
            if self.state == "NONE":
                secret = "two-phase-server-secret"
                self._prepared = {
                    "prepare_id": "prepare-server-fixture-01",
                    "client_request_id": proof["client_request_id"],
                    "commit_id": registration._recovery_two_phase_id(
                        "commit",
                        {
                            "authorization_id": proof["authorization_id"],
                            "producer_id": proof["producer_id"],
                            "producer_install_id": proof[
                                "producer_install_id"
                            ],
                            "source_host_id": proof["source_host_id"],
                            "manifest_hash": proof["manifest_hash"],
                            "possession_key_fingerprint": proof[
                                "new_possession_key_fingerprint"
                            ],
                            "client_request_id": proof["client_request_id"],
                        },
                    ),
                    "producer_id": proof["producer_id"],
                    "producer_install_id": proof["producer_install_id"],
                    "source_host_id": proof["source_host_id"],
                    "manifest_hash": proof["manifest_hash"],
                    "key_id": "two-phase-key-02",
                    "secret": secret,
                    "secret_fingerprint_sha256": hashlib.sha256(
                        secret.encode("utf-8")
                    ).hexdigest(),
                    "proposed_credential_epoch": 2,
                }
                self.state = "PREPARED"
            elif self.state != "PREPARED":
                return _TwoPhaseResponse(
                    {
                        "status": "rejected",
                        "error": {
                            "code": "recovery_prepare_not_available",
                            "message": "Recovery prepare is no longer pending",
                        },
                    },
                    status_code=409,
                )
            prepared = self._prepared
            assert proof["client_request_id"] == prepared["client_request_id"]
            return _TwoPhaseResponse(
                {
                    "contract_version": (
                        registration.ADMIN_RECOVERY_2PC_PREPARE_RESPONSE_CONTRACT_VERSION
                    ),
                    "status": "prepared",
                    "recovery_state": "PREPARED",
                    "identity_action": "REATTACHED",
                    "recovery_action": "ADMIN_RECOVERY",
                    "authorization_state": "RESERVED",
                    "prepare_id": prepared["prepare_id"],
                    "prepare_expires_at": self.prepare_expires_at,
                    "client_request_id": prepared["client_request_id"],
                    "producer_id": prepared["producer_id"],
                    "producer_install_id": prepared["producer_install_id"],
                    "source_host_id": prepared["source_host_id"],
                    "proposed_credential_epoch": prepared[
                        "proposed_credential_epoch"
                    ],
                    "key_id": prepared["key_id"],
                    "secret": prepared["secret"],
                    "secret_fingerprint_sha256": prepared[
                        "secret_fingerprint_sha256"
                    ],
                    "active_manifest_hashes": [prepared["manifest_hash"]],
                    "possession_key": {
                        "contract_version": (
                            registration.POSSESSION_KEY_CONTRACT_VERSION
                        ),
                        "fingerprint": TEST_POSSESSION_FINGERPRINT,
                    },
                }
            )
        if url.endswith(registration.ADMIN_RECOVERY_2PC_STATUS_PATH):
            self.status_calls += 1
            if self.fail_on_status_call == self.status_calls:
                raise RuntimeError("simulated status transport failure")
            if self.expire_on_status_call == self.status_calls:
                self.state = "EXPIRED"
            assert (
                json["contract_version"]
                == registration.ADMIN_RECOVERY_2PC_STATUS_REQUEST_CONTRACT_VERSION
            )
            assert len(json["signature"]) == 86
            proof = json["proof"]
            assert (
                proof["contract_version"]
                == registration.ADMIN_RECOVERY_2PC_STATUS_PROOF_CONTRACT_VERSION
            )
            prepared = self._prepared
            assert proof["prepare_id"] == prepared["prepare_id"]
            payload = {
                "contract_version": (
                    registration.ADMIN_RECOVERY_2PC_STATUS_RESPONSE_CONTRACT_VERSION
                ),
                "status": "observed",
                "recovery_state": self.state,
                "prepare_id": prepared["prepare_id"],
                "client_request_id": prepared["client_request_id"],
                "producer_id": prepared["producer_id"],
                "producer_install_id": prepared["producer_install_id"],
                "source_host_id": prepared["source_host_id"],
            }
            if self.state == "COMMITTED":
                committed = self._commit_payload()
                for key in (
                    "identity_action",
                    "recovery_action",
                    "authorization_state",
                    "commit_id",
                    "key_id",
                    "secret_fingerprint_sha256",
                    "credential_epoch",
                    "committed_at",
                    "possession_key",
                ):
                    payload[key] = committed[key]
            return _TwoPhaseResponse(payload)
        if url.endswith(registration.ADMIN_RECOVERY_2PC_COMMIT_PATH):
            self.commit_calls += 1
            proof = json["proof"]
            prepared = self._prepared
            assert proof["prepare_id"] == prepared["prepare_id"]
            assert proof["commit_id"] == prepared["commit_id"]
            self.state = "COMMITTED"
            self.old_credential_active = False
            self.new_credential_active = True
            return _TwoPhaseResponse(self._commit_payload())
        raise AssertionError(f"unexpected two-phase URL: {url}")


def _two_phase_recovery_args(tmp_path, recovery_secret_path, report_path):
    return [
        "--hostname",
        "RECOVERY-2PC",
        "--producer-id",
        "container-audit-recovery-2pc",
        "--source-host-id",
        "container-audit-recovery-2pc",
        "--producer-install-id",
        "container-audit-install-recovery-2pc",
        "--admin-recovery-secret-file",
        str(recovery_secret_path),
        "--admin-recovery-two-phase",
        "--admin-recovery-journal-path",
        str(tmp_path / "recovery-two-phase-journal.json"),
        "--endpoint-url",
        "https://worker.example.invalid/api/producer-ingest/v1/source-file",
        "--credential-scope",
        "current_user",
        "--preserve-existing-machine-profile",
        "--report-path",
        str(report_path),
    ]


@pytest.mark.parametrize(
    ("cut_point", "expected_first_server_state"),
    [
        ("BEFORE_PREPARE_REQUEST", "NONE"),
        ("AFTER_PREPARE_RESPONSE", "PREPARED"),
        ("BEFORE_LOCAL_PACKAGE_STAGE", "PREPARED"),
        ("AFTER_LOCAL_PACKAGE_STAGE", "PREPARED"),
        ("BEFORE_COMMIT_REQUEST", "PREPARED"),
        ("AFTER_COMMIT_REQUEST", "COMMITTED"),
        ("BEFORE_COMMIT_RESPONSE_ACCEPT", "COMMITTED"),
        ("AFTER_COMMIT_RESPONSE_ACCEPT", "COMMITTED"),
        ("BEFORE_LOCAL_CREDENTIAL_ACTIVATION", "COMMITTED"),
        ("AFTER_LOCAL_CREDENTIAL_ACTIVATION", "COMMITTED"),
        ("AFTER_ALL_LOCAL_PERSISTENCE", "COMMITTED"),
        ("AFTER_COMPLETE_JOURNAL", "COMMITTED"),
    ],
)
def test_two_phase_recovery_resumes_every_crash_cut_without_new_authorization(
    tmp_path,
    monkeypatch,
    cut_point,
    expected_first_server_state,
):
    _self_enroll_env(tmp_path, monkeypatch)
    recovery_secret_path = tmp_path / "protected-recovery.json"
    report_path = tmp_path / "registration-two-phase-report.json"
    _write_admin_recovery_authorization(
        recovery_secret_path,
        producer_id="container-audit-recovery-2pc",
    )
    server = _FakeRecoveryTwoPhaseServer()
    active_secrets = []
    crash = {"armed": True}

    def crash_hook(observed):
        if crash["armed"] and observed == cut_point:
            crash["armed"] = False
            raise _SimulatedRecoveryPowerLoss(observed)

    def fake_write_dpapi_secret(data_dir, target_name, secret, **_kwargs):
        active_secrets.append(secret)
        return Path(data_dir) / "secrets" / f"{target_name}.dpapi"

    monkeypatch.setattr(registration, "_post_enrollment_request", server.post)
    monkeypatch.setattr(registration, "_write_dpapi_secret", fake_write_dpapi_secret)
    monkeypatch.setattr(
        registration,
        "_dpapi_protect_current_user",
        lambda value: b"sealed-fixture:" + value.encode("utf-8"),
    )
    monkeypatch.setattr(
        registration,
        "_dpapi_unprotect_current_user",
        lambda value: value.removeprefix(b"sealed-fixture:").decode("utf-8"),
    )
    monkeypatch.setattr(registration, "_recovery_two_phase_cut_point", crash_hook)
    args = _two_phase_recovery_args(
        tmp_path,
        recovery_secret_path,
        report_path,
    )

    with pytest.raises(_SimulatedRecoveryPowerLoss, match=cut_point):
        registration.main(args)

    assert server.state == expected_first_server_state
    assert server.old_credential_active is (server.state != "COMMITTED")
    assert server.new_credential_active is (server.state == "COMMITTED")
    assert recovery_secret_path.is_file() is (
        cut_point != "AFTER_COMPLETE_JOURNAL"
    )
    if cut_point == "AFTER_LOCAL_PACKAGE_STAGE":
        _write_admin_recovery_authorization(
            recovery_secret_path,
            producer_id="container-audit-recovery-2pc",
            expires_at="2000-01-01T00:00:00Z",
        )

    monkeypatch.setattr(
        registration,
        "_recovery_two_phase_cut_point",
        lambda _name: None,
    )
    assert registration.main(args) == 0

    report = json.loads(report_path.read_text(encoding="utf-8"))
    journal_path = tmp_path / "recovery-two-phase-journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert server.state == "COMMITTED"
    assert server.old_credential_active is False
    assert server.new_credential_active is True
    assert server.commit_calls == 1
    assert server.status_calls >= 1
    assert report["status"] == "ADMIN_RECOVERY_REGISTERED"
    assert report["recovery_two_phase"] is True
    assert report["recovery_two_phase_state"] == "COMPLETE"
    assert report["recovery_two_phase_resume_without_admin"] is True
    assert report["producer_credential_dual_valid_window"] is False
    assert report["admin_recovery_secret_file_deleted"] is True
    assert journal["state"] == "COMPLETE"
    assert not recovery_secret_path.exists()
    assert not (tmp_path / "recovery-two-phase-journal.prepared-package.dpapi").exists()
    assert active_secrets[-1] == "two-phase-server-secret"


@pytest.mark.parametrize(
    ("cut_point", "first_journal_state", "remove_authorization_before_restart"),
    [
        ("BEFORE_EXPIRED_TERMINAL_JOURNAL", "PREPARED", True),
        ("AFTER_EXPIRED_TERMINAL_JOURNAL", "EXPIRED", False),
    ],
)
def test_two_phase_expiry_crash_cuts_restart_to_audited_terminal_state(
    tmp_path,
    monkeypatch,
    cut_point,
    first_journal_state,
    remove_authorization_before_restart,
):
    _self_enroll_env(tmp_path, monkeypatch)
    recovery_secret_path = tmp_path / "protected-recovery.json"
    report_path = tmp_path / "registration-two-phase-report.json"
    _write_admin_recovery_authorization(
        recovery_secret_path,
        producer_id="container-audit-recovery-2pc",
    )
    server = _FakeRecoveryTwoPhaseServer()
    server.expire_on_status_call = 1
    server.prepare_expires_at = "2000-01-01T00:00:00Z"
    active_secrets = []
    crash = {"armed": True}

    def crash_hook(observed):
        if crash["armed"] and observed == cut_point:
            crash["armed"] = False
            raise _SimulatedRecoveryPowerLoss(observed)

    def fake_write_dpapi_secret(data_dir, target_name, secret, **_kwargs):
        active_secrets.append(secret)
        return Path(data_dir) / "secrets" / f"{target_name}.dpapi"

    monkeypatch.setattr(registration, "_post_enrollment_request", server.post)
    monkeypatch.setattr(registration, "_write_dpapi_secret", fake_write_dpapi_secret)
    monkeypatch.setattr(
        registration,
        "_dpapi_protect_current_user",
        lambda value: b"sealed-fixture:" + value.encode("utf-8"),
    )
    monkeypatch.setattr(
        registration,
        "_dpapi_unprotect_current_user",
        lambda value: value.removeprefix(b"sealed-fixture:").decode("utf-8"),
    )
    monkeypatch.setattr(registration, "_recovery_two_phase_cut_point", crash_hook)
    args = _two_phase_recovery_args(
        tmp_path,
        recovery_secret_path,
        report_path,
    )

    with pytest.raises(_SimulatedRecoveryPowerLoss, match=cut_point):
        registration.main(args)

    journal_path = tmp_path / "recovery-two-phase-journal.json"
    first_journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert first_journal["state"] == first_journal_state
    assert first_journal["prepare_expires_at"] == "2000-01-01T00:00:00Z"
    assert server.state == "EXPIRED"
    assert server.commit_calls == 0
    assert server.old_credential_active is True
    assert server.new_credential_active is False
    if remove_authorization_before_restart:
        recovery_secret_path.unlink()

    monkeypatch.setattr(
        registration,
        "_recovery_two_phase_cut_point",
        lambda _name: None,
    )
    assert registration.main(args) == 2

    report = json.loads(report_path.read_text(encoding="utf-8"))
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert report["status"] == registration.ADMIN_RECOVERY_ACTION
    assert report["enrollment_error_code"] == "recovery_prepare_expired"
    assert report["required_next_action"] == "NEW_AUDITED_RECOVERY_REQUIRED"
    assert report["server_credential_committed"] is False
    assert report["recovery_two_phase_state"] == "EXPIRED"
    assert journal["state"] == "EXPIRED"
    assert (
        journal["terminal_reason_code"]
        == "SIGNED_STATUS_CONFIRMED_PREPARE_EXPIRED"
    )
    assert journal["terminal_server_state"] == "EXPIRED"
    assert journal["committed_credential_epoch"] is None
    assert server.commit_calls == 0
    assert active_secrets == []
    assert recovery_secret_path.is_file() is (
        not remove_authorization_before_restart
    )
    assert not (
        tmp_path / "recovery-two-phase-journal.prepared-package.dpapi"
    ).exists()


def test_two_phase_expiry_after_package_stage_removes_stale_package(
    tmp_path,
    monkeypatch,
):
    _self_enroll_env(tmp_path, monkeypatch)
    recovery_secret_path = tmp_path / "protected-recovery.json"
    report_path = tmp_path / "registration-two-phase-report.json"
    _write_admin_recovery_authorization(
        recovery_secret_path,
        producer_id="container-audit-recovery-2pc",
    )
    server = _FakeRecoveryTwoPhaseServer()
    server.expire_on_status_call = 2
    active_secrets = []

    monkeypatch.setattr(registration, "_post_enrollment_request", server.post)
    monkeypatch.setattr(
        registration,
        "_write_dpapi_secret",
        lambda _data_dir, _target_name, secret, **_kwargs: active_secrets.append(
            secret
        ),
    )
    monkeypatch.setattr(
        registration,
        "_dpapi_protect_current_user",
        lambda value: b"sealed-fixture:" + value.encode("utf-8"),
    )
    monkeypatch.setattr(
        registration,
        "_dpapi_unprotect_current_user",
        lambda value: value.removeprefix(b"sealed-fixture:").decode("utf-8"),
    )
    args = _two_phase_recovery_args(
        tmp_path,
        recovery_secret_path,
        report_path,
    )

    assert registration.main(args) == 2

    journal_path = tmp_path / "recovery-two-phase-journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert [row["to"] for row in journal["transitions"]][-3:] == [
        "LOCAL_PACKAGE_DURABLE",
        "COMMIT_INTENT_DURABLE",
        "EXPIRED",
    ]
    assert report["enrollment_error_code"] == "recovery_prepare_expired"
    assert report["recovery_two_phase_state"] == "EXPIRED"
    assert server.commit_calls == 0
    assert server.old_credential_active is True
    assert server.new_credential_active is False
    assert active_secrets == []
    assert not (
        tmp_path / "recovery-two-phase-journal.prepared-package.dpapi"
    ).exists()


def test_two_phase_terminal_journals_roll_to_new_authorizations(
    tmp_path,
    monkeypatch,
):
    _self_enroll_env(tmp_path, monkeypatch)
    recovery_secret_path = tmp_path / "protected-recovery.json"
    report_path = tmp_path / "registration-two-phase-report.json"
    _write_admin_recovery_authorization(
        recovery_secret_path,
        producer_id="container-audit-recovery-2pc",
    )
    expired_server = _FakeRecoveryTwoPhaseServer()
    expired_server.expire_on_status_call = 1
    active_secrets = []

    def fake_write_dpapi_secret(data_dir, target_name, secret, **_kwargs):
        active_secrets.append(secret)
        return Path(data_dir) / "secrets" / f"{target_name}.dpapi"

    monkeypatch.setattr(
        registration,
        "_post_enrollment_request",
        expired_server.post,
    )
    monkeypatch.setattr(registration, "_write_dpapi_secret", fake_write_dpapi_secret)
    monkeypatch.setattr(
        registration,
        "_dpapi_protect_current_user",
        lambda value: b"sealed-fixture:" + value.encode("utf-8"),
    )
    monkeypatch.setattr(
        registration,
        "_dpapi_unprotect_current_user",
        lambda value: value.removeprefix(b"sealed-fixture:").decode("utf-8"),
    )
    args = _two_phase_recovery_args(
        tmp_path,
        recovery_secret_path,
        report_path,
    )

    assert registration.main(args) == 2
    journal_path = tmp_path / "recovery-two-phase-journal.json"
    expired_journal = json.loads(journal_path.read_text(encoding="utf-8"))
    assert expired_journal["state"] == "EXPIRED"
    assert expired_server.commit_calls == 0

    _write_admin_recovery_authorization(
        recovery_secret_path,
        producer_id="container-audit-recovery-2pc",
        authorization_id="recovery-fixture-02",
        audit_event_id="authz-audit-fixture-02",
    )
    replacement_server = _FakeRecoveryTwoPhaseServer()
    monkeypatch.setattr(
        registration,
        "_post_enrollment_request",
        replacement_server.post,
    )

    assert registration.main(args) == 0

    completed = json.loads(journal_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    archived = list(tmp_path.glob("terminal-*.json"))
    assert completed["state"] == "COMPLETE"
    assert completed["bindings"]["authorization_id"] == "recovery-fixture-02"
    assert report["status"] == "ADMIN_RECOVERY_REGISTERED"
    assert report["recovery_two_phase_state"] == "COMPLETE"
    assert replacement_server.commit_calls == 1
    assert replacement_server.old_credential_active is False
    assert replacement_server.new_credential_active is True
    assert len(archived) == 1
    assert json.loads(archived[0].read_text(encoding="utf-8"))["state"] == (
        "EXPIRED"
    )
    assert not recovery_secret_path.exists()
    assert active_secrets[-1] == "two-phase-server-secret"

    stale_complete_package = (
        tmp_path / "recovery-two-phase-journal.prepared-package.dpapi"
    )
    stale_complete_package.write_bytes(b"sealed-package-left-by-power-loss")
    assert stale_complete_package.is_file()
    _write_admin_recovery_authorization(
        recovery_secret_path,
        producer_id="container-audit-recovery-2pc",
        authorization_id="recovery-fixture-03",
        audit_event_id="authz-audit-fixture-03",
    )
    third_server = _FakeRecoveryTwoPhaseServer()
    monkeypatch.setattr(
        registration,
        "_post_enrollment_request",
        third_server.post,
    )

    assert registration.main(args) == 0

    third_completed = json.loads(journal_path.read_text(encoding="utf-8"))
    completed_archives = list(tmp_path.glob("completed-*.json"))
    assert third_completed["state"] == "COMPLETE"
    assert third_completed["bindings"]["authorization_id"] == (
        "recovery-fixture-03"
    )
    assert third_server.commit_calls == 1
    assert len(completed_archives) == 1
    assert json.loads(
        completed_archives[0].read_text(encoding="utf-8")
    )["state"] == "COMPLETE"
    assert not recovery_secret_path.exists()
    assert not stale_complete_package.exists()


def test_two_phase_unavailable_status_remains_reconcilable_not_expired(
    tmp_path,
    monkeypatch,
):
    _self_enroll_env(tmp_path, monkeypatch)
    recovery_secret_path = tmp_path / "protected-recovery.json"
    report_path = tmp_path / "registration-two-phase-report.json"
    _write_admin_recovery_authorization(
        recovery_secret_path,
        producer_id="container-audit-recovery-2pc",
    )
    server = _FakeRecoveryTwoPhaseServer()
    server.fail_on_status_call = 2

    monkeypatch.setattr(registration, "_post_enrollment_request", server.post)
    monkeypatch.setattr(
        registration,
        "_dpapi_protect_current_user",
        lambda value: b"sealed-fixture:" + value.encode("utf-8"),
    )
    monkeypatch.setattr(
        registration,
        "_dpapi_unprotect_current_user",
        lambda value: value.removeprefix(b"sealed-fixture:").decode("utf-8"),
    )
    args = _two_phase_recovery_args(
        tmp_path,
        recovery_secret_path,
        report_path,
    )

    assert registration.main(args) == 2

    journal_path = tmp_path / "recovery-two-phase-journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert journal["state"] == "COMMIT_INTENT_DURABLE"
    assert journal["terminal_reason_code"] == ""
    assert journal["terminal_server_state"] == ""
    assert journal["terminal_observed_at"] == ""
    assert report["status"] == "RESUME_TWO_PHASE_RECOVERY"
    assert report["recovery_two_phase_state"] == "COMMIT_INTENT_DURABLE"
    assert report["server_credential_committed"] is False
    assert server.state == "PREPARED"
    assert server.commit_calls == 0
    assert recovery_secret_path.is_file()
    assert (
        tmp_path / "recovery-two-phase-journal.prepared-package.dpapi"
    ).is_file()


def test_legacy_v2_recovery_remains_default_when_two_phase_flag_is_absent(
    tmp_path,
    monkeypatch,
):
    _self_enroll_env(tmp_path, monkeypatch)
    recovery_secret_path = tmp_path / "protected-legacy-recovery.json"
    report_path = tmp_path / "registration-legacy-recovery-report.json"
    producer_id = "container-audit-legacy-default"
    _write_admin_recovery_authorization(
        recovery_secret_path,
        producer_id=producer_id,
    )
    captured = {}

    class LegacyResponse:
        status_code = 200

        def json(self):
            proof = captured["json"]["proof"]
            return {
                "contract_version": (
                    registration.ADMIN_RECOVERY_COMPLETE_CONTRACT_VERSION
                ),
                "status": "recovered",
                "identity_action": "REATTACHED",
                "recovery_action": "ADMIN_RECOVERY",
                "authorization_state": "OPERATION_PENDING",
                "credential_epoch": 2,
                "producer_id": proof["producer_id"],
                "producer_install_id": proof["producer_install_id"],
                "source_host_id": proof["source_host_id"],
                "key_id": "legacy-key-02",
                "secret": "legacy-secret-02",
                "secret_fingerprint_sha256": hashlib.sha256(
                    b"legacy-secret-02"
                ).hexdigest(),
                "active_manifest_hashes": [proof["manifest_hash"]],
                "possession_key": {
                    "contract_version": registration.POSSESSION_KEY_CONTRACT_VERSION,
                    "fingerprint": TEST_POSSESSION_FINGERPRINT,
                },
            }

    def legacy_post(url, *, json, **_kwargs):
        captured.update({"url": url, "json": json})
        return LegacyResponse()

    monkeypatch.setattr(registration, "_post_enrollment_request", legacy_post)
    monkeypatch.setattr(
        registration,
        "_write_dpapi_secret",
        lambda data_dir, target_name, _secret, **_kwargs: Path(data_dir)
        / "secrets"
        / f"{target_name}.dpapi",
    )

    assert registration.main(
        [
            "--hostname",
            "LEGACY-DEFAULT",
            "--producer-id",
            producer_id,
            "--source-host-id",
            producer_id,
            "--producer-install-id",
            "legacy-default-install",
            "--admin-recovery-secret-file",
            str(recovery_secret_path),
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--credential-scope",
            "current_user",
            "--preserve-existing-machine-profile",
            "--report-path",
            str(report_path),
        ]
    ) == 0

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert captured["url"].endswith(registration.ADMIN_RECOVERY_PATH)
    assert report.get("recovery_two_phase") is None
    assert report["registration_contract_version"] == (
        registration.ADMIN_RECOVERY_COMPLETE_CONTRACT_VERSION
    )


def test_worker_pc_registration_persists_identity_after_self_enroll_success(tmp_path, monkeypatch):
    local_app_data, _program_data = _self_enroll_env(tmp_path, monkeypatch)
    report_path = tmp_path / "registration-identity-persist-report.json"
    captured = {}
    monkeypatch.setattr(
        registration,
        "_post_enrollment_request",
        _fake_enroll_post(captured),
    )
    monkeypatch.setattr(
        registration,
        "_write_dpapi_secret",
        lambda data_dir, target_name, secret: Path(data_dir) / "secrets" / f"{target_name}.dpapi",
    )

    exit_code = registration.main(
        [
            "--hostname",
            "PC-PERSIST",
            "--self-enroll",
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    identity_path = local_app_data / "KMTech" / "DirectSync" / "container_audit" / "producer_identity.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    generated_install_id = _generated_install_id()

    assert exit_code == 0
    assert report["status"] == "SELF_ENROLLMENT_REGISTERED"
    assert report["producer_identity_source"] == "generated"
    assert report["producer_install_id_derivation"] == (
        registration.INSTALL_IDENTITY_DERIVATION_VERSION
    )
    assert report["producer_identity_persisted"] is True
    assert Path(report["producer_identity_path"]) == identity_path.resolve()
    assert identity == _identity_payload(
        "container-audit-pc-persist",
        "container-audit-pc-persist",
        generated_install_id,
        possession_bound=True,
    )
    assert captured["json"]["producer_id"] == "container-audit-pc-persist"
    assert captured["json"]["manifest"]["pc_identity"]["producer_install_id"] == generated_install_id
    assert captured["json"]["manifest"]["streams"][0]["raw_event_names"] == (
        registration._container_audit_catalog_raw_event_names()
    )


def test_worker_pc_registration_preserves_legacy_identity_without_key_or_http(
    tmp_path, monkeypatch
):
    local_app_data, _program_data = _self_enroll_env(tmp_path, monkeypatch)
    identity_path = local_app_data / "KMTech" / "DirectSync" / "container_audit" / "producer_identity.json"
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    pinned = _identity_payload(
        "container-audit-pc-reuse",
        "container-audit-pc-reuse",
        "container-audit-pc-reuse-aaaaaaaaaaaa",
    )
    identity_path.write_text(json.dumps(pinned, indent=2) + "\n", encoding="utf-8")
    report_path = tmp_path / "registration-identity-reuse-report.json"
    calls = []
    monkeypatch.setattr(
        registration,
        "_current_machine_guid",
        lambda: (_ for _ in ()).throw(AssertionError("persisted identity must bypass machine lookup")),
    )
    monkeypatch.setattr(
        registration,
        "_current_user_sid",
        lambda: (_ for _ in ()).throw(AssertionError("persisted identity must bypass user lookup")),
    )
    monkeypatch.setattr(
        registration,
        "_post_enrollment_request",
        lambda *args, **kwargs: calls.append((args, kwargs))
        or (_ for _ in ()).throw(
            AssertionError("legacy identity must not be enrolled automatically")
        ),
    )
    monkeypatch.setattr(
        registration.PersistentPossessionKey,
        "provision_initial",
        classmethod(
            lambda _cls, *args, **kwargs: (_ for _ in ()).throw(
                AssertionError("legacy identity must not create a possession key")
            )
        ),
    )
    monkeypatch.setattr(
        registration,
        "_write_dpapi_secret",
        lambda data_dir, target_name, secret: Path(data_dir) / "secrets" / f"{target_name}.dpapi",
    )

    exit_code = registration.main(
        [
            "--hostname",
            "PC-REUSE",
            "--self-enroll",
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    persisted = json.loads(identity_path.read_text(encoding="utf-8"))
    assert exit_code == 2
    assert report["status"] == registration.ADMIN_RECOVERY_ACTION
    assert report["recovery_action"] == registration.ADMIN_RECOVERY_ACTION
    assert report["enrollment_error_code"] == (
        "legacy_producer_admin_recovery_required"
    )
    assert report["automatic_key_replacement"] is False
    assert report["automatic_legacy_migration"] is False
    assert "existing legacy producer identity" in report["blocked_reason"]
    assert calls == []
    assert persisted == pinned


def test_worker_pc_registration_pins_explicit_producer_install_id_over_generated(tmp_path, monkeypatch):
    _self_enroll_env(tmp_path, monkeypatch)
    report_path = tmp_path / "registration-identity-pin-report.json"
    captured = {}
    monkeypatch.setattr(
        registration,
        "_post_enrollment_request",
        _fake_enroll_post(captured),
    )
    monkeypatch.setattr(
        registration,
        "_write_dpapi_secret",
        lambda data_dir, target_name, secret: Path(data_dir) / "secrets" / f"{target_name}.dpapi",
    )

    exit_code = registration.main(
        [
            "--hostname",
            "TEST1",
            "--producer-id",
            "container-audit-test1",
            "--source-host-id",
            "container-audit-test1",
            "--producer-install-id",
            "container-audit-test1-pin-fixture",
            "--self-enroll",
            "--confirm-new-server-identity",
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    identity_path = Path(report["producer_identity_path"])
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    generated_install_id = _generated_install_id()

    assert exit_code == 0
    assert report["producer_identity_source"] == "cli"
    assert report["producer_install_id_derivation"] == "cli"
    assert captured["json"]["producer_id"] == "container-audit-test1"
    assert captured["json"]["manifest"]["pc_identity"]["producer_install_id"] == (
        "container-audit-test1-pin-fixture"
    )
    assert captured["json"]["manifest"]["pc_identity"]["producer_install_id"] != generated_install_id
    assert identity["producer_install_id"] == "container-audit-test1-pin-fixture"
    assert identity["enrollment_contract_version"] == (
        registration.SELF_ENROLLMENT_CONTRACT_VERSION
    )
    assert identity["possession_key_fingerprint"] == TEST_POSSESSION_FINGERPRINT
    assert "9231ea1cf5b8" not in identity_path.read_text(encoding="utf-8")


def test_worker_pc_registration_seeded_legacy_identity_requires_admin_recovery(
    tmp_path, monkeypatch
):
    _self_enroll_env(tmp_path, monkeypatch)
    seed_path = tmp_path / "seed" / "producer_identity.json"
    seed_path.parent.mkdir()
    seed = _identity_payload(
        "container-audit-seed-host",
        "container-audit-seed-host",
        "container-audit-seed-host-bbbbbbbbbbbb",
    )
    seed_path.write_text(json.dumps(seed, indent=2) + "\n", encoding="utf-8")
    report_path = tmp_path / "registration-identity-seed-report.json"
    calls = []
    monkeypatch.setattr(
        registration,
        "_post_enrollment_request",
        lambda *args, **kwargs: calls.append((args, kwargs))
        or (_ for _ in ()).throw(
            AssertionError("seeded legacy identity must not enroll")
        ),
    )
    monkeypatch.setattr(
        registration,
        "_write_dpapi_secret",
        lambda data_dir, target_name, secret: Path(data_dir) / "secrets" / f"{target_name}.dpapi",
    )

    exit_code = registration.main(
        [
            "--hostname",
            "PC-SEED",
            "--producer-identity-path",
            str(seed_path),
            "--self-enroll",
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert exit_code == 2
    assert report["status"] == registration.ADMIN_RECOVERY_ACTION
    assert report["recovery_action"] == registration.ADMIN_RECOVERY_ACTION
    assert report["automatic_legacy_migration"] is False
    assert calls == []
    assert json.loads(seed_path.read_text(encoding="utf-8")) == seed


def test_worker_pc_registration_identity_conflict_fail_closed_without_reuse_evidence(
    tmp_path, monkeypatch
):
    local_app_data, _program_data = _self_enroll_env(tmp_path, monkeypatch)
    report_path = tmp_path / "registration-identity-conflict-report.json"
    captured = {}
    identity_path = local_app_data / "KMTech" / "DirectSync" / "container_audit" / "producer_identity.json"
    monkeypatch.setattr(
        registration,
        "_post_enrollment_request",
        _fake_enroll_post(
            captured,
            status_code=409,
            error_code="producer_identity_conflict",
        ),
    )
    writes = []
    monkeypatch.setattr(
        registration,
        "_write_dpapi_secret",
        lambda *args, **kwargs: writes.append((args, kwargs)),
    )

    exit_code = registration.main(
        [
            "--hostname",
            "TEST1",
            "--self-enroll",
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert exit_code == 2
    assert report["status"] == registration.ADMIN_RECOVERY_ACTION
    assert report["recovery_action"] == registration.ADMIN_RECOVERY_ACTION
    assert report["enrollment_error_code"] == "producer_identity_conflict"
    assert report["automatic_legacy_migration"] is False
    assert "audited administrator recovery" in report["blocked_reason"]
    assert report["raw_secret_written"] is False
    assert writes == []
    assert not identity_path.exists()
    assert captured["json"]["manifest"]["pc_identity"]["producer_install_id"] == (
        _generated_install_id()
    )
    assert captured["json"]["manifest"]["streams"][0]["raw_event_names"] == (
        registration._container_audit_catalog_raw_event_names()
    )


def test_worker_pc_registration_blocks_malformed_identity_file_before_enroll(tmp_path, monkeypatch):
    _self_enroll_env(tmp_path, monkeypatch)
    seed_path = tmp_path / "bad-identity.json"
    seed_path.write_text("{}\n", encoding="utf-8")
    report_path = tmp_path / "registration-bad-identity-report.json"
    calls = []
    monkeypatch.setattr(
        registration,
        "_post_enrollment_request",
        lambda *args, **kwargs: calls.append((args, kwargs)) or (_ for _ in ()).throw(
            AssertionError("malformed identity must not enroll")
        ),
    )

    exit_code = registration.main(
        [
            "--hostname",
            "PC-BAD",
            "--producer-identity-path",
            str(seed_path),
            "--self-enroll",
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert exit_code == 2
    assert calls == []
    assert report["status"] == "BLOCKED"
    assert "schema_version is invalid" in report["blocked_reason"]


def test_worker_pc_registration_blocks_syncthing_identity_path(tmp_path, monkeypatch):
    _self_enroll_env(tmp_path, monkeypatch)
    report_path = tmp_path / "registration-identity-syncthing-report.json"

    exit_code = registration.main(
        [
            "--producer-identity-path",
            r"C:\Sync\producer_identity.json",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert exit_code == 2
    assert report["status"] == "BLOCKED"
    assert "producer_identity_path must not point at the legacy Syncthing folder" in report[
        "blocked_reason"
    ]


def test_worker_pc_registration_blocks_syncthing_data_root(tmp_path, monkeypatch):
    report_path = tmp_path / "registration-blocked.json"
    monkeypatch.setenv(DATA_ROOT_ENV, r"C:\Sync")

    exit_code = registration.main(["--report-path", str(report_path)])

    assert exit_code == 2
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "BLOCKED"
    assert report["raw_secret_written"] is False
    assert "legacy Syncthing folder" in report["blocked_reason"]
