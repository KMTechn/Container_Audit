import hashlib
import json
import os
from pathlib import Path

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
    "MASTER_LABEL_REPLACEMENT_APPLIED",
    "PHS_REPLACEMENT_WAITING_MARKED",
    "PHS_RECONCILIATION_ACTION_RESOLVED",
    "PHS_RECONCILIATION_LABEL_EXCHANGED",
    "WORK_END",
]


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
    assert len(catalog_names) == 17
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

    assert len(catalog_names) == 17
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

    monkeypatch.setattr(registration.requests, "post", fake_post)
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
    assert captured["url"] == "https://worker.example.invalid/api/producer-ingest/v1/enroll"
    assert captured["headers"]["X-Producer-Enrollment-Token"] == "install-token"
    assert captured["json"]["contract_version"] == "producer-self-enrollment-v1"
    assert captured["json"]["producer_id"] == "container-audit-pc-02"
    assert captured["json"]["key_id"] == "install-request-key-pc-02"
    assert captured["json"]["manifest"]["schema_version"] == "producer-onboarding-manifest-v1"
    assert captured["wincred_target"] == "KMTech.DirectSync.ContainerAudit.PC-02"
    assert captured["wincred_secret"] == "server-issued-secret-pc-02"


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

    monkeypatch.setattr(registration.requests, "post", fake_post)
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

    monkeypatch.setattr(registration.requests, "post", fake_post)
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
                "status": "enrolled",
                "producer_id": "producer-pc-hash",
                "key_id": "server-key-pc-hash",
                "secret": "server-issued-secret-pc-hash",
                "active_manifest_hashes": ["0" * 64],
            }

    monkeypatch.setattr(registration.requests, "post", lambda *args, **kwargs: FakeResponse())
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
                "status": "already_enrolled",
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

    monkeypatch.setattr(registration.requests, "post", fake_post)
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

    monkeypatch.setattr(registration.requests, "post", fake_post)
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
    monkeypatch.setattr(registration.uuid, "getnode", lambda: 0xEDE662C694C5)
    return local_app_data, program_data


def _identity_payload(producer_id, source_host_id, producer_install_id):
    return {
        "schema_version": registration.PRODUCER_IDENTITY_SCHEMA_VERSION,
        "producer_id": producer_id,
        "source_host_id": source_host_id,
        "producer_install_id": producer_install_id,
    }


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


def test_worker_pc_registration_persists_identity_after_self_enroll_success(tmp_path, monkeypatch):
    local_app_data, _program_data = _self_enroll_env(tmp_path, monkeypatch)
    report_path = tmp_path / "registration-identity-persist-report.json"
    captured = {}
    monkeypatch.setattr(registration.requests, "post", _fake_enroll_post(captured))
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
    generated_install_id = f"container-audit-pc-persist-{0xEDE662C694C5:012x}"

    assert exit_code == 0
    assert report["status"] == "SELF_ENROLLMENT_REGISTERED"
    assert report["producer_identity_source"] == "generated"
    assert report["producer_identity_persisted"] is True
    assert Path(report["producer_identity_path"]) == identity_path.resolve()
    assert identity == _identity_payload(
        "container-audit-pc-persist",
        "container-audit-pc-persist",
        generated_install_id,
    )
    assert captured["json"]["producer_id"] == "container-audit-pc-persist"
    assert captured["json"]["manifest"]["pc_identity"]["producer_install_id"] == generated_install_id
    assert captured["json"]["manifest"]["streams"][0]["raw_event_names"] == (
        registration._container_audit_catalog_raw_event_names()
    )


def test_worker_pc_registration_reuses_persisted_identity_instead_of_new_node_id(tmp_path, monkeypatch):
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
    captured = {}
    monkeypatch.setattr(registration.requests, "post", _fake_enroll_post(captured, status="already_enrolled"))
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
    generated_install_id = f"container-audit-pc-reuse-{0xEDE662C694C5:012x}"

    assert exit_code == 0
    assert report["producer_identity_source"] == "identity_file"
    assert captured["json"]["producer_id"] == "container-audit-pc-reuse"
    assert captured["json"]["manifest"]["pc_identity"]["source_host_id"] == "container-audit-pc-reuse"
    assert captured["json"]["manifest"]["pc_identity"]["producer_install_id"] == (
        "container-audit-pc-reuse-aaaaaaaaaaaa"
    )
    assert captured["json"]["manifest"]["pc_identity"]["producer_install_id"] != generated_install_id
    assert persisted["producer_install_id"] == "container-audit-pc-reuse-aaaaaaaaaaaa"
    assert captured["json"]["manifest"]["streams"][0]["raw_event_names"] == (
        registration._container_audit_catalog_raw_event_names()
    )
    assert captured["json"]["manifest"]["streams"][0]["raw_event_names"] != GUI_ORDER_RAW_EVENT_NAMES


def test_worker_pc_registration_pins_explicit_producer_install_id_over_generated(tmp_path, monkeypatch):
    _self_enroll_env(tmp_path, monkeypatch)
    report_path = tmp_path / "registration-identity-pin-report.json"
    captured = {}
    monkeypatch.setattr(registration.requests, "post", _fake_enroll_post(captured, status="already_enrolled"))
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
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--report-path",
            str(report_path),
        ]
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    identity_path = Path(report["producer_identity_path"])
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    generated_install_id = f"container-audit-test1-{0xEDE662C694C5:012x}"

    assert exit_code == 0
    assert report["producer_identity_source"] == "cli"
    assert captured["json"]["producer_id"] == "container-audit-test1"
    assert captured["json"]["manifest"]["pc_identity"]["producer_install_id"] == (
        "container-audit-test1-pin-fixture"
    )
    assert captured["json"]["manifest"]["pc_identity"]["producer_install_id"] != generated_install_id
    assert identity["producer_install_id"] == "container-audit-test1-pin-fixture"
    assert "9231ea1cf5b8" not in identity_path.read_text(encoding="utf-8")


def test_worker_pc_registration_uses_seeded_identity_file_path(tmp_path, monkeypatch):
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
    captured = {}
    monkeypatch.setattr(registration.requests, "post", _fake_enroll_post(captured, status="already_enrolled"))
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
    persist_path = Path(report["producer_identity_path"])
    persisted = json.loads(persist_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert report["producer_identity_source"] == "identity_file"
    assert report["producer_identity_loaded_from"] == str(seed_path.resolve())
    assert captured["json"]["manifest"]["pc_identity"]["producer_install_id"] == (
        "container-audit-seed-host-bbbbbbbbbbbb"
    )
    assert persisted == seed
    assert persist_path != seed_path.resolve()


def test_worker_pc_registration_identity_conflict_fail_closed_without_reuse_evidence(
    tmp_path, monkeypatch
):
    local_app_data, _program_data = _self_enroll_env(tmp_path, monkeypatch)
    report_path = tmp_path / "registration-identity-conflict-report.json"
    captured = {}
    identity_path = local_app_data / "KMTech" / "DirectSync" / "container_audit" / "producer_identity.json"
    monkeypatch.setattr(
        registration.requests,
        "post",
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
    assert report["status"] == "BLOCKED"
    assert report["blocked_reason"] == "self-enroll failed: producer_identity_conflict"
    assert report["raw_secret_written"] is False
    assert writes == []
    assert not identity_path.exists()
    assert captured["json"]["manifest"]["pc_identity"]["producer_install_id"] == (
        f"container-audit-test1-{0xEDE662C694C5:012x}"
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
        registration.requests,
        "post",
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
