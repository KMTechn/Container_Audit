import hashlib
import json
from pathlib import Path

from storage_policy import DATA_ROOT_ENV
from tools import register_container_audit_worker_pc as registration


def test_worker_pc_registration_frozen_default_app_root_uses_executable_directory(tmp_path, monkeypatch):
    frozen_exe = tmp_path / "release" / "Container_Audit_Worker_PC_Register.exe"
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
    expected_direct_sync_root = (program_data / "KMTech" / "DirectSync" / "container_audit").resolve()

    assert report["status"] == "LOCAL_REGISTRATION_WRITTEN_PENDING_SECRET"
    assert report["raw_secret_written"] is False
    assert report["secret_bootstrap_verified"] is False
    assert manifest["schema_version"] == "producer-onboarding-manifest-v1"
    assert manifest["pc_identity"]["source_host_id"] == "container-audit-pc-01"
    raw_event_names = manifest["streams"][0]["raw_event_names"]
    assert raw_event_names == [
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
    assert manifest["sync"]["sync_transport"] == "http_push"
    assert manifest["sync"]["sync_dir"] == (expected_root / "events").as_posix()
    assert manifest["paths"]["data_dir"] == expected_direct_sync_root.as_posix()
    assert report["local_storage"]["events_dir"] == str(expected_root / "events")
    assert report["local_storage"]["direct_sync_root"] == str(expected_direct_sync_root)
    assert report["local_storage"]["syncthing_dependency"] is False
    assert credential["key_id"] == "server-issued-key-01"
    assert credential["secret_ref"] == "wincred:KMTech.DirectSync.ContainerAudit.PC-01"
    assert "secret" not in credential


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

    def fake_post(url, *, json, headers, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
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

    def fake_post(url, *, json, headers, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
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
    expected_direct_sync_root = program_data / "KMTech" / "DirectSync" / "container_audit"
    assert credential["secret_data_dir"] == str(expected_direct_sync_root)
    assert "secret" not in credential
    assert captured["dpapi_data_dir"] == str(expected_direct_sync_root)
    assert captured["dpapi_target"] == "KMTech.DirectSync.ContainerAudit.pc-ip"
    assert captured["dpapi_secret"] == "server-issued-secret-pc-ip"


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


def test_worker_pc_registration_blocks_syncthing_data_root(tmp_path, monkeypatch):
    report_path = tmp_path / "registration-blocked.json"
    monkeypatch.setenv(DATA_ROOT_ENV, r"C:\Sync")

    exit_code = registration.main(["--report-path", str(report_path)])

    assert exit_code == 2
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "BLOCKED"
    assert report["raw_secret_written"] is False
    assert "legacy Syncthing folder" in report["blocked_reason"]
