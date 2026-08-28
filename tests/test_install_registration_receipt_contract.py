import json
from pathlib import Path
from types import SimpleNamespace

import direct_sync_push
import direct_sync_runtime
from direct_sync_push import ProducerCredentials, RELAY_STATUS_ACKED, manifest_hash, relay_queue_status
from direct_sync_runtime import DirectSyncRuntimeConfig, enqueue_completed_source_file, run_relay_once
from producer_runtime_client import RuntimePreparation
from tools import register_container_audit_worker_pc as registration


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


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _AcceptedUploadSession:
    def post(self, _url, *, data, files, **_kwargs):
        metadata = json.loads(data["metadata"])
        files["file"][1].read()
        request_id = f"request-{metadata['client_batch_id']}"
        return _Response(
            200,
            {
                "request_id": request_id,
                "upload_id": request_id,
                "client_batch_id": metadata["client_batch_id"],
                "server_source_file_id": (
                    f"{metadata['source_host_id']}/{metadata['producer_role']}/"
                    f"{metadata['stream_name']}/{metadata['relative_path']}"
                ),
                "committed": True,
                "status": "accepted",
                "retryable": False,
                "next_retry_after": None,
                "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
            },
        )


def test_install_registration_manifest_authorization_and_first_clean_receipt(tmp_path, monkeypatch):
    program_data = tmp_path / "ProgramData"
    direct_sync_root = program_data / "KMTech" / "DirectSync" / "container_audit"
    manifest_path = direct_sync_root / "producer_manifest.json"
    credential_path = direct_sync_root / "credential.json"
    report_path = direct_sync_root / "status" / "worker_pc_registration.json"
    captured = {}
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
    monkeypatch.setenv("PROGRAMDATA", str(program_data))

    def enroll_post(_url, *, json, **_kwargs):
        captured["manifest"] = json["manifest"]
        return _Response(
            200,
            {
                "contract_version": registration.SELF_ENROLLMENT_CONTRACT_VERSION,
                "status": "enrolled",
                "identity_action": "CREATED",
                "authorization_state": "OPERATION_PENDING",
                "credential_epoch": 1,
                "possession_key": {
                    "contract_version": registration.POSSESSION_KEY_CONTRACT_VERSION,
                    "fingerprint": TEST_POSSESSION_FINGERPRINT,
                },
                "producer_id": "container-audit-test1",
                "key_id": "container-audit-test1-key",
                "secret": "fixture-secret-not-persisted-in-json",
                "active_manifest_hashes": [manifest_hash(json["manifest"])],
                "machine_credential_bundle": {"must_not_replace_existing_profile": True},
            },
        )

    def write_dpapi_secret(data_dir, target_name, _secret):
        path = Path(data_dir) / "secrets" / f"{target_name}.dpapi"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixture-machine-protected-secret")
        return path

    monkeypatch.setattr(registration, "_post_enrollment_request", enroll_post)
    monkeypatch.setattr(
        registration.PersistentPossessionKey,
        "provision_initial",
        classmethod(lambda _cls, *args, **kwargs: _FakePossessionKey()),
    )
    monkeypatch.setattr(registration, "_write_dpapi_secret", write_dpapi_secret)
    monkeypatch.setattr(
        direct_sync_push,
        "prepare_runtime_metadata",
        lambda **kwargs: RuntimePreparation(metadata=dict(kwargs["metadata"])),
    )
    monkeypatch.setattr(direct_sync_push, "client_runtime_lease_mode", lambda _credentials: "observe")
    monkeypatch.setattr(
        direct_sync_runtime,
        "ensure_runtime_authority",
        lambda **kwargs: RuntimePreparation(
            status_code=200,
            receipt={
                "status": "ACTIVE",
                "server_grant_accepted": True,
                "producer_install_id": kwargs["producer_install_id"],
                "lease_id": "lease-install-registration-test",
                "runtime_instance_id": "runtime-install-registration-test",
                "expires_at": "2099-01-01T00:00:00Z",
                "request_sent": False,
            },
        ),
    )

    registration_exit = registration.main(
        [
            "--app-root",
            str(tmp_path / "release"),
            "--hostname",
            "TEST1",
            "--source-host-id",
            "container-audit-test1",
            "--producer-install-id",
            "container-audit-test1-install",
            "--producer-id",
            "container-audit-test1",
            "--key-id",
            "container-audit-test1-key",
            "--secret-ref",
            "dpapi:container-audit-test1",
            "--endpoint-url",
            "https://worker.example.invalid/api/producer-ingest/v1/source-file",
            "--self-enroll",
            "--confirm-new-server-identity",
            "--preserve-existing-machine-profile",
            "--manifest-path",
            str(manifest_path),
            "--credential-path",
            str(credential_path),
            "--report-path",
            str(report_path),
        ]
    )

    registration_report = json.loads(report_path.read_text(encoding="utf-8"))
    persisted_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert registration_exit == 0
    assert registration_report["manifest_hash_verified"] is True
    assert registration_report["persisted_manifest_hash_verified"] is True
    assert registration_report["manifest_hash"] == manifest_hash(persisted_manifest)
    assert registration_report["machine_profile_mode"] == "preserved_existing"
    assert registration_report["machine_profiles"] == {}
    assert "PHS_RECONCILIATION_ACTION_RESOLVED" in persisted_manifest["streams"][0]["raw_event_names"]
    assert "PHS_RECONCILIATION_LABEL_EXCHANGED" in persisted_manifest["streams"][0]["raw_event_names"]
    assert "TRAY_RESTORE" in persisted_manifest["streams"][0]["raw_event_names"]

    source_file = tmp_path / "이적작업이벤트로그_install_contract.csv"
    source_file.write_text(
        "timestamp,worker_name,event,details\n"
        '2026-08-09T00:00:00Z,worker,WORK_START,"{}"\n',
        encoding="utf-8",
    )
    credentials = ProducerCredentials(
        producer_id="container-audit-test1",
        key_id="container-audit-test1-key",
        secret="fixture-secret-not-persisted-in-json",
        endpoint_url="https://worker.example.invalid/api/producer-ingest/v1/source-file",
    )
    config = DirectSyncRuntimeConfig(
        db_path=direct_sync_root / "queue" / "direct_sync_relay.sqlite3",
        spool_dir=direct_sync_root / "spool",
        producer_manifest_path=manifest_path,
        credential_path=credential_path,
        upload_status_dir=direct_sync_root / "upload_status",
        runtime_status_path=direct_sync_root / "status" / "direct_sync_relay_status.json",
        log_path=direct_sync_root / "logs" / "direct_sync_relay.jsonl",
    )
    enqueued = enqueue_completed_source_file(
        config,
        source_file_path=source_file,
        relative_path="events/install-contract.csv",
        credentials=credentials,
    )
    assert enqueued["status"] == "enqueued", enqueued
    runtime = run_relay_once(config, session=_AcceptedUploadSession(), credentials=credentials)
    assert runtime["status"] == "acked", runtime
    assert runtime["manifest_hash"] == registration_report["manifest_hash"]
    upload_status = json.loads(Path(runtime["last_result"]["upload_status_path"]).read_text(encoding="utf-8"))
    counts = relay_queue_status(config.db_path)["counts"]

    assert upload_status["success"] is True
    assert upload_status["committed"] is True
    assert upload_status["receipt"]["status"] == "accepted"
    assert upload_status["receipt"]["totals"] == {
        "inserted": 1,
        "replayed": 0,
        "quarantined": 0,
        "errors": 0,
    }
    assert counts[RELAY_STATUS_ACKED] == 1
    assert counts.get("failed_permanent", 0) == 0
    assert counts.get("operator_review", 0) == 0
