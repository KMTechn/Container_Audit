import json
from pathlib import Path
import direct_sync_push
import direct_sync_runtime
from direct_sync_push import RELAY_STATUS_ACKED, relay_queue_status
from direct_sync_runtime import (
    DirectSyncRuntimeConfig,
    enqueue_completed_source_file,
    run_relay_once,
)
from producer_runtime_client import RuntimePreparation
import user_relay


def test_hkcu_autostart_uses_hardened_main_and_exact_readback(tmp_path):
    app_root = tmp_path / "hardened"
    app_root.mkdir()
    executable = app_root / "Container_Audit.exe"
    executable.write_bytes(b"exe")
    stored = {}

    report = user_relay.install_user_relay_autostart(
        app_root,
        setter=lambda value: stored.update(value=value),
        getter=lambda: stored.get("value", ""),
    )

    assert report["status"] == "PASS"
    assert report["principal"] == "current_user"
    assert report["registry_hive"] == "HKEY_CURRENT_USER"
    assert str(executable.resolve()) in report["command"]
    assert "--container-audit-user-relay" in report["command"]
    assert "schtasks" not in report["command"].lower()


def test_persistent_loop_maps_missing_cycle_value_to_unknown(tmp_path):
    result = user_relay.run_persistent_relay_loop(
        lambda: None,
        status_path=tmp_path / "status.json",
        interval_seconds=0,
        max_cycles=1,
    )

    assert result["cycle_count"] == 1
    assert result["last_cycle"]["status"] == "UNKNOWN"
    persisted = json.loads((tmp_path / "status.json").read_text(encoding="utf-8"))
    assert persisted["last_cycle"]["status"] == "UNKNOWN"
    assert persisted["persistent_retry"] is True


class _Response:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.headers = {}

    def json(self):
        return self._payload


class _OfflineSession:
    def __init__(self):
        self.calls = []

    def post(self, url, *, data, files, headers, timeout, allow_redirects):
        self.calls.append(url)
        return _Response(
            503,
            {
                "committed": False,
                "retryable": True,
                "error": {"code": "network_offline", "message": "offline"},
            },
        )


class _OnlineSession:
    def __init__(self):
        self.calls = []

    def post(self, url, *, data, files, headers, timeout, allow_redirects):
        metadata = json.loads(data["metadata"])
        self.calls.append(metadata)
        return _Response(
            200,
            {
                "request_id": f"request-{metadata['client_batch_id']}",
                "upload_id": f"request-{metadata['client_batch_id']}",
                "client_batch_id": metadata["client_batch_id"],
                "server_source_file_id": (
                    f"{metadata['source_host_id']}/{metadata['producer_role']}/"
                    f"{metadata['stream_name']}/{metadata['relative_path']}"
                ),
                "committed": True,
                "status": "accepted",
                "retryable": False,
                "next_retry_after": None,
                "totals": {
                    "inserted": 1,
                    "replayed": 0,
                    "quarantined": 0,
                    "errors": 0,
                },
            },
        )


def _runtime_config(root: Path) -> DirectSyncRuntimeConfig:
    manifest = {
        "schema_version": "producer-onboarding-manifest-v1",
        "pc_identity": {
            "pc_id": "CONTAINER-PC01",
            "source_host_id": "container-user-relay-host",
            "producer_install_id": "container-user-relay-install",
        },
        "apps": ["ContainerAudit"],
        "streams": [
            {
                "producer_role": "container_audit",
                "stream_name": "container_audit_events",
                "source_system": "container_audit",
                "source_transport": "legacy_transfer_csv",
            }
        ],
    }
    manifest_path = root / "producer_manifest.json"
    credential_path = root / "credential.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    credential_path.write_text(
        json.dumps(
            {
                "producer_id": "container-user-relay-host",
                "key_id": "test-key",
                "secret": "test-secret",
                "endpoint_url": (
                    "https://worker.example.invalid/api/producer-ingest/v1/source-file"
                ),
            }
        ),
        encoding="utf-8",
    )
    return DirectSyncRuntimeConfig(
        db_path=root / "queue" / "relay.sqlite3",
        spool_dir=root / "spool",
        producer_manifest_path=manifest_path,
        credential_path=credential_path,
        upload_status_dir=root / "upload_status",
        runtime_status_path=root / "status" / "direct_sync_relay_status.json",
        log_path=root / "logs" / "relay.jsonl",
        retry_base_seconds=1,
        timeout_seconds=5,
        operator_pause_path=root / "control" / "pause.json",
    )


def test_persistent_user_relay_flushes_durable_queue_offline_to_online_once(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("APP_ENV", raising=False)
    monkeypatch.setattr(
        direct_sync_push,
        "prepare_runtime_metadata",
        lambda **kwargs: RuntimePreparation(metadata=dict(kwargs["metadata"])),
    )
    monkeypatch.setattr(
        direct_sync_push,
        "client_runtime_lease_mode",
        lambda _credentials: "observe",
    )
    monkeypatch.setattr(
        direct_sync_runtime,
        "ensure_runtime_authority",
        lambda **kwargs: RuntimePreparation(
            status_code=200,
            receipt={
                "status": "ACTIVE",
                "server_grant_accepted": True,
                "producer_install_id": kwargs["producer_install_id"],
                "lease_id": "lease-user-relay",
                "runtime_instance_id": "runtime-user-relay",
                "expires_at": "3999-01-01T00:00:00Z",
                "request_sent": False,
            },
        ),
    )
    config = _runtime_config(tmp_path / "state")
    source = tmp_path / "events" / "container.csv"
    source.parent.mkdir()
    source.write_text(
        "timestamp,worker_name,event,details\n"
        '2026-08-28T00:00:00,worker,SCAN_OK,"{ ""product_barcode"": ""BC-1"" }"\n',
        encoding="utf-8",
    )
    enqueued = enqueue_completed_source_file(config, source_file_path=source)
    assert enqueued["status"] == "enqueued"
    offline = _OfflineSession()
    online = _OnlineSession()
    cycle_number = 0

    def cycle():
        nonlocal cycle_number
        cycle_number += 1
        if cycle_number == 1:
            return run_relay_once(
                config,
                session=offline,
                now="2099-01-01T00:00:00Z",
            )
        return run_relay_once(
            config,
            session=online,
            now="2999-01-01T00:00:00Z",
        )

    result = user_relay.run_persistent_relay_loop(
        cycle,
        status_path=tmp_path / "user-relay-status.json",
        interval_seconds=0,
        max_cycles=2,
    )

    assert result["cycle_count"] == 2
    assert result["last_cycle"]["status"] == "acked"
    assert len(offline.calls) == 1
    assert len(online.calls) == 1
    assert relay_queue_status(config.db_path)["counts"][RELAY_STATUS_ACKED] == 1
