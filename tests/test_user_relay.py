import json
import os
from pathlib import Path
import socket
import ssl
import threading

import pytest
import requests

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
import writer_session_fence as fence


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


def test_portable_autostart_reenters_isolated_main_before_source_fallback(tmp_path):
    app_root = tmp_path / "portable" / "app"
    app_root.mkdir(parents=True)
    portable_main = app_root / "main.py"
    portable_main.write_text("# portable entry\n", encoding="utf-8")
    (app_root / "Container_Audit.py").write_text("# source app\n", encoding="utf-8")

    command = user_relay.build_user_relay_command(app_root)

    assert command == [
        user_relay.sys.executable,
        "-I",
        "-B",
        str(portable_main.resolve()),
        "--container-audit-user-relay",
    ]


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


def test_persistent_loop_outlives_a_status_write_behind_a_held_writer_gate(tmp_path):
    # GUI start keeps the per-user writer admission while its offline catalog
    # warning is open (09-29 lab: 10:46:33-10:47:21), and during an outage a
    # lookup or relay child keeps it across an HTTP timeout. The relay's status
    # write gives up at the 5 s gate: that may cost one status line, never the
    # relay.
    held, release = threading.Event(), threading.Event()

    def startup_dialog():
        with fence.writer_admission("gui_startup"):
            held.set()
            release.wait(30)

    holder = threading.Thread(target=startup_dialog)
    status_path = tmp_path / "status.json"
    seen = []

    def cycle():
        seen.append(len(seen) + 1)
        if len(seen) == 1:
            holder.start()
            assert held.wait(10)
            return {"status": "UNKNOWN", "reason": "relay process did not return an exit code"}
        if len(seen) == 2:
            release.set()
            holder.join(10)
        else:
            seen.append(json.loads(status_path.read_text(encoding="utf-8")))
        return {"status": "idle"}

    try:
        result = user_relay.run_persistent_relay_loop(
            cycle, status_path=status_path, interval_seconds=0, max_cycles=3
        )
    finally:
        release.set()
        if holder.ident is not None:
            holder.join(10)

    assert result["cycle_count"] == 3
    after_the_gate = seen[-1]
    assert after_the_gate["status"] == "RUNNING"
    assert after_the_gate["cycle_count"] == 2
    assert after_the_gate["previous_status_write_error"] == {
        "cycle_count": 1,
        "error_type": "WriterFencedError",
        "error_code": "WRITER_GATE_TIMEOUT",
    }
    persisted = json.loads(status_path.read_text(encoding="utf-8"))
    assert persisted["status"] == "COMPLETED"
    assert persisted["cycle_count"] == 3


@pytest.mark.skipif(os.name != "nt", reason="Windows named-mutex abandonment")
def test_persistent_loop_outlives_a_writer_that_ended_holding_admission(tmp_path):
    # subprocess.run kills a relay child that overruns its budget while it
    # holds the admission; the next waiter finds the mutex abandoned.
    def abandoning_writer():
        name = fence.writer_admission_mutex_name(fence.canonical_control_root())
        assert fence._acquire_named_mutex(name, 5) is not None

    status_path = tmp_path / "status.json"
    seen = []

    def cycle():
        seen.append(len(seen) + 1)
        if len(seen) == 1:
            writer = threading.Thread(target=abandoning_writer)
            writer.start()
            writer.join(10)
            return {"status": "UNKNOWN", "reason": "relay process did not return an exit code"}
        if len(seen) == 3:
            seen.append(json.loads(status_path.read_text(encoding="utf-8")))
        return {"status": "idle"}

    result = user_relay.run_persistent_relay_loop(
        cycle, status_path=status_path, interval_seconds=0, max_cycles=3
    )

    assert result["cycle_count"] == 3
    assert seen[-1]["previous_status_write_error"] == {
        "cycle_count": 1,
        "error_type": "WriterFencedError",
        "error_code": "WRITER_GATE_ABANDONED",
    }
    assert json.loads(status_path.read_text(encoding="utf-8"))["status"] == "COMPLETED"


@pytest.mark.parametrize("invalid_binding", [False, True], ids=["active", "invalid-binding"])
def test_persistent_loop_stops_when_a_writer_fence_appears(tmp_path, invalid_binding):
    from tests.test_writer_session_fence import _active_payload, _write_active

    attempts = []
    payload = _active_payload()
    if invalid_binding:
        payload["writer_inventory_sha256"] = "f" * 64

    def cycle():
        attempts.append(1)
        if len(attempts) == 1:
            _write_active(fence.canonical_control_root(), payload)
        return {"status": "idle"}

    status_path = tmp_path / "status.json"
    with pytest.raises(fence.WriterFenceError) as error:
        user_relay.run_persistent_relay_loop(
            cycle, status_path=status_path, interval_seconds=0, max_cycles=3
        )

    assert error.value.code == ("FENCE_BINDING_INVALID" if invalid_binding else "ACTIVE_WRITER_FENCE")
    assert attempts == [1], "fence rejection must end the resident before another cycle"
    assert not status_path.exists()


def _app_start(tmp_path, monkeypatch, *, registered="relay command"):
    import direct_sync_auto_bootstrap as bootstrap

    launches = []
    monkeypatch.setattr(user_relay, "_registry_get", lambda: registered)
    monkeypatch.setattr(
        user_relay,
        "start_user_relay_process",
        lambda app_root, *, environ=None: launches.append(Path(app_root))
        or {"status": "START_REQUESTED", "process_id": 4242},
    )
    monkeypatch.setattr(
        bootstrap,
        "run_session_direct_sync_once",
        lambda **kwargs: {"status": "PASS", "returncode": 0, "reason": kwargs["reason"]},
    )
    direct_sync_root = tmp_path / "direct-sync"

    def start():
        return bootstrap.run_direct_sync_auto_bootstrap(
            app_root=tmp_path / "app",
            direct_sync_root=direct_sync_root,
            scan_source_dir=tmp_path / "events",
        )

    return start, launches, direct_sync_root


def test_app_start_requests_the_registered_relay_when_none_holds_its_lease(
    tmp_path, monkeypatch
):
    start, launches, direct_sync_root = _app_start(tmp_path, monkeypatch)

    report = start()

    assert launches == [tmp_path / "app"]
    assert report["resident_relay"] == {"status": "START_REQUESTED", "process_id": 4242}
    persisted = json.loads(
        (direct_sync_root / "status" / "container_audit_direct_sync_auto_bootstrap.json")
        .read_text(encoding="utf-8")
    )
    assert persisted == report
    lease = user_relay.acquire_runtime_instance(direct_sync_root / "user-relay-instance")
    assert lease is not None, "the probe must release the relay lease before the launch"
    lease.release()


def test_app_start_leaves_a_live_relay_alone(tmp_path, monkeypatch):
    start, launches, direct_sync_root = _app_start(tmp_path, monkeypatch)
    live = user_relay.acquire_runtime_instance(direct_sync_root.resolve() / "user-relay-instance")
    try:
        report = start()
    finally:
        live.release()

    assert launches == []
    assert report["resident_relay"] == {"status": "RUNNING"}


def test_app_start_can_request_twice_before_a_resident_holds_the_instance_lease(
    tmp_path, monkeypatch
):
    # START_REQUESTED is only a launch request. The child owns the single-loop
    # guarantee when it acquires its lease; a pending request is not a live relay.
    start, launches, _ = _app_start(tmp_path, monkeypatch)

    assert start()["resident_relay"]["status"] == "START_REQUESTED"
    assert start()["resident_relay"]["status"] == "START_REQUESTED"
    assert launches == [tmp_path / "app", tmp_path / "app"]


@pytest.mark.parametrize("state", ["unregistered", "stop_requested"])
def test_app_start_never_starts_a_relay_that_is_not_meant_to_run(
    tmp_path, monkeypatch, state
):
    start, launches, direct_sync_root = _app_start(
        tmp_path, monkeypatch, registered="" if state == "unregistered" else "relay command"
    )
    if state == "stop_requested":
        stop = user_relay.user_relay_stop_path(direct_sync_root)
        stop.parent.mkdir(parents=True)
        stop.write_text("{}", encoding="utf-8")

    report = start()

    assert launches == []
    assert report["resident_relay"] == {
        "status": "NOT_REGISTERED" if state == "unregistered" else "STOP_REQUESTED"
    }


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
                "projection_disposition": "COMPLETE",
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


class _FailingSession:
    def __init__(self, failure):
        self.failure = failure
        self.calls = []

    def post(self, url, *, data, files, headers, timeout, allow_redirects):
        self.calls.append(json.loads(data["metadata"]))
        raise self.failure


@pytest.mark.parametrize(
    "failure",
    [
        ConnectionRefusedError(10061, "connection refused"),
        ConnectionResetError(10054, "connection reset by peer"),
        socket.gaierror(11001, "host not found"),
        OSError(0, "network is unreachable", None, 10051),
        OSError(0, "no route to host", None, 10065),
        ssl.SSLError("EOF occurred in violation of protocol"),
        requests.exceptions.ConnectionError("network adapter disabled"),
        requests.exceptions.ReadTimeout("read timed out"),
    ],
    ids=[
        "refused",
        "reset",
        "dns",
        "net-unreachable-10051",
        "host-unreachable-10065",
        "ssl",
        "adapter-off",
        "read-timeout",
    ],
)
def test_network_failure_leaves_the_same_row_to_the_next_relay_cycle(
    tmp_path, monkeypatch, failure
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
            receipt={"status": "ACTIVE", "server_grant_accepted": True},
        ),
    )
    config = _runtime_config(tmp_path / "state")
    source = tmp_path / "events" / "container.csv"
    source.parent.mkdir()
    source.write_text(
        "timestamp,worker_name,event,details\n"
        '2026-09-29T10:47:00,worker,SCAN_OK,"{ ""product_barcode"": ""BC-1"" }"\n',
        encoding="utf-8",
    )
    assert enqueue_completed_source_file(config, source_file_path=source)["status"] == "enqueued"
    offline = _FailingSession(failure)
    online = _OnlineSession()
    cycles = []

    def cycle():
        cycles.append(len(cycles) + 1)
        if len(cycles) == 1:
            return run_relay_once(config, session=offline, now="2099-01-01T00:00:00Z")
        return run_relay_once(config, session=online, now="2999-01-01T00:00:00Z")

    result = user_relay.run_persistent_relay_loop(
        cycle,
        status_path=tmp_path / "user-relay-status.json",
        interval_seconds=0,
        max_cycles=2,
    )

    assert result["cycle_count"] == 2
    assert result["last_cycle"]["status"] == "acked"
    assert len(offline.calls) == len(online.calls) == 1
    assert offline.calls[0]["idempotency_key"] == online.calls[0]["idempotency_key"]
    assert relay_queue_status(config.db_path)["counts"][RELAY_STATUS_ACKED] == 1
