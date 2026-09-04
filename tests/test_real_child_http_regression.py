"""Real-child / real-HTTP regression for Container_Audit data-plane mock gaps.

These tests do not mock subprocess or requests.Session. They spawn the
production relay child and POST over loopback HTTPS. If those paths become
no-ops, this file must turn red. Product code is not changed here: a failure
is a finding.
"""

from __future__ import annotations

from contextlib import contextmanager
from email.parser import BytesParser
from email.policy import default as email_policy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import urlsplit

import pytest
import requests

import direct_sync_auto_bootstrap as bootstrap
import isolated_qualification
import producer_runtime_client as runtime_client
import transfer_seal
import user_relay
import writer_session_fence as fence
from direct_sync_push import (
    DEFAULT_ENDPOINT_PATH,
    ProducerCredentials,
    build_source_file_plan,
    upload_source_file,
)
from tools import isolated_qualification_authority as authority


ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = Path(__file__).resolve().parent
WRITER_ROOT_ENV = "KMTECH_TEST_CA_WRITER_ROOT"
WRITER_MUTEX_ENV = "KMTECH_TEST_CA_WRITER_MUTEX"
SITECUSTOMIZE_MARKER_ENV = "KMTECH_TEST_CA_SITECUSTOMIZE_MARKER"
CSV_NAME = "이적작업이벤트로그_loopback_20260904.csv"
CSV_BODY = (
    "timestamp,worker_name,event,details\n"
    "2026-09-04T00:00:00,loopback-worker,SCAN_OK,"
    '"{{ ""product_barcode"": ""BC-LOOPBACK-1"" }}"\n'
)


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    if not 1024 <= port <= 65535:
        raise RuntimeError(f"loopback test port {port} is outside the isolated qualification range")
    return port


def _install_parent_writer_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, str]:
    control_root = tmp_path / "writer-control"
    control_root.mkdir()
    mutex_name = (
        r"Local\KMTech.ContainerAudit.WriterAdmission.Test."
        + hashlib.sha256(str(control_root).encode("utf-8")).hexdigest()[:16]
    )
    local_app_data = tmp_path / "localappdata"
    local_app_data.mkdir()
    monkeypatch.setenv(WRITER_ROOT_ENV, str(control_root))
    monkeypatch.setenv(WRITER_MUTEX_ENV, mutex_name)
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(tmp_path / "data-root"))
    monkeypatch.setattr(fence, "canonical_control_root", lambda _environ=None: control_root)
    monkeypatch.setattr(
        fence,
        "writer_admission_mutex_name",
        lambda _control_root, *, environ=None: mutex_name,
    )
    acquire_named_mutex = fence._acquire_named_mutex

    def guarded_acquire_named_mutex(name: str, timeout_seconds: float):
        if name == fence.WRITER_MUTEX_NAME:
            raise AssertionError(
                "test parent attempted to acquire the machine-global canonical "
                f"writer-admission mutex: {name}"
            )
        return acquire_named_mutex(name, timeout_seconds)

    monkeypatch.setattr(fence, "_acquire_named_mutex", guarded_acquire_named_mutex)
    return control_root, mutex_name


def _child_pythonpath() -> str:
    parts = [str(TESTS_DIR), str(ROOT)]
    existing = os.environ.get("PYTHONPATH", "").strip()
    if existing:
        parts.append(existing)
    return os.pathsep.join(parts)


def _write_manifest(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "producer-onboarding-manifest-v1",
                "pc_identity": {
                    "pc_id": "CONTAINER-LOOPBACK-PC",
                    "source_host_id": "container-loopback-host",
                    "producer_install_id": "install-container-loopback",
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
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def _write_csv(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = CSV_BODY.encode("utf-8")
    path.write_bytes(payload)
    return payload


def _json_bytes(payload: MappingLike) -> bytes:
    return (json.dumps(dict(payload), ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


MappingLike = dict[str, Any]


class _LoopbackState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.calls: list[dict[str, Any]] = []

    def record(self, **call: Any) -> None:
        with self.lock:
            self.calls.append(call)

    def paths(self) -> list[str]:
        with self.lock:
            return [str(call["path"]) for call in self.calls]

    def bodies_for(self, path: str) -> list[bytes]:
        with self.lock:
            return [bytes(call["body"]) for call in self.calls if call["path"] == path]


def _multipart_parts(headers: Any, body: bytes) -> tuple[dict[str, Any], bytes]:
    content_type = str(headers.get("Content-Type") or "")
    message = BytesParser(policy=email_policy).parsebytes(
        b"Content-Type: "
        + content_type.encode("ascii")
        + b"\r\nMIME-Version: 1.0\r\n\r\n"
        + body
    )
    metadata = None
    file_bytes = None
    for part in message.iter_parts():
        disposition = part.get("Content-Disposition", "")
        name = part.get_param("name", header="Content-Disposition")
        if "form-data" not in disposition:
            continue
        payload = part.get_payload(decode=True) or b""
        if name == "metadata":
            metadata = json.loads(payload.decode("utf-8"))
        elif name == "file":
            file_bytes = payload
    if not isinstance(metadata, dict) or file_bytes is None:
        raise ValueError("multipart request fields are missing")
    return metadata, file_bytes


def _make_handler(state: _LoopbackState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            return

        def _send(self, status: int, payload: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        def _send_json(self, status: int, payload: MappingLike) -> None:
            self._send(status, _json_bytes(payload), "application/json; charset=utf-8")

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length") or "0")
            if length < 0:
                raise ValueError("content length is invalid")
            return self.rfile.read(length) if length else b""

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            state.record(method="GET", path=parsed.path, body=b"", headers=dict(self.headers))
            if parsed.path == "/health/qualification":
                self._send_json(200, {"ok": True, "status": "READY"})
                return
            if parsed.path == "/inbound/api/item-catalog.csv":
                catalog = (
                    "Item Code,Item Name,Spec,Tray Image\r\n"
                    "AAA2270730100,Loopback L07,KMC_LHD,assets/KMC_LHD.png\r\n"
                ).encode("utf-8")
                self._send(200, catalog, "text/csv; charset=utf-8")
                return
            self._send_json(404, {"ok": False, "error": {"code": "loopback_route_not_found"}})

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlsplit(self.path)
            body = self._read_body()
            state.record(
                method="POST",
                path=parsed.path,
                body=body,
                headers=dict(self.headers),
            )
            try:
                if parsed.path == runtime_client.ENDPOINT_PATH:
                    request = json.loads(body.decode("utf-8"))
                    sequence = int(request.get("runtime_request_sequence") or 0) + 1
                    self._send_json(
                        200,
                        {
                            "ok": True,
                            "status": "ACTIVE",
                            "contract_version": runtime_client.CONTRACT_VERSION,
                            "operation": (
                                "renewed" if "runtime_request_token" in request else "issued"
                            ),
                            "lease_id": "loopback-runtime-lease",
                            "producer_install_id": "install-container-loopback",
                            "runtime_instance_id": request["runtime_instance_id"],
                            "public_jwk_thumbprint": runtime_client._jwk_thumbprint(
                                request["public_jwk"]
                            ),
                            "issue_idempotency_key": request["issue_idempotency_key"],
                            "fence": int(request.get("runtime_fence") or 1),
                            "issued_at": "2026-09-04T00:00:00Z",
                            "expires_at": "2099-09-04T00:00:00Z",
                            "next_request_token": secrets.token_urlsafe(32)[:43],
                            "next_request_sequence": sequence,
                        },
                    )
                    return
                if parsed.path == DEFAULT_ENDPOINT_PATH:
                    metadata, file_bytes = _multipart_parts(self.headers, body)
                    request_id = f"loopback-{metadata['client_batch_id']}"
                    row_count = int(metadata.get("row_count") or 0)
                    receipt: MappingLike = {
                        "request_id": request_id,
                        "upload_id": request_id,
                        "producer_install_id": metadata["producer_install_id"],
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
                            "inserted": row_count,
                            "replayed": 0,
                            "quarantined": 0,
                            "errors": 0,
                        },
                    }
                    if "runtime_request_token" in metadata:
                        receipt["runtime_lease"] = {
                            "contract_version": runtime_client.CONTRACT_VERSION,
                            "validation_status": "consumed",
                            "lease_id": "loopback-runtime-lease",
                            "fence": int(metadata["runtime_fence"]),
                            "next_request_token": secrets.token_urlsafe(32)[:43],
                            "next_request_sequence": int(metadata["runtime_request_sequence"])
                            + 1,
                            "expires_at": "2099-09-04T00:00:00Z",
                        }
                    receipt["_loopback_file_sha256"] = hashlib.sha256(file_bytes).hexdigest()
                    self._send_json(200, receipt)
                    return
                if parsed.path == "/logistics/api/v1/transfers/seal":
                    request = json.loads(body.decode("utf-8")) if body else {}
                    self._send_json(
                        200,
                        {
                            "ok": True,
                            "data": {
                                "receipt_id": "loopback-seal-1",
                                "status": "COMMITTED",
                                "authority_scope_id": request.get("authority_scope_id", ""),
                                "idempotency_key": request.get("idempotency_key", ""),
                            },
                        },
                    )
                    return
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                self._send_json(
                    400,
                    {
                        "ok": False,
                        "committed": False,
                        "retryable": False,
                        "error": {"code": "loopback_request_invalid"},
                    },
                )
                return
            self._send_json(404, {"ok": False, "error": {"code": "loopback_route_not_found"}})

    return Handler


@contextmanager
def _loopback_https(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _install_parent_writer_isolation(tmp_path, monkeypatch)
    monkeypatch.setenv(isolated_qualification.SOURCE_TEST_MODE_ENV, "1")
    monkeypatch.setenv("COMPUTERNAME", "CA-LOOPBACK-TEST-HOST")
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "programdata"))
    monkeypatch.setenv("PYTHONPATH", _child_pythonpath())
    marker_path = tmp_path / "sitecustomize.loaded"
    monkeypatch.setenv(SITECUSTOMIZE_MARKER_ENV, str(marker_path))
    port = _free_loopback_port()
    operator_root = tmp_path / "operator-local-app-data"
    operator_root.mkdir()
    state_root = isolated_qualification.default_state_root()
    authority.initialize_authority(
        state_root=state_root,
        operator_user_sid="S-1-5-21-100-200-300-504",
        operator_local_app_data_root=str(operator_root),
        port=port,
        report_path=tmp_path / "qualification-initialize.json",
    )
    context = isolated_qualification.load_isolated_qualification_context(
        state_root / isolated_qualification.CONTEXT_FILENAME
    )
    private = json.loads(
        (state_root / authority.PRIVATE_STATE_FILENAME).read_text(encoding="utf-8")
    )
    recorded = _LoopbackState()
    server = ThreadingHTTPServer(
        ("127.0.0.1", port),
        _make_handler(recorded),
        bind_and_activate=False,
    )
    server.allow_reuse_address = False
    server.server_bind()
    server.server_activate()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(
        certfile=str(state_root / authority.SERVER_CERT_FILENAME),
        keyfile=str(state_root / authority.SERVER_KEY_FILENAME),
    )
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        last_error = None
        while time.monotonic() < deadline:
            try:
                response = requests.get(
                    f"{context.server_base_url}/health/qualification",
                    timeout=1,
                    allow_redirects=False,
                    verify=context.ca_bundle_path,
                )
                if response.status_code == 200:
                    break
            except requests.RequestException as exc:
                last_error = exc
                time.sleep(0.05)
        else:
            raise RuntimeError(f"loopback HTTPS stub did not become ready: {last_error}")
        yield {
            "context": context,
            "private": private,
            "recorded": recorded,
            "marker_path": marker_path,
            "state_root": state_root,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _credentials(bundle: dict[str, Any]) -> ProducerCredentials:
    context = bundle["context"]
    private = bundle["private"]
    return ProducerCredentials(
        producer_id="container-loopback-host",
        key_id=str(private["producer_key_id"]),
        secret=str(private["producer_secret"]),
        endpoint_url=context.endpoint_url,
        runtime_lease_mode="observe",
        isolated_qualification_context_path=str(
            Path(context.state_root) / isolated_qualification.CONTEXT_FILENAME
        ),
        tls_ca_bundle_path=context.ca_bundle_path,
    )


def _write_child_runtime(direct_sync_root: Path, bundle: dict[str, Any]) -> None:
    direct_sync_root.mkdir(parents=True, exist_ok=True)
    _write_manifest(direct_sync_root / "producer_manifest.json")
    context = bundle["context"]
    private = bundle["private"]
    (direct_sync_root / "credential.json").write_text(
        json.dumps(
            {
                "producer_id": "container-loopback-host",
                "key_id": private["producer_key_id"],
                "secret": private["producer_secret"],
                "endpoint_url": context.endpoint_url,
                "runtime_lease_mode": "observe",
                "isolated_qualification_context_path": str(
                    Path(context.state_root) / isolated_qualification.CONTEXT_FILENAME
                ),
                "tls_ca_bundle_path": context.ca_bundle_path,
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def test_real_https_ingest_posts_source_file_to_loopback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """M1: producer ingest HTTP. FakeSession would keep this green if POST were a no-op."""

    with _loopback_https(tmp_path, monkeypatch) as bundle:
        csv_path = tmp_path / "events" / CSV_NAME
        csv_bytes = _write_csv(csv_path)
        manifest_path = tmp_path / "producer_manifest.json"
        _write_manifest(manifest_path)
        credentials = _credentials(bundle)
        plan = build_source_file_plan(
            source_file_path=csv_path,
            producer_manifest_path=manifest_path,
            credentials=credentials,
        )
        result = upload_source_file(
            plan,
            credentials,
            session=None,
            status_dir=tmp_path / "upload-status",
        )

        ingest_bodies = bundle["recorded"].bodies_for(DEFAULT_ENDPOINT_PATH)
        assert result.success is True, (result.error_code, result.error_message)
        assert result.committed is True
        assert result.status_code == 200
        assert ingest_bodies, "producer ingest HTTP never reached the loopback stub"
        assert csv_bytes in ingest_bodies[0]


def test_real_child_relay_drains_csv_over_loopback_https(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M2/M4: real relay child + real drain HTTP, without the parent holding admission."""

    with _loopback_https(tmp_path, monkeypatch) as bundle:
        events = tmp_path / "events"
        csv_bytes = _write_csv(events / CSV_NAME)
        direct_sync_root = tmp_path / "direct-sync"
        _write_child_runtime(direct_sync_root, bundle)
        command = bootstrap.build_session_direct_sync_command(
            app_root=ROOT,
            direct_sync_root=direct_sync_root,
            scan_source_dir=events,
        )
        assert command[0] == sys.executable
        assert command[1] == str((ROOT / "tools" / "direct_sync_relay_runner.py").resolve())
        completed = subprocess.run(
            command,
            cwd=str(ROOT),
            check=False,
            capture_output=True,
            text=True,
            timeout=45,
        )
        assert bundle["marker_path"].is_file(), (
            "relay child did not load tests/sitecustomize.py; writer isolation is unproven"
        )
        assert completed.returncode == 0, completed.stderr or completed.stdout
        ingest_bodies = bundle["recorded"].bodies_for(DEFAULT_ENDPOINT_PATH)
        assert ingest_bodies, (
            "real relay child exited 0 but never POSTed /api/producer-ingest/v1/source-file"
        )
        assert csv_bytes in ingest_bodies[0]
        assert "direct_sync_relay_status=acked" in completed.stdout


@pytest.mark.skipif(os.name != "nt", reason="Windows named-mutex regression")
def test_session_direct_sync_once_real_child_posts_csv_to_loopback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M2 production wrapper: TRAY_COMPLETE session sync must spawn a real
    child that POSTs the CSV. Do not treat a writer-gate timeout as success.
    """

    with _loopback_https(tmp_path, monkeypatch) as bundle:
        events = tmp_path / "events"
        csv_bytes = _write_csv(events / CSV_NAME)
        direct_sync_root = tmp_path / "direct-sync"
        _write_child_runtime(direct_sync_root, bundle)
        result = bootstrap.run_session_direct_sync_once(
            app_root=ROOT,
            direct_sync_root=direct_sync_root,
            scan_source_dir=events,
            timeout_seconds=20,
        )
        assert bundle["marker_path"].is_file(), (
            "relay child did not load tests/sitecustomize.py; writer isolation is unproven"
        )
        ingest_bodies = bundle["recorded"].bodies_for(DEFAULT_ENDPOINT_PATH)
        assert result["status"] == "PASS", result
        assert result.get("returncode") == 0, result
        assert ingest_bodies, (
            "session direct-sync child never POSTed /api/producer-ingest/v1/source-file"
        )
        assert csv_bytes in ingest_bodies[0]


def test_real_https_transfer_seal_posts_to_loopback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M5: logistics POST /transfers/seal. FakeSession would keep this green if HTTP were a no-op."""

    with _loopback_https(tmp_path, monkeypatch) as bundle:
        context = bundle["context"]
        private = bundle["private"]
        client = transfer_seal.LogisticsTransferClient(
            context.server_base_url,
            str(private["logistics_token"]),
            "container-loopback-host",
            session=None,
            tls_ca_bundle_path=context.ca_bundle_path,
        )
        sealed = client.seal_transfer(
            {
                "authority_scope_id": "QUALIFICATION-CONTAINER-AUDIT",
                "idempotency_key": "loopback-seal-key",
                "member_ids": ["unit-1"],
            }
        )
        assert sealed["receipt_id"] == "loopback-seal-1"
        assert sealed["status"] == "COMMITTED"
        assert "/logistics/api/v1/transfers/seal" in bundle["recorded"].paths()


@pytest.mark.skipif(os.name != "nt", reason="Windows DETACHED_PROCESS user-relay launch")
def test_start_user_relay_process_spawns_real_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M3: start_user_relay_process uses real subprocess.Popen. A launcher stub
    would keep the suite green if the exe exited immediately.
    """

    with _loopback_https(tmp_path, monkeypatch) as bundle:
        events = tmp_path / "events"
        _write_csv(events / CSV_NAME)
        data_root = tmp_path / "data-root"
        monkeypatch.setenv("CONTAINER_AUDIT_DATA_ROOT", str(data_root))
        launched = user_relay.start_user_relay_process(ROOT)
        process_id = int(launched["process_id"])
        try:
            assert launched["status"] == "START_REQUESTED"
            assert process_id > 0
            deadline = time.monotonic() + 8
            alive = False
            while time.monotonic() < deadline:
                try:
                    os.kill(process_id, 0)
                    alive = True
                    break
                except OSError:
                    time.sleep(0.05)
            assert alive, f"user-relay child pid {process_id} was not observable after Popen"
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not bundle["marker_path"].is_file():
                time.sleep(0.05)
            assert bundle["marker_path"].is_file(), (
                "user-relay child did not load tests/sitecustomize.py; "
                "writer isolation is unproven"
            )
        finally:
            try:
                os.kill(process_id, 9)
            except OSError:
                pass
            subprocess.run(
                ["taskkill", "/PID", str(process_id), "/T", "/F"],
                check=False,
                capture_output=True,
                timeout=10,
            )
