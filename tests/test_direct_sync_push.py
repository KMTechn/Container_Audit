import csv
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

import direct_sync_push
from event_contracts import plan_b_event_detail
from event_log_store import append_event_log_entry
from direct_sync_push import (
    DEFAULT_ENDPOINT_PATH,
    DirectSyncPushError,
    ProducerCredentials,
    RELAY_STATUS_ACKED,
    RELAY_STATUS_FAILED_PERMANENT,
    RELAY_STATUS_LEASED,
    RELAY_STATUS_OPERATOR_REVIEW,
    RELAY_STATUS_PENDING,
    RELAY_STATUS_RETRY_WAIT,
    acked_relay_retention_candidates,
    build_raw_artifact_restore_url,
    build_source_file_plan,
    canonical_json,
    canonical_request_string,
    claim_next_relay_batch,
    count_csv_data_rows,
    drain_one_relay_batch,
    enqueue_source_file_for_relay,
    manifest_hash,
    relay_queue_status,
    reset_stale_relay_leases,
    restore_metadata_from_upload_metadata,
    restore_raw_artifact_to_file,
    signed_headers,
    upload_source_file,
)


def test_retry_after_seconds_uses_stable_bounded_jitter():
    assert direct_sync_push._retry_after_seconds(3, 10) == 30
    delays = {
        direct_sync_push._retry_after_seconds(3, 10, f"relay-{index:02d}")
        for index in range(20)
    }

    assert min(delays) >= 30
    assert max(delays) <= 36
    assert len(delays) > 1
    assert direct_sync_push._retry_after_seconds(3, 10, "relay-03") == (
        direct_sync_push._retry_after_seconds(3, 10, "relay-03")
    )


class FakeResponse:
    def __init__(self, status_code, payload, headers=None):
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def json(self):
        return self._payload


class InvalidJsonResponse:
    def __init__(self, status_code):
        self.status_code = status_code

    def json(self):
        raise ValueError("not json")


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, url, *, data, files, headers, timeout, allow_redirects):
        file_name, file_handle, content_type = files["file"]
        self.calls.append(
            {
                "url": url,
                "metadata": data["metadata"],
                "headers": dict(headers),
                "timeout": timeout,
                "allow_redirects": allow_redirects,
                "file_name": file_name,
                "file_bytes": file_handle.read(),
                "content_type": content_type,
            }
        )
        return self.response


class FakeRestoreResponse:
    def __init__(self, status_code, body=b"", *, headers=None, payload=None):
        self.status_code = status_code
        self.content = body
        self.headers = dict(headers or {})
        self._payload = payload if payload is not None else {}

    def iter_content(self, chunk_size=1024 * 1024):
        for index in range(0, len(self.content), chunk_size):
            yield self.content[index : index + chunk_size]

    def json(self):
        return self._payload


class FakeRestoreSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, *, headers, timeout, stream=False, allow_redirects=False):
        self.calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "timeout": timeout,
                "stream": stream,
                "allow_redirects": allow_redirects,
            }
        )
        return self.response


class SequenceFakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, *, data, files, headers, timeout, allow_redirects):
        file_name, file_handle, content_type = files["file"]
        self.calls.append(
            {
                "url": url,
                "metadata": data["metadata"],
                "headers": dict(headers),
                "timeout": timeout,
                "allow_redirects": allow_redirects,
                "file_name": file_name,
                "file_bytes": file_handle.read(),
                "content_type": content_type,
            }
        )
        return self.responses.pop(0)


def make_manifest(tmp_path):
    manifest = {
        "schema_version": "producer-onboarding-manifest-v1",
        "pc_identity": {
            "pc_id": "CONTAINER-PC01",
            "source_host_id": "container-host-1",
            "producer_install_id": "install-container-1",
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
    path = tmp_path / "producer_manifest.json"
    path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    return manifest, path


def write_csv(tmp_path):
    path = tmp_path / "이적작업이벤트로그_fixture_20260621.csv"
    path.write_text(
        "timestamp,worker_name,event,details\n"
        "2026-06-21T00:00:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-1\"\" }\"\n",
        encoding="utf-8",
    )
    return path


def write_container_audit_completion_csv(tmp_path):
    path = tmp_path / "이적작업이벤트로그_홍길동_20260622.csv"
    append_event_log_entry(
        str(path),
        {
            "timestamp": "2026-06-22T09:00:00",
            "worker_name": "홍길동",
            "event": "SCAN_OK",
            "details": json.dumps(
                plan_b_event_detail(
                    "SCAN_OK",
                    {"barcode": "AAA2270730100-001", "scan_count": 1},
                    source_system="container_audit",
                    source_transport_or_dataset="legacy_transfer_csv",
                ),
                ensure_ascii=False,
            ),
        },
    )
    append_event_log_entry(
        str(path),
        {
            "timestamp": "2026-06-22T09:03:00",
            "worker_name": "홍길동",
            "event": "TRAY_COMPLETE",
            "details": json.dumps(
                plan_b_event_detail(
                    "TRAY_COMPLETE",
                    {
                        "master_label_code": "PHS=1|CLC=AAA2270730100|QT=2",
                        "item_code": "AAA2270730100",
                        "item_name": "fixture item",
                        "scan_count": 2,
                        "tray_capacity": 60,
                        "scanned_product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
                        "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
                        "quantity_basis": "PRODUCT_BARCODE",
                        "confidence": "BARCODE",
                        "qty_uom": "piece",
                    },
                    source_system="container_audit",
                    source_transport_or_dataset="legacy_transfer_csv",
                ),
                ensure_ascii=False,
            ),
        },
    )
    return path


def make_credentials():
    return ProducerCredentials(
        producer_id="producer-container",
        key_id="key-container",
        secret="container-secret",
        endpoint_url="https://worker.example.invalid/api/producer-ingest/v1/source-file",
    )


def test_restore_raw_artifact_downloads_verified_payload(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    body = csv_path.read_bytes()
    destination = tmp_path / "spool" / "restored.csv"
    session = FakeRestoreSession(
        FakeRestoreResponse(
            200,
            body,
            headers={
                "X-Content-SHA256": plan.content_sha256,
                "X-Byte-Length": str(plan.byte_length),
            },
        )
    )

    result = restore_raw_artifact_to_file(
        credentials=credentials,
        metadata=plan.metadata,
        destination_path=destination,
        session=session,
    )

    assert result.success is True
    assert destination.read_bytes() == body
    assert session.calls[0]["url"] == build_raw_artifact_restore_url(
        credentials.endpoint_url,
        content_sha256=plan.content_sha256,
        byte_length=plan.byte_length,
    )
    assert json.loads(session.calls[0]["headers"]["X-Producer-Restore-Metadata"]) == (
        restore_metadata_from_upload_metadata(plan.metadata)
    )


def test_restore_raw_artifact_falls_back_when_hardlink_is_unavailable(tmp_path, monkeypatch):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    body = csv_path.read_bytes()
    destination = tmp_path / "spool" / "restored.csv"
    session = FakeRestoreSession(
        FakeRestoreResponse(
            200,
            body,
            headers={
                "X-Content-SHA256": plan.content_sha256,
                "X-Byte-Length": str(plan.byte_length),
            },
        )
    )

    def hardlink_unavailable(_src, _dst):
        raise OSError("hard links disabled")

    monkeypatch.setattr(direct_sync_push.os, "link", hardlink_unavailable)

    result = restore_raw_artifact_to_file(
        credentials=credentials,
        metadata=plan.metadata,
        destination_path=destination,
        session=session,
    )

    assert result.success is True
    assert destination.read_bytes() == body
    assert not list(destination.parent.glob("restored.csv.tmp.*"))


def test_restore_raw_artifact_does_not_overwrite_file_created_during_download(tmp_path, monkeypatch):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    destination = tmp_path / "spool" / "restored.csv"
    session = FakeRestoreSession(
        FakeRestoreResponse(
            200,
            csv_path.read_bytes(),
            headers={
                "X-Content-SHA256": plan.content_sha256,
                "X-Byte-Length": str(plan.byte_length),
            },
        )
    )

    def race_create_destination(_src, dst):
        Path(dst).write_text("operator-race-copy\n", encoding="utf-8")
        raise FileExistsError

    monkeypatch.setattr(direct_sync_push.os, "link", race_create_destination)

    result = restore_raw_artifact_to_file(
        credentials=credentials,
        metadata=plan.metadata,
        destination_path=destination,
        session=session,
    )

    assert result.success is False
    assert result.error_code == "restore_destination_exists"
    assert destination.read_text(encoding="utf-8") == "operator-race-copy\n"
    assert not list(destination.parent.glob("restored.csv.tmp.*"))


def expect_push_error(callable_obj):
    try:
        callable_obj()
    except DirectSyncPushError:
        return
    raise AssertionError("expected DirectSyncPushError")


def test_upload_status_atomic_json_write_uses_unique_temp_paths(tmp_path, monkeypatch):
    target = tmp_path / "status.json"
    observed = []
    original_replace = direct_sync_push.os.replace

    def capture_replace(src, dst):
        observed.append((Path(src).name, Path(dst).name))
        original_replace(src, dst)

    monkeypatch.setattr(direct_sync_push.os, "replace", capture_replace)

    direct_sync_push._write_json_atomic(target, {"step": 1})
    direct_sync_push._write_json_atomic(target, {"step": 2})

    assert observed[0][0].startswith("status.json.tmp.")
    assert observed[1][0].startswith("status.json.tmp.")
    assert observed[0][0] != observed[1][0]
    assert observed[0][1] == "status.json"
    assert json.loads(target.read_text(encoding="utf-8"))["step"] == 2
    assert list(tmp_path.glob("status.json.tmp.*")) == []


def test_relay_spool_atomic_copy_uses_unique_temp_paths(tmp_path, monkeypatch):
    source = tmp_path / "source.csv"
    source.write_text("payload", encoding="utf-8")
    destination = tmp_path / "spool" / "source.csv"
    observed = []
    original_replace = direct_sync_push.os.replace

    def capture_replace(src, dst):
        observed.append((Path(src).name, Path(dst).name))
        original_replace(src, dst)

    monkeypatch.setattr(direct_sync_push.os, "replace", capture_replace)

    direct_sync_push._copy_file_atomic(source, destination)
    direct_sync_push._copy_file_atomic(source, destination)

    assert observed[0][0].startswith("source.csv.tmp.")
    assert observed[1][0].startswith("source.csv.tmp.")
    assert observed[0][0] != observed[1][0]
    assert observed[0][1] == "source.csv"
    assert destination.read_text(encoding="utf-8") == "payload"
    assert list(destination.parent.glob("source.csv.tmp.*")) == []


def test_upload_rejects_unsafe_endpoint_before_signing_or_posting(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    for endpoint_url in (
        "http://localhost/api/producer-ingest/v1/source-file",
        "https://producer:secret@worker.example.invalid/api/producer-ingest/v1/source-file",
        "https://10.1.2.3/api/producer-ingest/v1/source-file",
        "https://172.16.0.5/api/producer-ingest/v1/source-file",
        "https://192.168.1.10/api/producer-ingest/v1/source-file",
        "https://169.254.169.254/api/producer-ingest/v1/source-file",
        "https://224.0.0.1/api/producer-ingest/v1/source-file",
        "https://240.0.0.1/api/producer-ingest/v1/source-file",
        "https://[fd00::1]/api/producer-ingest/v1/source-file",
        "https://worker.example.invalid:99999/api/producer-ingest/v1/source-file",
    ):
        credentials = ProducerCredentials(
            producer_id="producer-container",
            key_id="key-container",
            secret="container-secret",
            endpoint_url=endpoint_url,
        )
        plan = build_source_file_plan(
            source_file_path=csv_path,
            producer_manifest_path=manifest_path,
            credentials=credentials,
        )
        session = FakeSession(FakeResponse(200, {"committed": True}))

        expect_push_error(lambda: upload_source_file(plan, credentials, session=session))

        assert session.calls == []


def test_validate_endpoint_url_rejects_invalid_port_before_dns_lookup(monkeypatch):
    monkeypatch.setattr(
        direct_sync_push.socket,
        "getaddrinfo",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("invalid port should not resolve DNS")),
    )

    with pytest.raises(DirectSyncPushError, match="port is invalid"):
        direct_sync_push.validate_endpoint_url(
            "https://worker.example.invalid:99999/api/producer-ingest/v1/source-file"
        )


def test_upload_rejects_hostname_resolving_to_private_address_before_posting(tmp_path, monkeypatch):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = ProducerCredentials(
        producer_id="producer-container",
        key_id="key-container",
        secret="container-secret",
        endpoint_url="https://worker.example.invalid/api/producer-ingest/v1/source-file",
    )
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    session = FakeSession(FakeResponse(200, {"committed": True}))
    monkeypatch.setattr(
        direct_sync_push.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(direct_sync_push.socket.AF_INET, 0, 0, "", ("10.1.2.3", 443))],
    )

    expect_push_error(lambda: upload_source_file(plan, credentials, session=session))

    assert session.calls == []


def test_build_plan_uses_container_stream_and_csv_rows(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()

    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )

    content = csv_path.read_bytes()
    assert plan.content_sha256 == hashlib.sha256(content).hexdigest()
    assert plan.byte_length == len(content)
    assert count_csv_data_rows(csv_path) == 1
    assert plan.metadata["manifest_hash"] == manifest_hash(manifest)
    assert plan.metadata["producer_role"] == "container_audit"
    assert plan.metadata["stream_name"] == "container_audit_events"
    assert plan.metadata["source_system"] == "container_audit"
    assert plan.metadata["source_transport"] == "legacy_transfer_csv"
    assert plan.metadata["relative_path"] == f"legacy_csv/{csv_path.name}"
    assert plan.metadata["row_count"] == 1
    assert plan.metadata["first_row_number"] == 2
    assert plan.metadata["last_row_number"] == 2


def test_build_plan_counts_multiline_csv_details_as_one_data_row(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = tmp_path / "이적작업이벤트로그_multiline_20260621.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["timestamp", "worker_name", "event", "details"])
        writer.writerow(
            [
                "2026-06-21T00:00:00",
                "worker",
                "SCAN_OK",
                json.dumps({"product_barcode": "BC-1", "message": "line1\nline2"}, ensure_ascii=False),
            ]
        )
    credentials = make_credentials()

    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )

    assert count_csv_data_rows(csv_path) == 1
    assert plan.metadata["row_count"] == 1
    assert plan.metadata["first_row_number"] == 2
    assert plan.metadata["last_row_number"] == 2


def test_build_plan_rejects_duplicate_json_keys_in_manifest(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    manifest_path.write_text(
        '{"pc_identity": {"source_host_id": "host-1"}, '
        '"pc_identity": {"producer_install_id": "producer-1"}, "streams": []}',
        encoding="utf-8",
    )
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()

    with pytest.raises(DirectSyncPushError, match="duplicate key: pc_identity"):
        build_source_file_plan(
            source_file_path=csv_path,
            producer_manifest_path=manifest_path,
            credentials=credentials,
        )


def test_build_plan_rejects_wrong_manifest_producer_role(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    manifest["streams"][0]["producer_role"] = "other_producer"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()

    with pytest.raises(DirectSyncPushError, match="stream does not match"):
        build_source_file_plan(
            source_file_path=csv_path,
            producer_manifest_path=manifest_path,
            credentials=credentials,
        )


def test_build_plan_rejects_non_container_audit_csv_header(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = tmp_path / "이적작업이벤트로그_bad_20260622.csv"
    csv_path.write_text("not,timestamp,event,details\n1,2,3,4\n", encoding="utf-8")
    credentials = make_credentials()

    with pytest.raises(DirectSyncPushError, match="Container_Audit event log CSV"):
        build_source_file_plan(
            source_file_path=csv_path,
            producer_manifest_path=manifest_path,
            credentials=credentials,
        )


def test_build_plan_accepts_enriched_container_audit_completion_csv(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_container_audit_completion_csv(tmp_path)
    credentials = make_credentials()

    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )

    assert count_csv_data_rows(csv_path) == 2
    assert plan.metadata["source_system"] == "container_audit"
    assert plan.metadata["source_transport"] == "legacy_transfer_csv"
    assert plan.metadata["row_count"] == 2
    assert plan.metadata["first_row_number"] == 2
    assert plan.metadata["last_row_number"] == 3

    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    completion = next(row for row in rows if row["event"] == "TRAY_COMPLETE")
    details = json.loads(completion["details"])
    assert details["source_system"] == "container_audit"
    assert details["source_transport_or_dataset"] == "legacy_transfer_csv"
    assert details["raw_event_name"] == "TRAY_COMPLETE"
    assert details["canonical_event_name"] == "TRAY_COMPLETE"
    assert details["dispatch_key"] == "container_audit|legacy_transfer_csv|TRAY_COMPLETE"
    assert details["quantity_basis"] == "PRODUCT_BARCODE"
    assert details["product_barcodes"] == ["AAA2270730100-001", "AAA2270730100-002"]


def test_enqueue_relay_preserves_enriched_container_audit_completion_csv(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_container_audit_completion_csv(tmp_path)
    credentials = make_credentials()

    row = enqueue_source_file_for_relay(
        db_path=tmp_path / "relay.sqlite3",
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )

    spooled_content = Path(row.spooled_file_path).read_text(encoding="utf-8-sig")
    assert "TRAY_COMPLETE" in spooled_content
    assert "container_audit|legacy_transfer_csv|TRAY_COMPLETE" in spooled_content


def test_signed_headers_match_server_contract(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )

    headers = signed_headers(
        credentials,
        plan.metadata,
        timestamp="2026-06-21T00:00:00Z",
        nonce="nonce-container-1",
    )
    canonical = canonical_request_string(
        method="POST",
        path=DEFAULT_ENDPOINT_PATH,
        query_string="",
        timestamp="2026-06-21T00:00:00Z",
        nonce="nonce-container-1",
        producer_id=credentials.producer_id,
        key_id=credentials.key_id,
        metadata=plan.metadata,
        content_sha256=plan.metadata["content_sha256"],
        byte_length=plan.metadata["byte_length"],
        content_type="multipart/form-data",
    )
    import hmac

    expected = hmac.new(b"container-secret", canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    assert headers["X-Producer-Signature"] == expected


def test_upload_writes_status_without_storing_secret(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    session = FakeSession(
        FakeResponse(
            200,
                {
                    "request_id": "request-container-1",
                    "upload_id": "request-container-1",
                    "client_batch_id": plan.metadata["client_batch_id"],
                    "server_source_file_id": (
                        f"{plan.metadata['source_host_id']}/"
                    f"{plan.metadata['producer_role']}/"
                    f"{plan.metadata['stream_name']}/"
                    f"{plan.metadata['relative_path']}"
                ),
                "committed": True,
                "status": "accepted",
                "retryable": False,
                "next_retry_after": None,
                "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
            },
        )
    )

    result = upload_source_file(plan, credentials, session=session, status_dir=tmp_path / "status")

    assert result.success is True
    assert result.committed is True
    assert Path(result.status_path).is_file()
    assert json.loads(session.calls[0]["metadata"]) == plan.metadata
    assert session.calls[0]["metadata"] == canonical_json(plan.metadata)
    assert session.calls[0]["file_bytes"] == csv_path.read_bytes()
    status_text = Path(result.status_path).read_text(encoding="utf-8")
    assert "container-secret" not in status_text
    assert "X-Producer-Signature" not in status_text


def test_upload_refuses_source_file_changed_after_plan(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    csv_path.write_text(
        "timestamp,worker_name,event,details\n"
        "2026-06-21T00:00:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-2\"\" }\"\n"
        "2026-06-21T00:01:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-3\"\" }\"\n",
        encoding="utf-8",
    )
    session = FakeSession(FakeResponse(200, {"committed": True}))

    result = upload_source_file(plan, credentials, session=session, status_dir=tmp_path / "status")

    assert session.calls == []
    assert result.success is False
    assert result.committed is False
    assert result.retryable is False
    assert result.status_code == 0
    assert result.error_code == "source_file_digest_mismatch"
    assert Path(result.status_path).is_file()
    status = json.loads(Path(result.status_path).read_text(encoding="utf-8"))
    assert status["error_code"] == "source_file_digest_mismatch"
    assert status["metadata"] == plan.metadata


def test_upload_refuses_unreadable_source_file_after_plan(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    csv_path.unlink()
    session = FakeSession(FakeResponse(200, {"committed": True}))

    result = upload_source_file(plan, credentials, session=session, status_dir=tmp_path / "status")

    assert session.calls == []
    assert result.success is False
    assert result.committed is False
    assert result.retryable is False
    assert result.status_code == 0
    assert result.error_code == "source_file_unreadable"
    assert "FileNotFoundError" in result.error_message
    assert Path(result.status_path).is_file()


def test_upload_disables_redirects_and_rejects_redirect_response(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    session = FakeSession(InvalidJsonResponse(307))

    result = upload_source_file(plan, credentials, session=session, status_dir=tmp_path / "status")

    assert session.calls[0]["allow_redirects"] is False
    assert result.success is False
    assert result.committed is False
    assert result.retryable is False
    assert result.status_code == 307
    assert result.error_code == "producer_redirect_not_allowed"
    assert Path(result.status_path).is_file()


def test_upload_remote_failure_redacts_server_echoed_sensitive_payload(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )

    class EchoingFailureSession:
        def __init__(self):
            self.calls = []

        def post(self, url, *, data, files, headers, timeout, allow_redirects):
            file_name, file_handle, content_type = files["file"]
            self.calls.append(
                {
                    "url": url,
                    "metadata": data["metadata"],
                    "headers": dict(headers),
                    "timeout": timeout,
                    "allow_redirects": allow_redirects,
                    "file_name": file_name,
                    "file_bytes": file_handle.read(),
                    "content_type": content_type,
                }
            )
            signature = headers["X-Producer-Signature"]
            return FakeResponse(
                503,
                {
                    "committed": False,
                    "retryable": True,
                    "error": {
                        "code": "ingest_write_disabled",
                        "message": (
                            "disabled Authorization: Bearer SHOULD-NOT-LEAK "
                            f"{signature} X-Producer-Signature "
                            f"{direct_sync_push.SIGNATURE_VERSION} {credentials.secret}\nnext"
                        ),
                    },
                    "echo": ["Authorization: Bearer SHOULD-NOT-LEAK", signature],
                    "X-Producer-Signature": "server-echo-key",
                },
            )

    session = EchoingFailureSession()

    result = upload_source_file(plan, credentials, session=session, status_dir=tmp_path / "status")

    assert result.success is False
    assert result.committed is False
    assert result.retryable is True
    assert result.error_code == "ingest_write_disabled"
    assert "\n" not in result.error_message
    status_text = Path(result.status_path).read_text(encoding="utf-8")
    combined_text = json.dumps(result.receipt, ensure_ascii=False) + status_text + result.error_message
    for leaked in (
        "SHOULD-NOT-LEAK",
        credentials.secret,
        session.calls[0]["headers"]["X-Producer-Signature"],
        "X-Producer-Signature",
        direct_sync_push.SIGNATURE_VERSION,
        "Authorization",
    ):
        assert leaked not in combined_text


def test_upload_non_2xx_invalid_json_has_retryable_diagnostic(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    session = FakeSession(InvalidJsonResponse(500))

    result = upload_source_file(plan, credentials, session=session, status_dir=tmp_path / "status")

    assert session.calls[0]["allow_redirects"] is False
    assert result.success is False
    assert result.committed is False
    assert result.retryable is True
    assert result.status_code == 500
    assert result.error_code == "producer_response_invalid_json"
    assert "not valid JSON" in result.error_message
    assert Path(result.status_path).is_file()


def test_upload_status_artifact_write_failure_preserves_upload_result(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    server_source_file_id = (
        f"{plan.metadata['source_host_id']}/"
        f"{plan.metadata['producer_role']}/"
        f"{plan.metadata['stream_name']}/"
        f"{plan.metadata['relative_path']}"
    )
    status_dir = tmp_path / "status-is-a-file"
    status_dir.write_text("not a directory", encoding="utf-8")
    session = FakeSession(
        FakeResponse(
            200,
                {
                    "request_id": "request-container-1",
                    "upload_id": "request-container-1",
                    "client_batch_id": plan.metadata["client_batch_id"],
                    "server_source_file_id": server_source_file_id,
                    "committed": True,
                "status": "accepted",
                "retryable": False,
                "next_retry_after": None,
                "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
            },
        )
    )

    result = upload_source_file(plan, credentials, session=session, status_dir=status_dir)

    assert result.success is True
    assert result.committed is True
    assert result.status_path == ""
    assert result.error_code == "upload_status_write_failed"
    assert "FileExistsError" in result.error_message


def test_upload_status_artifact_write_failure_does_not_mask_producer_error(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    status_dir = tmp_path / "status-is-a-file"
    status_dir.write_text("not a directory", encoding="utf-8")
    session = FakeSession(
        FakeResponse(
            503,
            {
                "committed": False,
                "retryable": True,
                "error": {"code": "temporary_unavailable", "message": "try later"},
            },
        )
    )

    result = upload_source_file(plan, credentials, session=session, status_dir=status_dir)

    assert result.success is False
    assert result.retryable is True
    assert result.status_path == ""
    assert result.error_code == "temporary_unavailable"
    assert result.error_message == "try later"
    assert result.receipt["_local_upload_status_write_error_code"] == "upload_status_write_failed"
    assert "FileExistsError" in result.receipt["_local_upload_status_write_error_message"]


def test_upload_2xx_invalid_receipt_is_operator_review_candidate(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    session = FakeSession(InvalidJsonResponse(200))

    result = upload_source_file(plan, credentials, session=session, status_dir=tmp_path / "status")

    assert result.success is False
    assert result.committed is True
    assert result.retryable is False
    assert result.error_code == "producer_receipt_invalid"
    assert Path(result.status_path).is_file()


def test_upload_2xx_string_committed_receipt_is_operator_review_candidate(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    plan = build_source_file_plan(
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    server_source_file_id = (
        f"{plan.metadata['source_host_id']}/"
        f"{plan.metadata['producer_role']}/"
        f"{plan.metadata['stream_name']}/"
        f"{plan.metadata['relative_path']}"
    )
    session = FakeSession(
        FakeResponse(
            200,
            {
                "request_id": "request-string-committed",
                "client_batch_id": plan.metadata["client_batch_id"],
                "server_source_file_id": server_source_file_id,
                "committed": "false",
                "status": "accepted",
                "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
            },
        )
    )

    result = upload_source_file(plan, credentials, session=session, status_dir=tmp_path / "status")

    assert result.success is False
    assert result.committed is True
    assert result.retryable is False
    assert result.error_code == "producer_receipt_invalid"
    assert Path(result.status_path).is_file()


def test_relay_enqueue_spools_file_without_storing_auth_secret_or_signature(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()

    row = enqueue_source_file_for_relay(
        db_path=tmp_path / "relay.sqlite3",
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )

    assert row.status == RELAY_STATUS_PENDING
    assert Path(row.spooled_file_path).read_bytes() == csv_path.read_bytes()
    status = relay_queue_status(tmp_path / "relay.sqlite3")
    assert status["counts"][RELAY_STATUS_PENDING] == 1
    db_bytes = (tmp_path / "relay.sqlite3").read_bytes()
    assert b"container-secret" not in db_bytes
    assert b"X-Producer-Signature" not in db_bytes
    assert b"PRODUCER-HMAC-SHA256-V1" not in db_bytes


def test_relay_enqueue_dedupes_same_completed_file_and_blocks_changed_content(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    spool_dir = tmp_path / "spool"

    first = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )
    duplicate = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )

    assert duplicate.relay_id == first.relay_id
    assert duplicate.deduped_existing is True
    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_PENDING] == 1
    assert len(list(spool_dir.iterdir())) == 1

    csv_path.write_text(
        "timestamp,worker_name,event,details\n"
        "2026-06-22T00:01:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-2\"\" }\"\n",
        encoding="utf-8",
    )
    with pytest.raises(DirectSyncPushError, match="source file content conflict"):
        enqueue_source_file_for_relay(
            db_path=db_path,
            spool_dir=spool_dir,
            source_file_path=csv_path,
            producer_manifest_path=manifest_path,
            credentials=credentials,
            dedupe_existing=True,
        )

    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_PENDING] == 1
    assert len(list(spool_dir.iterdir())) == 1


def test_relay_enqueue_does_not_dedupe_when_manifest_identity_changes(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    spool_dir = tmp_path / "spool"

    first = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )
    manifest["pc_identity"]["source_host_id"] = "container-host-2"
    manifest["pc_identity"]["producer_install_id"] = "install-container-2"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    second = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )

    assert second.relay_id != first.relay_id
    assert second.deduped_existing is False
    assert first.metadata["source_host_id"] == "container-host-1"
    assert second.metadata["source_host_id"] == "container-host-2"
    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_PENDING] == 2
    assert len(list(spool_dir.iterdir())) == 2


def test_relay_enqueue_dedupes_same_upload_identity_from_copied_manifest(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    copied_manifest_path = tmp_path / "copied_manifest.json"
    copied_manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    spool_dir = tmp_path / "spool"

    first = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )
    duplicate = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_path,
        producer_manifest_path=copied_manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )

    assert duplicate.relay_id == first.relay_id
    assert duplicate.deduped_existing is True
    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_PENDING] == 1
    assert len(list(spool_dir.iterdir())) == 1


def test_relay_enqueue_blocks_changed_content_for_same_upload_identity_from_copied_manifest(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    copied_manifest_path = tmp_path / "copied_manifest.json"
    copied_manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
    source_a = tmp_path / "source-a"
    source_b = tmp_path / "source-b"
    source_a.mkdir()
    source_b.mkdir()
    csv_a = write_csv(source_a)
    csv_b = write_csv(source_b)
    csv_b.write_text(
        "timestamp,worker_name,event,details\n"
        "2026-06-22T00:01:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-2\"\" }\"\n",
        encoding="utf-8",
    )
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    spool_dir = tmp_path / "spool"

    enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_a,
        producer_manifest_path=manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )
    with pytest.raises(DirectSyncPushError, match="source file content conflict"):
        enqueue_source_file_for_relay(
            db_path=db_path,
            spool_dir=spool_dir,
            source_file_path=csv_b,
            producer_manifest_path=copied_manifest_path,
            credentials=credentials,
            dedupe_existing=True,
        )

    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_PENDING] == 1
    assert len(list(spool_dir.iterdir())) == 1


@pytest.mark.parametrize("damage", ["delete", "tamper"])
def test_relay_enqueue_repairs_invalid_existing_spool_for_deduped_pending_batch(tmp_path, damage):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    spool_dir = tmp_path / "spool"
    first = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )
    spooled_path = Path(first.spooled_file_path)
    if damage == "delete":
        spooled_path.unlink()
    else:
        spooled_path.write_text("timestamp,worker_name,event,details\n", encoding="utf-8")

    duplicate = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )

    assert duplicate.relay_id == first.relay_id
    assert duplicate.deduped_existing is True
    assert Path(duplicate.spooled_file_path).read_bytes() == csv_path.read_bytes()
    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_PENDING] == 1

    server_source_file_id = f"{manifest['pc_identity']['source_host_id']}/container_audit/container_audit_events/{duplicate.relative_path}"
    session = FakeSession(
        FakeResponse(
            200,
                {
                    "request_id": "request-repaired-spool",
                    "upload_id": "request-repaired-spool",
                    "client_batch_id": duplicate.relay_id,
                    "server_source_file_id": server_source_file_id,
                    "committed": True,
                "status": "accepted",
                "retryable": False,
                "next_retry_after": None,
                "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
            },
        )
    )

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is True
    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_ACKED] == 1


def test_relay_enqueue_dedupes_concurrent_same_completed_file(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    spool_dir = tmp_path / "spool"

    def enqueue():
        return enqueue_source_file_for_relay(
            db_path=db_path,
            spool_dir=spool_dir,
            source_file_path=csv_path,
            producer_manifest_path=manifest_path,
            credentials=credentials,
            dedupe_existing=True,
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        rows = list(executor.map(lambda _: enqueue(), range(4)))

    assert len({row.relay_id for row in rows}) == 1
    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_PENDING] == 1
    assert len(list(spool_dir.iterdir())) == 1


def test_relay_enqueue_dedupes_same_file_with_relative_and_absolute_paths(tmp_path, monkeypatch):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    spool_dir = tmp_path / "spool"
    monkeypatch.chdir(tmp_path)

    first = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_path.resolve(),
        producer_manifest_path=manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )
    duplicate = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_path.name,
        producer_manifest_path=manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )

    assert duplicate.relay_id == first.relay_id
    assert duplicate.deduped_existing is True
    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_PENDING] == 1
    assert len(list(spool_dir.iterdir())) == 1


def test_relay_enqueue_dedupes_same_upload_identity_from_different_source_dirs(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    source_a = tmp_path / "source-a"
    source_b = tmp_path / "source-b"
    source_a.mkdir()
    source_b.mkdir()
    csv_a = write_csv(source_a)
    csv_b = write_csv(source_b)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    spool_dir = tmp_path / "spool"

    first = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_a,
        producer_manifest_path=manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )
    duplicate = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_b,
        producer_manifest_path=manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )

    assert duplicate.relay_id == first.relay_id
    assert duplicate.deduped_existing is True
    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_PENDING] == 1
    assert len(list(spool_dir.iterdir())) == 1


def test_relay_enqueue_blocks_changed_content_for_same_upload_identity_from_different_source_dirs(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    source_a = tmp_path / "source-a"
    source_b = tmp_path / "source-b"
    source_a.mkdir()
    source_b.mkdir()
    csv_a = write_csv(source_a)
    csv_b = write_csv(source_b)
    csv_b.write_text(
        "timestamp,worker_name,event,details\n"
        "2026-06-22T00:01:00,worker,SCAN_OK,\"{ \"\"product_barcode\"\": \"\"BC-2\"\" }\"\n",
        encoding="utf-8",
    )
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    spool_dir = tmp_path / "spool"

    enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=csv_a,
        producer_manifest_path=manifest_path,
        credentials=credentials,
        dedupe_existing=True,
    )
    with pytest.raises(DirectSyncPushError, match="source file content conflict"):
        enqueue_source_file_for_relay(
            db_path=db_path,
            spool_dir=spool_dir,
            source_file_path=csv_b,
            producer_manifest_path=manifest_path,
            credentials=credentials,
            dedupe_existing=True,
        )

    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_PENDING] == 1
    assert len(list(spool_dir.iterdir())) == 1


def test_relay_enqueue_keeps_legacy_duplicate_behavior_without_dedupe(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"

    first = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    second = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )

    assert second.relay_id != first.relay_id
    assert second.deduped_existing is False
    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_PENDING] == 2


def test_relay_enqueue_cleans_spool_temp_file_when_atomic_copy_fails(tmp_path, monkeypatch):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    spool_dir = tmp_path / "spool"

    def fail_replace(_src, _dst):
        raise OSError("replace failed")

    monkeypatch.setattr(direct_sync_push.os, "replace", fail_replace)

    with pytest.raises(direct_sync_push.RelaySpoolFileError, match="relay spool file cannot be written"):
        enqueue_source_file_for_relay(
            db_path=tmp_path / "relay.sqlite3",
            spool_dir=spool_dir,
            source_file_path=csv_path,
            producer_manifest_path=manifest_path,
            credentials=credentials,
        )

    assert list(spool_dir.glob("*.tmp")) == []


def test_relay_claim_and_stale_lease_reset(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )

    claimed = claim_next_relay_batch(
        db_path=db_path,
        worker_id="worker-1",
        lease_seconds=1,
        now="2999-06-21T00:00:00Z",
    )

    assert claimed is not None
    assert claimed.status == RELAY_STATUS_LEASED
    assert claimed.attempt_count == 1
    assert claim_next_relay_batch(db_path=db_path, worker_id="worker-2", now="2999-06-21T00:00:00Z") is None
    assert reset_stale_relay_leases(db_path=db_path, now="2999-06-21T00:00:02Z") == 1
    status = relay_queue_status(db_path)
    assert status["counts"][RELAY_STATUS_PENDING] == 1


def test_relay_retry_then_success_uses_fresh_signed_request_and_marks_acked(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    server_source_file_id = f"{manifest['pc_identity']['source_host_id']}/container_audit/container_audit_events/{row.relative_path}"
    session = SequenceFakeSession(
        [
            FakeResponse(
                503,
                {
                    "committed": False,
                    "retryable": True,
                    "error": {"code": "temporary_unavailable", "message": "try later"},
                },
            ),
            FakeResponse(
                200,
                {
                    "request_id": "request-relay-2",
                    "upload_id": "request-relay-2",
                    "client_batch_id": row.relay_id,
                    "server_source_file_id": server_source_file_id,
                    "committed": True,
                    "status": "accepted",
                    "retryable": False,
                    "next_retry_after": None,
                    "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
                },
            ),
        ]
    )

    first = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
        retry_base_seconds=1,
    )

    assert first.success is False
    first_status_path = Path(first.status_path)
    assert first_status_path.is_file()
    first_status = json.loads(first_status_path.read_text(encoding="utf-8"))
    assert first_status["error_code"] == "temporary_unavailable"
    assert first_status["status_context"] == {"attempt_count": 1, "relay_id": row.relay_id}
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute("SELECT status FROM direct_sync_relay_batches WHERE relay_id = ?", (row.relay_id,)).fetchone()
        assert current["status"] == RELAY_STATUS_RETRY_WAIT
        conn.execute(
            "UPDATE direct_sync_relay_batches SET next_attempt_at = ? WHERE relay_id = ?",
            ("2026-06-21T00:00:00Z", row.relay_id),
        )
        conn.commit()

    second = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
        retry_base_seconds=1,
    )

    assert second.success is True
    second_status_path = Path(second.status_path)
    assert second_status_path.is_file()
    assert second_status_path != first_status_path
    second_status = json.loads(second_status_path.read_text(encoding="utf-8"))
    assert second_status["status_context"] == {"attempt_count": 2, "relay_id": row.relay_id}
    assert json.loads(first_status_path.read_text(encoding="utf-8"))["error_code"] == "temporary_unavailable"
    assert len(session.calls) == 2
    assert session.calls[0]["headers"]["X-Producer-Nonce"] != session.calls[1]["headers"]["X-Producer-Nonce"]
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            """
            SELECT status, receipt_json, upload_status_path
            FROM direct_sync_relay_batches
            WHERE relay_id = ?
            """,
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_ACKED
    assert json.loads(current["receipt_json"])["request_id"] == "request-relay-2"
    assert Path(current["upload_status_path"]).is_file()


def test_drain_retry_wait_uses_retry_after_header(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    session = FakeSession(
        FakeResponse(
            503,
            {
                "committed": False,
                "retryable": True,
                "error": {"code": "temporary_unavailable", "message": "try later"},
            },
            headers={"Retry-After": "120"},
        )
    )

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
        retry_base_seconds=1,
        now="2099-01-01T00:00:00Z",
    )

    assert result is not None
    assert result.success is False
    assert result.retry_after_seconds == 120
    status_artifact = json.loads(Path(result.status_path).read_text(encoding="utf-8"))
    assert status_artifact["retry_after_seconds"] == 120
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, next_attempt_at FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_RETRY_WAIT
    assert current["next_attempt_at"] == "2099-01-01T00:02:00Z"


def test_drain_retry_wait_preserves_zero_retry_after_header(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    session = FakeSession(
        FakeResponse(
            503,
            {
                "committed": False,
                "retryable": True,
                "error": {"code": "temporary_unavailable", "message": "try now"},
            },
            headers={"Retry-After": "0"},
        )
    )

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
        retry_base_seconds=60,
        now="2099-01-01T00:00:00Z",
    )

    assert result is not None
    assert result.retry_after_seconds == 0
    status_artifact = json.loads(Path(result.status_path).read_text(encoding="utf-8"))
    assert status_artifact["retry_after_seconds"] == 0
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, next_attempt_at FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_RETRY_WAIT
    assert current["next_attempt_at"] == "2099-01-01T00:00:00Z"


def test_retry_after_header_caps_far_future_http_date():
    retry_after = direct_sync_push._retry_after_header_seconds(
        "Tue, 01 Jan 2999 00:00:00 GMT",
        now=datetime(2099, 1, 1, tzinfo=timezone.utc),
    )

    assert retry_after == direct_sync_push.MAX_RETRY_AFTER_SECONDS


def test_drain_retry_wait_caps_huge_retry_after_header(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    session = FakeSession(
        FakeResponse(
            503,
            {
                "committed": False,
                "retryable": True,
                "error": {"code": "temporary_unavailable", "message": "try later"},
            },
            headers={"Retry-After": "315360000"},
        )
    )

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
        retry_base_seconds=1,
        now="2099-01-01T00:00:00Z",
    )

    assert result is not None
    assert result.retry_after_seconds == direct_sync_push.MAX_RETRY_AFTER_SECONDS
    status_artifact = json.loads(Path(result.status_path).read_text(encoding="utf-8"))
    assert status_artifact["retry_after_seconds"] == direct_sync_push.MAX_RETRY_AFTER_SECONDS
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, next_attempt_at FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_RETRY_WAIT
    assert current["next_attempt_at"] == "2099-01-02T00:00:00Z"


def test_drain_pre_upload_pause_releases_claim_without_posting(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    session = FakeSession(FakeResponse(200, {"committed": True, "status": "accepted"}))

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
        pre_upload_pause_check=lambda: {
            "enabled": True,
            "paused": True,
            "marker_valid": True,
            "operator_id": "operator-a",
        },
    )

    assert result is not None
    assert result.success is False
    assert result.error_code == "operator_paused"
    assert session.calls == []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            """
            SELECT status, attempt_count, lease_owner, lease_expires_at, last_error_code
            FROM direct_sync_relay_batches
            WHERE relay_id = ?
            """,
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_PENDING
    assert current["attempt_count"] == 0
    assert current["lease_owner"] is None
    assert current["lease_expires_at"] is None
    assert current["last_error_code"] == "operator_paused"


def test_drain_pre_upload_pause_restores_due_retry_wait_state(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    retry_session = FakeSession(
        FakeResponse(
            503,
            {
                "committed": False,
                "retryable": True,
                "error": {"code": "temporary_unavailable", "message": "try later"},
            },
        )
    )
    first = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=retry_session,
        status_dir=tmp_path / "status",
        retry_base_seconds=1,
    )
    assert first.retryable is True
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE direct_sync_relay_batches SET next_attempt_at = ? WHERE relay_id = ?",
            ("2026-06-21T00:00:00Z", row.relay_id),
        )
        conn.commit()
    paused_session = FakeSession(FakeResponse(200, {"committed": True, "status": "accepted"}))

    paused = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=paused_session,
        status_dir=tmp_path / "status",
        pre_upload_pause_check=lambda: {"enabled": True, "paused": True, "marker_valid": True},
    )

    assert paused is not None
    assert paused.error_code == "operator_paused"
    assert paused_session.calls == []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            """
            SELECT status, attempt_count, next_attempt_at, lease_owner, last_error_code
            FROM direct_sync_relay_batches
            WHERE relay_id = ?
            """,
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_RETRY_WAIT
    assert current["attempt_count"] == 1
    assert current["next_attempt_at"] == "2026-06-21T00:00:00Z"
    assert current["lease_owner"] is None
    assert current["last_error_code"] == "operator_paused"


def test_drain_uses_enqueued_metadata_snapshot_after_manifest_changes(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    original_manifest_hash = manifest_hash(manifest)
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    manifest["pc_identity"]["source_host_id"] = "changed-host-after-enqueue"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

    class EchoAcceptedSession:
        def __init__(self):
            self.calls = []

        def post(self, url, *, data, files, headers, timeout, allow_redirects):
            metadata = json.loads(data["metadata"])
            self.calls.append(metadata)
            return FakeResponse(
                200,
                {
                    "request_id": "request-snapshot",
                    "upload_id": "request-snapshot",
                    "client_batch_id": metadata["client_batch_id"],
                    "server_source_file_id": (
                        f"{metadata['source_host_id']}/"
                        f"{metadata['producer_role']}/"
                        f"{metadata['stream_name']}/"
                        f"{metadata['relative_path']}"
                    ),
                    "committed": True,
                    "status": "accepted",
                    "retryable": False,
                    "next_retry_after": None,
                    "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
                },
            )

    session = EchoAcceptedSession()

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is True
    assert session.calls[0]["client_batch_id"] == row.relay_id
    assert session.calls[0]["source_host_id"] == "container-host-1"
    assert session.calls[0]["manifest_hash"] == original_manifest_hash
    assert session.calls[0]["idempotency_key"].startswith("source-file:container-host-1/")


def test_relay_schema_migrates_legacy_queue_without_metadata_snapshot(tmp_path):
    db_path = tmp_path / "legacy-relay.sqlite3"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE direct_sync_relay_batches (
                relay_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                source_file_path TEXT NOT NULL,
                spooled_file_path TEXT NOT NULL,
                producer_manifest_path TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                byte_length INTEGER NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                lease_owner TEXT,
                lease_expires_at TEXT,
                next_attempt_at TEXT,
                last_error_code TEXT,
                last_error_message TEXT,
                receipt_json TEXT,
                upload_status_path TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO direct_sync_relay_batches (
                relay_id, status, source_file_path, spooled_file_path,
                producer_manifest_path, relative_path, content_sha256,
                byte_length, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "relay-legacy",
                RELAY_STATUS_PENDING,
                "source.csv",
                "spool.csv",
                "manifest.json",
                "legacy_csv/source.csv",
                "0" * 64,
                0,
                "2026-06-22T00:00:00Z",
                "2026-06-22T00:00:00Z",
            ),
        )
        conn.commit()

    direct_sync_push.init_relay_queue_schema(db_path)

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(direct_sync_relay_batches)").fetchall()}
        count = conn.execute("SELECT COUNT(*) AS count FROM direct_sync_relay_batches").fetchone()["count"]

    assert "metadata_json" in columns
    assert count == 1


def test_drain_legacy_row_without_metadata_snapshot_goes_to_operator_review_without_upload(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "legacy-relay.sqlite3"
    spooled_file = tmp_path / "spool.csv"
    spooled_file.write_text("timestamp,worker_name,event,details\n", encoding="utf-8")
    content = spooled_file.read_bytes()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE direct_sync_relay_batches (
                relay_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                source_file_path TEXT NOT NULL,
                spooled_file_path TEXT NOT NULL,
                producer_manifest_path TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                content_sha256 TEXT NOT NULL,
                byte_length INTEGER NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                lease_owner TEXT,
                lease_expires_at TEXT,
                next_attempt_at TEXT,
                last_error_code TEXT,
                last_error_message TEXT,
                receipt_json TEXT,
                upload_status_path TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO direct_sync_relay_batches (
                relay_id, status, source_file_path, spooled_file_path,
                producer_manifest_path, relative_path, content_sha256,
                byte_length, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "relay-legacy",
                RELAY_STATUS_PENDING,
                "source.csv",
                str(spooled_file),
                str(manifest_path),
                "legacy_csv/source.csv",
                hashlib.sha256(content).hexdigest(),
                len(content),
                "2026-06-22T00:00:00Z",
                "2026-06-22T00:00:00Z",
            ),
        )
        conn.commit()
    session = FakeSession(FakeResponse(200, {"committed": True}))

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.error_code == "relay_metadata_invalid"
    assert "metadata_json is missing" in result.error_message
    assert session.calls == []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, receipt_json FROM direct_sync_relay_batches WHERE relay_id = ?",
            ("relay-legacy",),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert current["last_error_code"] == "relay_metadata_invalid"
    assert json.loads(current["receipt_json"]) == {"client_batch_id": "relay-legacy"}


def test_drain_moves_committed_receipt_identity_mismatch_to_operator_review(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    session = FakeSession(
        FakeResponse(
            200,
            {
                "request_id": "request-wrong-identity",
                "client_batch_id": "relay-some-other-row",
                "server_source_file_id": "wrong/source/id",
                "committed": True,
                "status": "accepted",
                "retryable": False,
                "next_retry_after": None,
                "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
            },
        )
    )

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.committed is True
    assert result.relay_id == row.relay_id
    assert result.receipt["client_batch_id"] == "relay-some-other-row"
    assert result.error_code == "receipt_identity_mismatch"
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, receipt_json FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert current["last_error_code"] == "receipt_identity_mismatch"
    assert json.loads(current["receipt_json"])["client_batch_id"] == "relay-some-other-row"


def test_drain_moves_committed_receipt_missing_client_batch_id_to_operator_review(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    server_source_file_id = f"{manifest['pc_identity']['source_host_id']}/container_audit/container_audit_events/{row.relative_path}"
    session = FakeSession(
        FakeResponse(
            200,
            {
                "request_id": "request-missing-client-batch",
                "server_source_file_id": server_source_file_id,
                "committed": True,
                "status": "accepted",
                "retryable": False,
                "next_retry_after": None,
                "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
            },
        )
    )

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.committed is True
    assert result.error_code == "receipt_identity_missing"
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, receipt_json FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert current["last_error_code"] == "receipt_identity_missing"
    assert json.loads(current["receipt_json"])["request_id"] == "request-missing-client-batch"


@pytest.mark.parametrize(
    ("receipt_patch", "expected_error_code"),
    [
        ({"request_id": "__DELETE__"}, "receipt_trace_missing"),
        ({"upload_id": "__DELETE__"}, "receipt_trace_missing"),
        ({"upload_id": "request-from-different-upload"}, "receipt_trace_mismatch"),
    ],
)
def test_drain_moves_committed_receipt_missing_trace_identity_to_operator_review(
    tmp_path, receipt_patch, expected_error_code
):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    server_source_file_id = f"{manifest['pc_identity']['source_host_id']}/container_audit/container_audit_events/{row.relative_path}"
    receipt = {
        "request_id": "request-trace-identity",
        "upload_id": "request-trace-identity",
        "client_batch_id": row.relay_id,
        "server_source_file_id": server_source_file_id,
        "committed": True,
        "status": "accepted",
        "retryable": False,
        "next_retry_after": None,
        "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
    }
    for key, value in receipt_patch.items():
        if value == "__DELETE__":
            receipt.pop(key, None)
        else:
            receipt[key] = value
    session = FakeSession(FakeResponse(200, receipt))

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.committed is True
    assert result.error_code == expected_error_code
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, receipt_json FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert current["last_error_code"] == expected_error_code
    stored_receipt = json.loads(current["receipt_json"])
    assert stored_receipt["client_batch_id"] == row.relay_id


@pytest.mark.parametrize(
    ("receipt_patch", "expected_error_code"),
    [
        ({"server_source_file_id": None}, "receipt_identity_missing"),
        ({"status": "retry_wait"}, "producer_receipt_invalid"),
        ({"retryable": "__DELETE__"}, "producer_receipt_invalid"),
        ({"retryable": None}, "producer_receipt_invalid"),
        ({"retryable": True}, "producer_receipt_invalid"),
        ({"retryable": "false"}, "producer_receipt_invalid"),
        ({"next_retry_after": "2026-06-21T00:01:00Z"}, "producer_receipt_invalid"),
        ({"error": {"code": "contradictory_error", "message": "not accepted"}}, "producer_receipt_invalid"),
        ({"totals": None}, "producer_receipt_invalid"),
        ({"totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": "bad"}}, "producer_receipt_invalid"),
        ({"totals": {"inserted": True, "replayed": 0, "quarantined": 0, "errors": 0}}, "producer_receipt_invalid"),
        ({"totals": {"inserted": "1", "replayed": 0, "quarantined": 0, "errors": 0}}, "producer_receipt_invalid"),
        ({"totals": {"inserted": 0, "replayed": 0, "quarantined": 0, "errors": 0}}, "producer_receipt_invalid"),
    ],
)
def test_drain_moves_incomplete_committed_receipt_to_operator_review(tmp_path, receipt_patch, expected_error_code):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    server_source_file_id = f"{manifest['pc_identity']['source_host_id']}/container_audit/container_audit_events/{row.relative_path}"
    receipt = {
        "request_id": "request-incomplete-committed",
        "upload_id": "request-incomplete-committed",
        "client_batch_id": row.relay_id,
        "server_source_file_id": server_source_file_id,
        "committed": True,
        "status": "accepted",
        "retryable": False,
        "next_retry_after": None,
        "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
    }
    for key, value in receipt_patch.items():
        if value == "__DELETE__":
            receipt.pop(key, None)
        else:
            receipt[key] = value
    session = FakeSession(FakeResponse(200, receipt))

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.committed is True
    assert result.error_code == expected_error_code
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, receipt_json FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert current["last_error_code"] == expected_error_code
    assert json.loads(current["receipt_json"])["request_id"] == "request-incomplete-committed"


def test_drain_moves_2xx_invalid_receipt_to_operator_review(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    session = FakeSession(InvalidJsonResponse(200))

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.committed is True
    assert result.error_code == "producer_receipt_invalid"
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, receipt_json, upload_status_path FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert current["last_error_code"] == "producer_receipt_invalid"
    receipt = json.loads(current["receipt_json"])
    assert receipt["client_batch_id"] == row.relay_id
    assert receipt["_local_upload_result_committed"] is True
    assert receipt["_local_upload_result_error_code"] == "producer_receipt_invalid"
    assert Path(current["upload_status_path"]).is_file()


def test_drain_moves_2xx_string_committed_receipt_to_operator_review(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    server_source_file_id = f"{manifest['pc_identity']['source_host_id']}/container_audit/container_audit_events/{row.relative_path}"
    session = FakeSession(
        FakeResponse(
            200,
            {
                "request_id": "request-string-committed",
                "client_batch_id": row.relay_id,
                "server_source_file_id": server_source_file_id,
                "committed": "false",
                "status": "accepted",
                "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
            },
        )
    )

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.committed is True
    assert result.error_code == "producer_receipt_invalid"
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, upload_status_path FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert current["last_error_code"] == "producer_receipt_invalid"
    assert Path(current["upload_status_path"]).is_file()


def test_drain_preserves_non_2xx_committed_receipt_for_operator_review(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    server_source_file_id = f"{manifest['pc_identity']['source_host_id']}/container_audit/container_audit_events/{row.relative_path}"
    session = FakeSession(
        FakeResponse(
            409,
            {
                "request_id": "request-committed-conflict",
                "upload_id": "request-committed-conflict",
                "client_batch_id": row.relay_id,
                "server_source_file_id": server_source_file_id,
                "committed": True,
                "status": "accepted",
                "retryable": False,
                "next_retry_after": None,
                "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
            },
            headers={"Retry-After": "120"},
        )
    )

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.committed is True
    assert result.retryable is False
    assert result.retry_after_seconds is None
    assert result.status_code == 409
    assert result.error_code == "producer_committed_non_2xx"
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, receipt_json, upload_status_path, next_attempt_at FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert current["last_error_code"] == "producer_committed_non_2xx"
    assert current["next_attempt_at"] is None
    receipt = json.loads(current["receipt_json"])
    assert receipt["request_id"] == "request-committed-conflict"
    assert receipt["_local_upload_result_committed"] is True
    status_artifact = json.loads(Path(current["upload_status_path"]).read_text(encoding="utf-8"))
    assert status_artifact["retryable"] is False
    assert status_artifact["retry_after_seconds"] is None


def test_drain_treats_string_retryable_false_as_failed_permanent(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    session = FakeSession(
        FakeResponse(
            400,
            {
                "committed": False,
                "retryable": "false",
                "error": {"code": "bad_request", "message": "bad request"},
            },
        )
    )

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.committed is False
    assert result.retryable is False
    assert result.error_code == "bad_request"
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_FAILED_PERMANENT
    assert current["last_error_code"] == "bad_request"


def test_drain_missing_spooled_file_marks_failed_permanent_without_posting(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    Path(row.spooled_file_path).unlink()
    session = FakeSession(FakeResponse(200, {"committed": True}))

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.error_code == "spooled_file_missing"
    assert session.calls == []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, last_error_message, receipt_json FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_FAILED_PERMANENT
    assert current["last_error_code"] == "spooled_file_missing"
    assert "spooled file cannot be read" in current["last_error_message"]
    assert json.loads(current["receipt_json"]) == {"client_batch_id": row.relay_id}


def test_drain_spooled_file_digest_mismatch_records_relay_identity(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    Path(row.spooled_file_path).write_text("timestamp,worker_name,event,details\n", encoding="utf-8")
    session = FakeSession(FakeResponse(200, {"committed": True}))

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.error_code == "spooled_file_digest_mismatch"
    assert result.receipt == {"client_batch_id": row.relay_id}
    assert session.calls == []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, receipt_json FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_FAILED_PERMANENT
    assert current["last_error_code"] == "spooled_file_digest_mismatch"
    assert json.loads(current["receipt_json"]) == {"client_batch_id": row.relay_id}


def test_drain_invalid_relay_metadata_records_relay_identity(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    metadata = dict(row.metadata)
    metadata["client_batch_id"] = "relay-wrong"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE direct_sync_relay_batches SET metadata_json = ? WHERE relay_id = ?",
            (json.dumps(metadata, ensure_ascii=False, sort_keys=True), row.relay_id),
        )
        conn.commit()
    session = FakeSession(FakeResponse(200, {"committed": True}))

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.error_code == "relay_metadata_invalid"
    assert result.receipt == {"client_batch_id": row.relay_id}
    assert session.calls == []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, receipt_json FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert current["last_error_code"] == "relay_metadata_invalid"
    assert json.loads(current["receipt_json"]) == {"client_batch_id": row.relay_id}


def test_drain_corrupt_relay_metadata_goes_to_operator_review_without_rebuild(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE direct_sync_relay_batches SET metadata_json = ? WHERE relay_id = ?",
            ("{not-json", row.relay_id),
        )
        conn.commit()
    session = FakeSession(FakeResponse(200, {"committed": True}))

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.error_code == "relay_metadata_invalid"
    assert "metadata_json is invalid JSON" in result.error_message
    assert result.receipt == {"client_batch_id": row.relay_id}
    assert session.calls == []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, receipt_json FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert current["last_error_code"] == "relay_metadata_invalid"
    assert json.loads(current["receipt_json"]) == {"client_batch_id": row.relay_id}


def test_drain_rejects_non_integer_relay_metadata_byte_length_without_upload(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    metadata = dict(row.metadata)
    metadata["byte_length"] = float(row.byte_length)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE direct_sync_relay_batches SET metadata_json = ? WHERE relay_id = ?",
            (json.dumps(metadata, ensure_ascii=False, sort_keys=True), row.relay_id),
        )
        conn.commit()
    session = FakeSession(FakeResponse(200, {"committed": True}))

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.error_code == "relay_metadata_invalid"
    assert "byte_length" in result.error_message
    assert session.calls == []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, receipt_json FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert current["last_error_code"] == "relay_metadata_invalid"
    assert json.loads(current["receipt_json"]) == {"client_batch_id": row.relay_id}


def test_drain_rejects_changed_producer_credentials_without_upload(tmp_path):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    changed_credentials = ProducerCredentials(
        producer_id=credentials.producer_id,
        key_id="key-container-rotated",
        secret=credentials.secret,
        endpoint_url=credentials.endpoint_url,
    )
    session = FakeSession(FakeResponse(200, {"committed": True}))

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=changed_credentials,
        session=session,
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.error_code == "relay_credentials_changed"
    assert session.calls == []
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, last_error_code, receipt_json FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert current["last_error_code"] == "relay_credentials_changed"
    assert json.loads(current["receipt_json"]) == {"client_batch_id": row.relay_id}


def test_drain_upload_exception_after_claim_releases_lease_to_operator_review(tmp_path, monkeypatch):
    _manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )

    def fake_upload(*args, **kwargs):
        raise RuntimeError("runtime-secret C:\\sensitive\\path")

    monkeypatch.setattr(direct_sync_push, "upload_source_file", fake_upload)

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        worker_id="worker-1",
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.committed is False
    assert result.retryable is False
    assert result.error_code == "upload_unhandled_exception"
    assert "RuntimeError" in result.error_message
    assert "runtime-secret" not in result.error_message
    assert "sensitive" not in result.error_message
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            """
            SELECT status, lease_owner, lease_expires_at, attempt_count, last_error_code, last_error_message, receipt_json
            FROM direct_sync_relay_batches
            WHERE relay_id = ?
            """,
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_OPERATOR_REVIEW
    assert current["lease_owner"] is None
    assert current["lease_expires_at"] is None
    assert current["attempt_count"] == 1
    assert current["last_error_code"] == "upload_unhandled_exception"
    assert current["last_error_message"] == result.error_message
    assert "runtime-secret" not in current["last_error_message"]
    assert json.loads(current["receipt_json"]) == {"client_batch_id": row.relay_id}


def test_drain_acks_committed_upload_when_status_artifact_write_fails(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    status_dir = tmp_path / "status-is-a-file"
    status_dir.write_text("not a directory", encoding="utf-8")
    server_source_file_id = f"{manifest['pc_identity']['source_host_id']}/container_audit/container_audit_events/{row.relative_path}"
    session = FakeSession(
        FakeResponse(
            200,
                {
                    "request_id": "request-relay-acked",
                    "upload_id": "request-relay-acked",
                    "client_batch_id": row.relay_id,
                    "server_source_file_id": server_source_file_id,
                    "committed": True,
                "status": "accepted",
                "retryable": False,
                "next_retry_after": None,
                "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
            },
        )
    )

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=status_dir,
    )

    assert result is not None
    assert result.success is True
    assert result.status_path == ""
    assert result.error_code == "upload_status_write_failed"
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            """
            SELECT status, upload_status_path, last_error_code, last_error_message, receipt_json
            FROM direct_sync_relay_batches
            WHERE relay_id = ?
            """,
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_ACKED
    assert current["upload_status_path"] == ""
    assert current["last_error_code"] == "upload_status_write_failed"
    assert "upload status artifact write failed" in current["last_error_message"]
    assert json.loads(current["receipt_json"])["request_id"] == "request-relay-acked"
    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_ACKED] == 1


def test_drain_status_write_failure_preserves_retryable_producer_error(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    status_dir = tmp_path / "status-is-a-file"
    status_dir.write_text("not a directory", encoding="utf-8")
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    session = FakeSession(
        FakeResponse(
            503,
            {
                "committed": False,
                "retryable": True,
                "error": {"code": "temporary_unavailable", "message": "try later"},
            },
        )
    )

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=session,
        status_dir=status_dir,
        retry_base_seconds=1,
        now="2099-01-01T00:00:00Z",
    )

    assert result is not None
    assert result.status_path == ""
    assert result.error_code == "temporary_unavailable"
    assert result.error_message == "try later"
    assert result.receipt["_local_upload_status_write_error_code"] == "upload_status_write_failed"
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            """
            SELECT status, upload_status_path, last_error_code, last_error_message, receipt_json
            FROM direct_sync_relay_batches
            WHERE relay_id = ?
            """,
            (row.relay_id,),
        ).fetchone()
    receipt = json.loads(current["receipt_json"])
    assert current["status"] == RELAY_STATUS_RETRY_WAIT
    assert current["upload_status_path"] == ""
    assert current["last_error_code"] == "temporary_unavailable"
    assert current["last_error_message"] == "try later"
    assert receipt["_local_upload_status_write_error_code"] == "upload_status_write_failed"
    assert "FileExistsError" in receipt["_local_upload_status_write_error_message"]


def test_drain_does_not_ack_when_lease_changes_before_status_update(tmp_path, monkeypatch):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    server_source_file_id = f"{manifest['pc_identity']['source_host_id']}/container_audit/container_audit_events/{row.relative_path}"

    def fake_upload(plan, _credentials, *, session=None, timeout=30, status_dir="", status_context=None):
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                """
                UPDATE direct_sync_relay_batches
                SET lease_owner = ?, attempt_count = attempt_count + 1
                WHERE relay_id = ?
                """,
                ("worker-2", plan.metadata["client_batch_id"]),
            )
            conn.commit()
        return direct_sync_push.UploadResult(
            success=True,
            status_code=200,
            committed=True,
            retryable=False,
            receipt={
                "request_id": "request-late-ack",
                "client_batch_id": plan.metadata["client_batch_id"],
                "server_source_file_id": server_source_file_id,
            },
            status_path=str(Path(status_dir) / "late-ack-status.json"),
        )

    monkeypatch.setattr(direct_sync_push, "upload_source_file", fake_upload)

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        worker_id="worker-1",
        status_dir=tmp_path / "status",
    )

    assert result is not None
    assert result.success is False
    assert result.committed is True
    assert result.status_code == 200
    assert result.relay_id == row.relay_id
    assert result.status_path.endswith("late-ack-status.json")
    assert result.receipt["request_id"] == "request-late-ack"
    assert result.receipt["client_batch_id"] == row.relay_id
    assert result.receipt["_local_status_update_error_code"] == "relay_status_update_conflict"
    assert result.error_code == "relay_status_update_conflict"
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        current = conn.execute(
            "SELECT status, lease_owner, attempt_count, receipt_json FROM direct_sync_relay_batches WHERE relay_id = ?",
            (row.relay_id,),
        ).fetchone()
    assert current["status"] == RELAY_STATUS_LEASED
    assert current["lease_owner"] == "worker-2"
    assert current["attempt_count"] == 2
    assert current["receipt_json"] is None


def test_drain_extends_lease_beyond_long_upload_timeout(tmp_path, monkeypatch):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    observed = {}
    started_at = datetime.now(timezone.utc)
    server_source_file_id = f"{manifest['pc_identity']['source_host_id']}/container_audit/container_audit_events/{row.relative_path}"

    def fake_upload(plan, _credentials, *, session=None, timeout=30, status_dir="", status_context=None):
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            current = conn.execute(
                "SELECT lease_expires_at FROM direct_sync_relay_batches WHERE relay_id = ?",
                (plan.metadata["client_batch_id"],),
            ).fetchone()
        observed["lease_expires_at"] = current["lease_expires_at"]
        return direct_sync_push.UploadResult(
            success=True,
            status_code=200,
            committed=True,
            retryable=False,
            receipt={
                "request_id": "request-long-timeout",
                "client_batch_id": plan.metadata["client_batch_id"],
                "server_source_file_id": server_source_file_id,
            },
        )

    monkeypatch.setattr(direct_sync_push, "upload_source_file", fake_upload)

    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        worker_id="worker-1",
        status_dir=tmp_path / "status",
        timeout=600,
    )

    assert result is not None
    assert result.success is True
    lease_expires_at = datetime.fromisoformat(observed["lease_expires_at"].replace("Z", "+00:00"))
    assert (lease_expires_at - started_at).total_seconds() >= 600


def test_acked_relay_retention_report_is_read_only_and_candidates_require_full_evidence(tmp_path):
    manifest, manifest_path = make_manifest(tmp_path)
    csv_path = write_csv(tmp_path)
    credentials = make_credentials()
    db_path = tmp_path / "relay.sqlite3"
    row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=tmp_path / "spool",
        source_file_path=csv_path,
        producer_manifest_path=manifest_path,
        credentials=credentials,
    )
    server_source_file_id = f"{manifest['pc_identity']['source_host_id']}/container_audit/container_audit_events/{row.relative_path}"
    receipt = {
        "request_id": "request-retention",
        "upload_id": "request-retention",
        "client_batch_id": row.relay_id,
        "server_source_file_id": server_source_file_id,
        "committed": True,
        "status": "accepted",
        "retryable": False,
        "next_retry_after": None,
        "totals": {"inserted": 1, "replayed": 0, "quarantined": 0, "errors": 0},
    }
    result = drain_one_relay_batch(
        db_path=db_path,
        credentials=credentials,
        session=FakeSession(FakeResponse(200, receipt)),
        status_dir=tmp_path / "status",
    )

    assert result.success is True
    retention = relay_queue_status(db_path)["acked_retention"]
    assert retention["status"] == "RETAIN_REQUIRED"
    assert retention["cleanup_safe"] is False
    assert retention["acked_row_delete_allowed"] is False
    assert retention["acked_spool_delete_allowed"] is False
    assert retention["acked_upload_status_delete_allowed"] is False
    assert retention["acked_count"] == 1
    assert retention["acked_spool_total_bytes"] == Path(row.spooled_file_path).stat().st_size
    assert retention["missing_acked_spool_count"] == 0
    assert retention["missing_acked_upload_status_count"] == 0

    candidates = acked_relay_retention_candidates(db_path)
    assert len(candidates) == 1
    assert candidates[0].relay_id == row.relay_id
    assert candidates[0].receipt == receipt
    assert len(
        acked_relay_retention_candidates(
            db_path,
            spool_roots=[tmp_path / "spool"],
            artifact_roots=[tmp_path / "status"],
        )
    ) == 1
    assert acked_relay_retention_candidates(db_path, spool_roots=[tmp_path / "wrong-spool"]) == ()
    assert acked_relay_retention_candidates(db_path, artifact_roots=[tmp_path / "wrong-status"]) == ()

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE direct_sync_relay_batches SET receipt_json = ? WHERE relay_id = ?",
            (json.dumps({"committed": True, "client_batch_id": row.relay_id}), row.relay_id),
        )
        conn.commit()
    assert acked_relay_retention_candidates(db_path) == ()

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE direct_sync_relay_batches SET receipt_json = ? WHERE relay_id = ?",
            (json.dumps(receipt, ensure_ascii=False, sort_keys=True), row.relay_id),
        )
        conn.commit()
    status_receipt_mismatch = dict(receipt)
    status_receipt_mismatch["request_id"] = "request-wrong-status-artifact"
    Path(candidates[0].upload_status_path).write_text(
        json.dumps(
            {
                "success": True,
                "committed": True,
                "retryable": False,
                "receipt": status_receipt_mismatch,
                "metadata": candidates[0].metadata,
                "source_file_path": candidates[0].spooled_file_path,
            }
        ),
        encoding="utf-8",
    )
    assert acked_relay_retention_candidates(db_path) == ()

    Path(candidates[0].upload_status_path).write_text(
        json.dumps({"success": True, "committed": True, "receipt": receipt, "metadata": {"relative_path": "wrong"}}),
        encoding="utf-8",
    )
    assert acked_relay_retention_candidates(db_path) == ()


def test_relay_status_and_retention_candidates_do_not_create_missing_db(tmp_path):
    db_path = tmp_path / "missing-relay.sqlite3"

    status = relay_queue_status(db_path)

    assert status["counts"] == {}
    assert status["acked_retention"]["read_only"] is True
    assert status["acked_retention"]["cleanup_safe"] is False
    assert acked_relay_retention_candidates(db_path) == ()
    assert not db_path.exists()
