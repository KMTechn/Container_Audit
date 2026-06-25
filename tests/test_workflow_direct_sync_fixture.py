import csv
import datetime
import json
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from Container_Audit import TraySession
from direct_sync_push import (
    ProducerCredentials,
    RELAY_STATUS_PENDING,
    build_source_file_plan,
    enqueue_source_file_for_relay,
    relay_queue_status,
    signed_headers,
)
from event_contracts import plan_b_event_detail
from event_log_store import append_event_log_entry
from event_payloads import build_tray_complete_detail


def _make_manifest(
    tmp_path,
    *,
    pc_id="CONTAINER-PC01",
    source_host_id="container-host-1",
    producer_install_id="install-container-1",
):
    manifest = {
        "schema_version": "producer-onboarding-manifest-v1",
        "pc_identity": {
            "pc_id": pc_id,
            "source_host_id": source_host_id,
            "producer_install_id": producer_install_id,
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
    return path


def _credentials(*, producer_id="producer-container", key_id="key-container", secret="container-secret"):
    return ProducerCredentials(
        producer_id=producer_id,
        key_id=key_id,
        secret=secret,
        endpoint_url="https://worker.example.invalid/api/producer-ingest/v1/source-file",
    )


def _write_completion_event_log(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    completion_detail = plan_b_event_detail(
        "TRAY_COMPLETE",
        {
            "master_label_code": "PHS=1|CLC=AAA2270730100|QT=2",
            "item_code": "AAA2270730100",
            "item_name": "fixture item",
            "scan_count": 2,
            "tray_capacity": 2,
            "scanned_product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
            "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
            "quantity_basis": "PRODUCT_BARCODE",
            "confidence": "BARCODE",
            "qty_uom": "piece",
        },
        source_system="container_audit",
        source_transport_or_dataset="legacy_transfer_csv",
    )
    append_event_log_entry(
        str(path),
        {
            "timestamp": "2026-06-24T09:02:00",
            "worker_name": "홍길동",
            "event": "TRAY_COMPLETE",
            "details": json.dumps(completion_detail, ensure_ascii=False, allow_nan=False),
        },
        durable=True,
    )
    return path


def _server_source_file_id(metadata):
    return (
        f"{metadata['source_host_id']}/"
        f"{metadata['producer_role']}/"
        f"{metadata['stream_name']}/"
        f"{metadata['relative_path']}"
    )


def test_tray_complete_payload_round_trips_to_direct_sync_source_plan(tmp_path):
    start_time = datetime.datetime(2026, 6, 24, 9, 0, 0)
    tray = TraySession(
        master_label_code="PHS=1|CLC=AAA2270730100|QT=2",
        item_code="AAA2270730100",
        item_name="fixture item",
        item_spec="fixture spec",
        scanned_barcodes=["AAA2270730100-001", "AAA2270730100-002"],
        scan_times=[
            start_time + datetime.timedelta(seconds=10),
            start_time + datetime.timedelta(seconds=20),
        ],
        tray_size=2,
        start_time=start_time,
        stopwatch_seconds=120.0,
    )
    completion_detail = build_tray_complete_detail(
        tray,
        master_label_fields={"PHS": "1", "CLC": "AAA2270730100", "QT": "2"},
        end_time=start_time + datetime.timedelta(seconds=120),
    )
    enriched_detail = plan_b_event_detail(
        "TRAY_COMPLETE",
        completion_detail,
        source_system="container_audit",
        source_transport_or_dataset="legacy_transfer_csv",
    )

    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260624.csv"
    append_event_log_entry(
        str(log_path),
        {
            "timestamp": "2026-06-24T09:02:00",
            "worker_name": "홍길동",
            "event": "TRAY_COMPLETE",
            "details": json.dumps(enriched_detail, ensure_ascii=False, allow_nan=False),
        },
        durable=True,
    )

    plan = build_source_file_plan(
        source_file_path=log_path,
        producer_manifest_path=_make_manifest(tmp_path),
        credentials=_credentials(),
    )
    headers = signed_headers(_credentials(), plan.metadata, timestamp="2026-06-24T00:00:00Z", nonce="fixed")

    assert plan.metadata["source_system"] == "container_audit"
    assert plan.metadata["source_transport"] == "legacy_transfer_csv"
    assert plan.metadata["stream_name"] == "container_audit_events"
    assert plan.metadata["row_count"] == 1
    assert plan.metadata["first_row_number"] == 2
    assert plan.metadata["last_row_number"] == 2
    assert plan.metadata["relative_path"].startswith("legacy_csv/")
    assert headers["X-Producer-Id"] == "producer-container"
    assert headers["X-Producer-Key-Id"] == "key-container"
    assert headers["X-Producer-Signature"]

    with log_path.open("r", encoding="utf-8-sig", newline="") as handle:
        row = next(csv.DictReader(handle))
    details = json.loads(row["details"])
    assert row["event"] == "TRAY_COMPLETE"
    assert details["dispatch_key"] == "container_audit|legacy_transfer_csv|TRAY_COMPLETE"
    assert details["scan_count"] == 2
    assert details["tray_capacity"] == 2
    assert details["scanned_product_barcodes"] == ["AAA2270730100-001", "AAA2270730100-002"]
    assert details["product_barcodes"] == details["scanned_product_barcodes"]
    assert details["quantity_basis"] == "PRODUCT_BARCODE"
    assert details["confidence"] == "BARCODE"


def test_multi_pc_same_completion_file_uses_distinct_direct_sync_identity(tmp_path):
    file_name = "이적작업이벤트로그_홍길동_20260624.csv"
    pc1_dir = tmp_path / "pc1"
    pc2_dir = tmp_path / "pc2"
    pc1_log = _write_completion_event_log(pc1_dir / file_name)
    pc2_log = _write_completion_event_log(pc2_dir / file_name)
    assert pc1_log.read_bytes() == pc2_log.read_bytes()

    pc1_manifest = _make_manifest(
        pc1_dir,
        pc_id="CONTAINER-PC01",
        source_host_id="container-host-1",
        producer_install_id="install-container-1",
    )
    pc2_manifest = _make_manifest(
        pc2_dir,
        pc_id="CONTAINER-PC02",
        source_host_id="container-host-2",
        producer_install_id="install-container-2",
    )
    pc1_credentials = _credentials(
        producer_id="producer-container-pc1",
        key_id="key-container-pc1",
        secret="container-secret-pc1",
    )
    pc2_credentials = _credentials(
        producer_id="producer-container-pc2",
        key_id="key-container-pc2",
        secret="container-secret-pc2",
    )

    pc1_plan = build_source_file_plan(
        source_file_path=pc1_log,
        producer_manifest_path=pc1_manifest,
        credentials=pc1_credentials,
    )
    pc2_plan = build_source_file_plan(
        source_file_path=pc2_log,
        producer_manifest_path=pc2_manifest,
        credentials=pc2_credentials,
    )

    assert pc1_plan.metadata["relative_path"] == pc2_plan.metadata["relative_path"] == f"legacy_csv/{file_name}"
    assert pc1_plan.metadata["content_sha256"] == pc2_plan.metadata["content_sha256"]
    assert pc1_plan.metadata["row_count"] == pc2_plan.metadata["row_count"] == 1
    assert pc1_plan.metadata["source_host_id"] == "container-host-1"
    assert pc2_plan.metadata["source_host_id"] == "container-host-2"
    assert pc1_plan.metadata["producer_install_id"] == "install-container-1"
    assert pc2_plan.metadata["producer_install_id"] == "install-container-2"
    assert pc1_plan.metadata["idempotency_key"] != pc2_plan.metadata["idempotency_key"]
    assert pc1_plan.metadata["client_batch_id"] != pc2_plan.metadata["client_batch_id"]

    pc1_server_source_file_id = (
        f"{pc1_plan.metadata['source_host_id']}/"
        f"{pc1_plan.metadata['producer_role']}/"
        f"{pc1_plan.metadata['stream_name']}/"
        f"{pc1_plan.metadata['relative_path']}"
    )
    pc2_server_source_file_id = (
        f"{pc2_plan.metadata['source_host_id']}/"
        f"{pc2_plan.metadata['producer_role']}/"
        f"{pc2_plan.metadata['stream_name']}/"
        f"{pc2_plan.metadata['relative_path']}"
    )
    assert pc1_server_source_file_id != pc2_server_source_file_id

    pc1_headers = signed_headers(pc1_credentials, pc1_plan.metadata, timestamp="2026-06-24T00:00:00Z", nonce="fixed")
    pc2_headers = signed_headers(pc2_credentials, pc2_plan.metadata, timestamp="2026-06-24T00:00:00Z", nonce="fixed")
    assert pc1_headers["X-Producer-Id"] == "producer-container-pc1"
    assert pc2_headers["X-Producer-Id"] == "producer-container-pc2"
    assert pc1_headers["X-Producer-Signature"] != pc2_headers["X-Producer-Signature"]

    db_path = tmp_path / "relay.sqlite3"
    spool_dir = tmp_path / "spool"
    pc1_row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=pc1_log,
        producer_manifest_path=pc1_manifest,
        credentials=pc1_credentials,
        dedupe_existing=True,
    )
    pc2_row = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=pc2_log,
        producer_manifest_path=pc2_manifest,
        credentials=pc2_credentials,
        dedupe_existing=True,
    )
    pc1_duplicate = enqueue_source_file_for_relay(
        db_path=db_path,
        spool_dir=spool_dir,
        source_file_path=pc1_log,
        producer_manifest_path=pc1_manifest,
        credentials=pc1_credentials,
        dedupe_existing=True,
    )

    assert pc1_row.relay_id != pc2_row.relay_id
    assert pc1_duplicate.relay_id == pc1_row.relay_id
    assert pc1_duplicate.deduped_existing is True
    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_PENDING] == 2
    assert {pc1_row.metadata["source_host_id"], pc2_row.metadata["source_host_id"]} == {
        "container-host-1",
        "container-host-2",
    }


def test_virtual_twenty_pc_completion_enqueue_concurrency_preserves_distinct_identities(tmp_path):
    file_name = "이적작업이벤트로그_홍길동_20260624.csv"
    db_path = tmp_path / "relay.sqlite3"
    spool_dir = tmp_path / "spool"
    pc_count = 20

    scenarios = []
    for index in range(1, pc_count + 1):
        pc_dir = tmp_path / f"pc-{index:02d}"
        log_path = _write_completion_event_log(pc_dir / file_name)
        manifest_path = _make_manifest(
            pc_dir,
            pc_id=f"CONTAINER-PC{index:02d}",
            source_host_id=f"container-host-{index:02d}",
            producer_install_id=f"install-container-{index:02d}",
        )
        credentials = _credentials(
            producer_id=f"producer-container-{index:02d}",
            key_id=f"key-container-{index:02d}",
            secret=f"container-secret-{index:02d}",
        )
        scenarios.append((index, log_path, manifest_path, credentials))

    def enqueue(scenario):
        index, log_path, manifest_path, credentials = scenario
        row = enqueue_source_file_for_relay(
            db_path=db_path,
            spool_dir=spool_dir,
            source_file_path=log_path,
            producer_manifest_path=manifest_path,
            credentials=credentials,
            dedupe_existing=True,
        )
        return index, row

    submitted = list(scenarios)
    submitted.extend(scenarios[::4])
    with ThreadPoolExecutor(max_workers=pc_count) as executor:
        futures = [executor.submit(enqueue, scenario) for scenario in submitted]
        results = [future.result() for future in as_completed(futures)]

    rows_by_host = defaultdict(list)
    for _, row in results:
        rows_by_host[row.metadata["source_host_id"]].append(row)

    assert sorted(rows_by_host) == [f"container-host-{index:02d}" for index in range(1, pc_count + 1)]
    unique_rows = []
    for host_id, rows in rows_by_host.items():
        relay_ids = {row.relay_id for row in rows}
        assert len(relay_ids) == 1, host_id
        unique_rows.append(rows[0])
        if len(rows) > 1:
            assert any(row.deduped_existing for row in rows), host_id

    assert len(unique_rows) == pc_count
    assert relay_queue_status(db_path)["counts"][RELAY_STATUS_PENDING] == pc_count
    assert len(list(spool_dir.glob("*.csv"))) == pc_count
    assert len({row.relay_id for row in unique_rows}) == pc_count
    assert {row.relative_path for row in unique_rows} == {f"legacy_csv/{file_name}"}
    assert len({row.content_sha256 for row in unique_rows}) == 1
    assert len({row.metadata["idempotency_key"] for row in unique_rows}) == pc_count
    assert len({_server_source_file_id(row.metadata) for row in unique_rows}) == pc_count
    assert {row.metadata["producer_install_id"] for row in unique_rows} == {
        f"install-container-{index:02d}" for index in range(1, pc_count + 1)
    }
