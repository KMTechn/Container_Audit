import csv
import json

import event_payloads
import replacement_log_lookup
from event_contracts import stable_hash


def test_replacement_log_file_paths_prefers_current_and_legacy_prefixes(tmp_path):
    current = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    legacy = tmp_path / "검사작업이벤트로그_홍길동_20260622.csv"
    ignored = tmp_path / "other_20260624.csv"
    current.write_text("", encoding="utf-8")
    legacy.write_text("", encoding="utf-8")
    ignored.write_text("", encoding="utf-8")

    paths = replacement_log_lookup.replacement_log_file_paths(tmp_path)

    assert paths == [str(current), str(legacy)]


def test_replacement_log_file_paths_sorts_by_date_across_prefixes(tmp_path):
    current_older = tmp_path / "이적작업이벤트로그_홍길동_20260622.csv"
    legacy_newer = tmp_path / "검사작업이벤트로그_홍길동_20260623.csv"
    current_same_day = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    current_older.write_text("", encoding="utf-8")
    legacy_newer.write_text("", encoding="utf-8")
    current_same_day.write_text("", encoding="utf-8")

    paths = replacement_log_lookup.replacement_log_file_paths(tmp_path)

    assert paths == [str(current_same_day), str(legacy_newer), str(current_older)]


def test_replacement_log_file_paths_ignores_backup_temp_and_directories(tmp_path):
    current = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    backup = tmp_path / "이적작업이벤트로그_홍길동_20260624.csv.bak"
    temp = tmp_path / "검사작업이벤트로그_홍길동_20260625.csv.tmp"
    directory = tmp_path / "이적작업이벤트로그_홍길동_20260626.csv"
    current.write_text("", encoding="utf-8")
    backup.write_text("", encoding="utf-8")
    temp.write_text("", encoding="utf-8")
    directory.mkdir()

    paths = replacement_log_lookup.replacement_log_file_paths(tmp_path)

    assert paths == [str(current)]


def test_find_replacement_source_entry_returns_physical_row_identity(tmp_path):
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    with log_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:00:00",
                "worker_name": "홍길동",
                "event": "SCAN_OK",
                "details": "{}",
            }
        )
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:01:00",
                "worker_name": "홍길동",
                "event": "TRAY_COMPLETE",
                "details": json.dumps(
                    {
                        "master_label_code": '{"QT":"60","CLC":"AAA2270730100"}',
                        "item_code": "AAA2270730100",
                        "scan_count": 1,
                        "tray_capacity": 60,
                        "product_barcodes": ["AAA2270730100-001"],
                    },
                    ensure_ascii=False,
                ),
            }
        )

    found = replacement_log_lookup.find_replacement_source_entry(
        log_path,
        '{"CLC":"AAA2270730100","QT":"60"}',
        stable_hash_func=stable_hash,
    )

    assert found is not None
    assert found["found_row_index"] == 3
    assert found["found_source_byte_offset"] and found["found_source_byte_offset"] > 0
    assert found["original_details"]["product_barcodes"] == ["AAA2270730100-001"]
    assert found["found_row_hash"] == stable_hash(
        {
            "source_file_id": log_path.name,
            "source_row_number": found["found_row_index"],
            "source_byte_offset": found["found_source_byte_offset"],
            "row": {
                "timestamp": "2026-06-23T09:01:00",
                "worker_name": "홍길동",
                "event": "TRAY_COMPLETE",
                "details": json.dumps(
                    {
                        "master_label_code": '{"QT":"60","CLC":"AAA2270730100"}',
                        "item_code": "AAA2270730100",
                        "scan_count": 1,
                        "tray_capacity": 60,
                        "product_barcodes": ["AAA2270730100-001"],
                    },
                    ensure_ascii=False,
                ),
            },
        }
    )


def test_find_replacement_source_entry_skips_malformed_matching_completion_row(tmp_path):
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    old_label = "PHS=1|CLC=AAA2270730100|QT=2"
    malformed_details = {
        "master_label_code": old_label,
        "item_code": "AAA2270730100",
        "scan_count": 2,
        "tray_capacity": 2,
        "product_barcodes": ["AAA2270730100-001"],
    }
    valid_details = {
        "master_label_code": old_label,
        "item_code": "AAA2270730100",
        "scan_count": 2,
        "tray_capacity": 2,
        "product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
        "scanned_product_barcodes": ["AAA2270730100-001", "AAA2270730100-002"],
    }
    with log_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:01:00",
                "worker_name": "홍길동",
                "event": "TRAY_COMPLETE",
                "details": json.dumps(malformed_details, ensure_ascii=False),
            }
        )
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:05:00",
                "worker_name": "홍길동",
                "event": "TRAY_COMPLETE",
                "details": json.dumps(valid_details, ensure_ascii=False),
            }
        )

    found = replacement_log_lookup.find_replacement_source_entry(
        log_path,
        old_label,
        stable_hash_func=stable_hash,
    )

    assert found is not None
    assert found["found_row_index"] == 3
    assert found["original_details"]["product_barcodes"] == ["AAA2270730100-001", "AAA2270730100-002"]


def test_find_replacement_source_entry_uses_unsuperseded_replacement_projection(tmp_path):
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    old_label = "PHS=1|CLC=AAA2270730100|QT=1"
    new_label = "PHS=1|CLC=AAA2270730100|QT=1|LOT=NEW"
    old_details = {
        "master_label_code": old_label,
        "item_code": "AAA2270730100",
        "product_barcodes": ["AAA2270730100-001"],
        "scanned_product_barcodes": ["AAA2270730100-001"],
        "scan_count": 1,
        "tray_capacity": 1,
    }
    old_details_text = json.dumps(old_details, ensure_ascii=False)
    old_row = {
        "timestamp": "2026-06-23T09:01:00",
        "worker_name": "홍길동",
        "event": "TRAY_COMPLETE",
        "details": old_details_text,
    }
    with log_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(old_row)

    raw_lines = log_path.read_bytes().splitlines(keepends=True)
    old_row_offset = len(raw_lines[0])
    old_row_hash = stable_hash(
        {
            "source_file_id": log_path.name,
            "source_row_number": 2,
            "source_byte_offset": old_row_offset,
            "row": old_row,
        }
    )
    replacement_detail = event_payloads.build_master_label_replacement_detail(
        original_details=old_details,
        old_label=old_label,
        new_label=new_label,
        source_system="container_audit",
        source_transport_or_dataset="legacy_transfer_csv",
        source_file_id=log_path.name,
        source_row_number=2,
        source_byte_offset=old_row_offset,
        operator="홍길동",
        stable_hash_func=stable_hash,
        old_row_hash=old_row_hash,
        old_qty=1,
        new_qty=1,
    )
    with log_path.open("a", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:05:00",
                "worker_name": "홍길동",
                "event": "MASTER_LABEL_REPLACEMENT_APPLIED",
                "details": json.dumps(replacement_detail, ensure_ascii=False),
            }
        )

    old_found = replacement_log_lookup.find_replacement_source_entry(
        log_path,
        old_label,
        stable_hash_func=stable_hash,
    )
    new_found = replacement_log_lookup.find_replacement_source_entry(
        log_path,
        new_label,
        stable_hash_func=stable_hash,
    )

    assert old_found is None
    assert new_found is not None
    assert new_found["found_row_hash"] == replacement_detail["new_row_hash"]
    assert new_found["found_source_file_id"] == log_path.name
    assert new_found["found_row_index"] == 2
    assert new_found["found_source_byte_offset"] == old_row_offset
    assert new_found["original_details"]["master_label_code"] == new_label
    assert new_found["original_details"]["product_barcodes"] == ["AAA2270730100-001"]


def test_replacement_supersede_hash_must_match_source_label_and_payload(tmp_path):
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    label_a = "PHS=1|CLC=AAA2270730100|QT=1|LOT=A"
    label_b = "PHS=1|CLC=AAA2270730100|QT=1|LOT=B"
    new_label = "PHS=1|CLC=AAA2270730100|QT=1|LOT=A-NEW"
    details_a = {
        "master_label_code": label_a,
        "item_code": "AAA2270730100",
        "product_barcodes": ["AAA2270730100-A01"],
        "scanned_product_barcodes": ["AAA2270730100-A01"],
        "scan_count": 1,
        "tray_capacity": 1,
    }
    details_b = {
        "master_label_code": label_b,
        "item_code": "AAA2270730100",
        "product_barcodes": ["AAA2270730100-B01"],
        "scanned_product_barcodes": ["AAA2270730100-B01"],
        "scan_count": 1,
        "tray_capacity": 1,
    }
    row_a = {
        "timestamp": "2026-06-23T09:01:00",
        "worker_name": "홍길동",
        "event": "TRAY_COMPLETE",
        "details": json.dumps(details_a, ensure_ascii=False),
    }
    row_b = {
        "timestamp": "2026-06-23T09:02:00",
        "worker_name": "홍길동",
        "event": "TRAY_COMPLETE",
        "details": json.dumps(details_b, ensure_ascii=False),
    }
    with log_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(row_a)
        writer.writerow(row_b)

    raw_lines = log_path.read_bytes().splitlines(keepends=True)
    row_a_offset = len(raw_lines[0])
    row_b_offset = row_a_offset + len(raw_lines[1])
    row_b_hash = stable_hash(
        {
            "source_file_id": log_path.name,
            "source_row_number": 3,
            "source_byte_offset": row_b_offset,
            "row": row_b,
        }
    )
    replacement_detail = event_payloads.build_master_label_replacement_detail(
        original_details=details_a,
        old_label=label_a,
        new_label=new_label,
        source_system="container_audit",
        source_transport_or_dataset="legacy_transfer_csv",
        source_file_id=log_path.name,
        source_row_number=2,
        source_byte_offset=row_a_offset,
        operator="홍길동",
        stable_hash_func=stable_hash,
        old_row_hash=row_b_hash,
        old_qty=1,
        new_qty=1,
    )
    with log_path.open("a", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:05:00",
                "worker_name": "홍길동",
                "event": "MASTER_LABEL_REPLACEMENT_APPLIED",
                "details": json.dumps(replacement_detail, ensure_ascii=False),
            }
        )

    superseded = replacement_log_lookup.collect_replacement_superseded_hashes(
        [log_path],
        stable_hash_func=stable_hash,
    )
    found_b = replacement_log_lookup.find_replacement_source_entry(
        log_path,
        label_b,
        stable_hash_func=stable_hash,
        superseded_hashes=superseded,
    )

    assert row_b_hash not in superseded
    assert found_b is not None
    assert found_b["found_row_hash"] == row_b_hash


def test_find_replacement_source_entry_ignores_malformed_replacement_supersede_hash(tmp_path):
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    old_label = "PHS=1|CLC=AAA2270730100|QT=1"
    old_details = {
        "master_label_code": old_label,
        "item_code": "AAA2270730100",
        "product_barcodes": ["AAA2270730100-001"],
        "scanned_product_barcodes": ["AAA2270730100-001"],
        "scan_count": 1,
        "tray_capacity": 1,
    }
    old_row = {
        "timestamp": "2026-06-23T09:01:00",
        "worker_name": "홍길동",
        "event": "TRAY_COMPLETE",
        "details": json.dumps(old_details, ensure_ascii=False),
    }
    with log_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(old_row)

    raw_lines = log_path.read_bytes().splitlines(keepends=True)
    old_row_offset = len(raw_lines[0])
    old_row_hash = stable_hash(
        {
            "source_file_id": log_path.name,
            "source_row_number": 2,
            "source_byte_offset": old_row_offset,
            "row": old_row,
        }
    )
    with log_path.open("a", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:05:00",
                "worker_name": "홍길동",
                "event": "MASTER_LABEL_REPLACEMENT_APPLIED",
                "details": json.dumps({"old_row_hash": old_row_hash}, ensure_ascii=False),
            }
        )

    superseded = replacement_log_lookup.collect_replacement_superseded_hashes(
        [log_path],
        stable_hash_func=stable_hash,
    )
    found = replacement_log_lookup.find_replacement_source_entry(
        log_path,
        old_label,
        stable_hash_func=stable_hash,
        superseded_hashes=superseded,
    )

    assert old_row_hash not in superseded
    assert found is not None
    assert found["found_row_hash"] == old_row_hash


def test_find_replacement_source_entry_rejects_tampered_projection_hash(tmp_path):
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    old_label = "PHS=1|CLC=AAA2270730100|QT=1"
    new_label = "PHS=1|CLC=AAA2270730100|QT=1|LOT=NEW"
    old_details = {
        "master_label_code": old_label,
        "item_code": "AAA2270730100",
        "product_barcodes": ["AAA2270730100-001"],
        "scanned_product_barcodes": ["AAA2270730100-001"],
        "scan_count": 1,
        "tray_capacity": 1,
    }
    replacement_detail = event_payloads.build_master_label_replacement_detail(
        original_details=old_details,
        old_label=old_label,
        new_label=new_label,
        source_system="container_audit",
        source_transport_or_dataset="legacy_transfer_csv",
        source_file_id=log_path.name,
        source_row_number=2,
        source_byte_offset=54,
        operator="홍길동",
        stable_hash_func=stable_hash,
        old_row_hash="old-row-hash",
        old_qty=1,
        new_qty=1,
    )
    replacement_detail["corrected_completion_projection"]["product_barcodes"] = ["AAA2270730100-999"]
    replacement_detail["corrected_completion_projection"]["scanned_product_barcodes"] = ["AAA2270730100-999"]
    with log_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:05:00",
                "worker_name": "홍길동",
                "event": "MASTER_LABEL_REPLACEMENT_APPLIED",
                "details": json.dumps(replacement_detail, ensure_ascii=False),
            }
        )

    found = replacement_log_lookup.find_replacement_source_entry(
        log_path,
        new_label,
        stable_hash_func=stable_hash,
    )
    superseded = replacement_log_lookup.collect_replacement_superseded_hashes(
        [log_path],
        stable_hash_func=stable_hash,
    )

    assert found is None
    assert replacement_detail["old_row_hash"] not in superseded


def test_find_replacement_source_entry_rejects_fake_projection_row_hash(tmp_path):
    log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    old_label = "PHS=1|CLC=AAA2270730100|QT=1"
    new_label = "PHS=1|CLC=AAA2270730100|QT=1|LOT=NEW"
    old_details = {
        "master_label_code": old_label,
        "item_code": "AAA2270730100",
        "product_barcodes": ["AAA2270730100-001"],
        "scanned_product_barcodes": ["AAA2270730100-001"],
        "scan_count": 1,
        "tray_capacity": 1,
    }
    replacement_detail = event_payloads.build_master_label_replacement_detail(
        original_details=old_details,
        old_label=old_label,
        new_label=new_label,
        source_system="container_audit",
        source_transport_or_dataset="legacy_transfer_csv",
        source_file_id=log_path.name,
        source_row_number=2,
        source_byte_offset=54,
        operator="홍길동",
        stable_hash_func=stable_hash,
        old_row_hash="old-row-hash",
        old_qty=1,
        new_qty=1,
    )
    replacement_detail["new_row_hash"] = "not-derived"
    with log_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:05:00",
                "worker_name": "홍길동",
                "event": "MASTER_LABEL_REPLACEMENT_APPLIED",
                "details": json.dumps(replacement_detail, ensure_ascii=False),
            }
        )

    found = replacement_log_lookup.find_replacement_source_entry(
        log_path,
        new_label,
        stable_hash_func=stable_hash,
    )
    superseded = replacement_log_lookup.collect_replacement_superseded_hashes(
        [log_path],
        stable_hash_func=stable_hash,
    )

    assert found is None
    assert replacement_detail["old_row_hash"] not in superseded


def test_find_replacement_source_entry_preserves_projection_original_source_file_id(tmp_path):
    original_log_name = "검사작업이벤트로그_홍길동_20260622.csv"
    correction_log_path = tmp_path / "이적작업이벤트로그_홍길동_20260623.csv"
    old_label = "PHS=1|CLC=AAA2270730100|QT=1"
    new_label = "PHS=1|CLC=AAA2270730100|QT=1|LOT=NEW"
    old_details = {
        "master_label_code": old_label,
        "item_code": "AAA2270730100",
        "product_barcodes": ["AAA2270730100-001"],
        "scanned_product_barcodes": ["AAA2270730100-001"],
        "scan_count": 1,
        "tray_capacity": 1,
    }
    original_row = {
        "timestamp": "2026-06-22T09:01:00",
        "worker_name": "홍길동",
        "event": "TRAY_COMPLETE",
        "details": json.dumps(old_details, ensure_ascii=False),
    }
    old_row_hash = stable_hash(
        {
            "source_file_id": original_log_name,
            "source_row_number": 2,
            "source_byte_offset": 54,
            "row": original_row,
        }
    )
    replacement_detail = event_payloads.build_master_label_replacement_detail(
        original_details=old_details,
        old_label=old_label,
        new_label=new_label,
        source_system="container_audit",
        source_transport_or_dataset="legacy_transfer_csv",
        source_file_id=original_log_name,
        source_row_number=2,
        source_byte_offset=54,
        operator="홍길동",
        stable_hash_func=stable_hash,
        old_row_hash=old_row_hash,
        old_qty=1,
        new_qty=1,
    )
    with correction_log_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=["timestamp", "worker_name", "event", "details"])
        writer.writeheader()
        writer.writerow(
            {
                "timestamp": "2026-06-23T09:05:00",
                "worker_name": "홍길동",
                "event": "MASTER_LABEL_REPLACEMENT_APPLIED",
                "details": json.dumps(replacement_detail, ensure_ascii=False),
            }
        )

    found = replacement_log_lookup.find_replacement_source_entry(
        correction_log_path,
        new_label,
        stable_hash_func=stable_hash,
    )

    assert found is not None
    assert found["found_log_file"] == str(correction_log_path)
    assert found["found_source_file_id"] == original_log_name
    assert found["found_row_index"] == 2
    assert found["found_source_byte_offset"] == 54
