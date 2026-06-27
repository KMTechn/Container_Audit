from types import SimpleNamespace

import pytest

import product_scan


def _tray(**overrides):
    data = {
        "item_code": "AAA2270730100",
        "scanned_barcodes": [],
        "tray_size": 2,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_decide_product_scan_rejects_short_product_barcode():
    decision = product_scan.decide_product_scan(_tray(), "AAA2270730100", item_code_length=13)

    assert decision.status == product_scan.SCAN_FORMAT_ERROR
    assert not decision.accepted
    assert decision.event_name == "SCAN_FAIL_FORMAT"
    assert decision.event_detail == {
        "raw_barcode": "AAA2270730100",
        "reason": "barcode_too_short",
        "item_code_length": 13,
    }


def test_decide_product_scan_rejects_missing_item_code_without_accepting_every_barcode():
    decision = product_scan.decide_product_scan(_tray(item_code=""), "ANY-BARCODE", item_code_length=3)

    assert decision.status == product_scan.SCAN_FORMAT_ERROR
    assert not decision.accepted
    assert decision.event_detail["reason"] == "missing_item_code"


def test_decide_product_scan_rejects_invalid_item_code_length_without_raising():
    decision = product_scan.decide_product_scan(_tray(), "AAA2270730100-001", item_code_length="bad")

    assert decision.status == product_scan.SCAN_FORMAT_ERROR
    assert not decision.accepted
    assert decision.event_detail == {
        "raw_barcode": "AAA2270730100-001",
        "reason": "invalid_item_code_length",
        "item_code_length": "bad",
    }


def test_decide_product_scan_rejects_malformed_scanned_barcodes_without_raising():
    decision = product_scan.decide_product_scan(
        _tray(scanned_barcodes="AAA2270730100-001"),
        "AAA2270730100-002",
        item_code_length=13,
    )

    assert decision.status == product_scan.SCAN_FORMAT_ERROR
    assert not decision.accepted


def test_decide_product_scan_rejects_invalid_tray_capacity_without_raising():
    decision = product_scan.decide_product_scan(_tray(tray_size="bad"), "AAA2270730100-001", item_code_length=13)

    assert decision.status == product_scan.SCAN_FORMAT_ERROR
    assert not decision.accepted


@pytest.mark.parametrize(
    ("barcode", "reason"),
    [
        ("AAA2270730100\n001", "control_character"),
        ("=AAA2270730100-001", "formula_prefix"),
        ("AAA2270730100<script>alert(1)</script>", "html_or_script_marker"),
        ("AAA2270730100..\\..\\evil", "path_traversal_marker"),
        ("AAA2270730100/../evil", "path_traversal_marker"),
        (f"AAA2270730100-{'1' * 128}", "barcode_too_long"),
    ],
)
def test_decide_product_scan_rejects_unsafe_product_barcodes_without_storing_raw_payload(barcode, reason):
    decision = product_scan.decide_product_scan(_tray(), barcode, item_code_length=13)

    assert decision.status == product_scan.SCAN_FORMAT_ERROR
    assert not decision.accepted
    assert decision.event_name == "SCAN_FAIL_FORMAT"
    assert decision.event_detail["reason"] == reason
    assert decision.event_detail["raw_barcode_length"] == len(barcode)
    assert len(decision.event_detail["raw_barcode_sha256"]) == 64
    assert "raw_barcode" not in decision.event_detail
    assert barcode not in str(decision.event_detail)


def test_decide_product_scan_rejects_item_mismatch_with_event_detail():
    decision = product_scan.decide_product_scan(_tray(), "BBB2270730100-001", item_code_length=13)

    assert decision.status == product_scan.SCAN_MISMATCH
    assert decision.event_name == "SCAN_FAIL_MISMATCH"
    assert decision.event_detail == {"expected": "AAA2270730100", "scanned": "BBB2270730100-001"}


def test_decide_product_scan_rejects_duplicate_with_event_detail():
    decision = product_scan.decide_product_scan(
        _tray(scanned_barcodes=["AAA2270730100-001"]),
        "AAA2270730100-001",
        item_code_length=13,
    )

    assert decision.status == product_scan.SCAN_DUPLICATE
    assert decision.event_name == "SCAN_FAIL_DUPLICATE"
    assert decision.event_detail == {"barcode": "AAA2270730100-001"}


def test_decide_product_scan_rejects_full_tray_with_event_detail():
    decision = product_scan.decide_product_scan(
        _tray(scanned_barcodes=["AAA2270730100-001"], tray_size=1),
        "AAA2270730100-002",
        item_code_length=13,
    )

    assert decision.status == product_scan.SCAN_TRAY_FULL
    assert decision.event_name == "SCAN_FAIL_TRAY_FULL"
    assert decision.event_detail == {
        "barcode": "AAA2270730100-002",
        "scan_count": 1,
        "tray_capacity": 1,
    }


def test_decide_product_scan_accepts_valid_new_product_barcode():
    decision = product_scan.decide_product_scan(_tray(), "AAA2270730100-001", item_code_length=13)

    assert decision.accepted
    assert decision.event_name == ""
    assert decision.event_detail == {}


@pytest.mark.parametrize(
    "barcode",
    [
        "AAA2270730100/LOT-001",
        "AAA2270730100&A=1",
        "AAA2270730100;SERIAL",
        "AAA2270730100|SERIAL",
        'AAA2270730100"SERIAL"',
        "AAA2270730100'SERIAL'",
        "AAA2270730100" + ("1" * (product_scan.MAX_PRODUCT_BARCODE_LENGTH - len("AAA2270730100"))),
    ],
)
def test_decide_product_scan_accepts_legitimate_non_control_separator_barcodes(barcode):
    decision = product_scan.decide_product_scan(_tray(), barcode, item_code_length=13)

    assert decision.accepted
