from types import SimpleNamespace

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
