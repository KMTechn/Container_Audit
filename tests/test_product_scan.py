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
    assert barcode not in decision.format_error_message
    assert "13자리보다" not in decision.format_error_message


@pytest.mark.parametrize("reason, situation, action, rescan", [
    ("barcode_too_short", "13자리보다 길어야", "제품 라벨의 바코드를 확인", True),
    ("barcode_too_long", "128자 이하", "제품 라벨 형식을 담당자에게 확인", False),
    ("leading_or_trailing_whitespace", "앞뒤에 공백", "스캐너 설정을 확인", True),
    ("control_character", "제어 문자", "스캐너 설정을 확인", True),
    ("formula_prefix", "시작 문자", "제품 라벨과 스캐너 설정을 담당자에게 확인", False),
    ("html_or_script_marker", "문자 형식", "제품 라벨과 스캐너 설정을 담당자에게 확인", False),
    ("path_traversal_marker", "경로 형식", "제품 라벨과 스캐너 설정을 담당자에게 확인", False),
    ("invalid_item_code_length", "품목코드 길이 설정", "관리자에게 문의", False),
    ("missing_item_code", "품목 정보가 없습니다", "현품표를 확인", False),
    ("malformed_scanned_barcodes", "스캔 기록", "관리자에게 문의", False),
    ("invalid_tray_capacity", "목표 수량", "관리자에게 문의", False),
    ("unknown", "형식이 올바르지 않습니다", "제품 라벨을 확인", False),
])
def test_format_error_message_explains_reason_without_echoing_input(reason, situation, action, rescan):
    decision = product_scan.ProductScanDecision(
        product_scan.SCAN_FORMAT_ERROR,
        event_detail={"reason": reason, "item_code_length": 13, "raw_barcode": "<unsafe>"},
    )
    message = decision.format_error_message
    assert situation in message
    assert action in message
    assert ("다시 스캔하세요" in message) is rescan
    assert message.index(action) > message.index(situation)
    assert decision.event_detail["reason"] == reason
    assert reason not in message
    assert "<unsafe>" not in message


def test_invalid_length_setting_does_not_expose_unsafe_barcode():
    decision = product_scan.decide_product_scan(_tray(), "<unsafe>", item_code_length="bad")
    assert "raw_barcode" not in decision.event_detail
    assert "<unsafe>" not in str(decision.event_detail)


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
