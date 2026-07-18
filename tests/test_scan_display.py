from __future__ import annotations

import hashlib

from scan_display import compact_scan_value, format_scan_list_row


ITEM_CODE = "AAA2270730100"


def test_item_prefixed_scan_shows_item_code_and_short_distinguishing_suffix():
    raw_barcode = f"{ITEM_CODE}-LINE-0001"

    assert compact_scan_value(raw_barcode, item_code=ITEM_CODE) == (
        f"{ITEM_CODE} · LINE-0001"
    )
    assert format_scan_list_row(3, raw_barcode, item_code=ITEM_CODE) == (
        f"(3) {ITEM_CODE} · LINE-0001"
    )


def test_long_simple_suffix_keeps_only_a_bounded_distinguishing_tail():
    raw_barcode = f"{ITEM_CODE}-PRODUCTION-LINE-000000123456"
    display = compact_scan_value(raw_barcode, item_code=ITEM_CODE)

    assert display == f"{ITEM_CODE} · …00000123456"
    assert len(display.rsplit(" · ", 1)[1]) == 12
    assert raw_barcode not in display


def test_structured_scan_uses_prioritized_serial_without_showing_telegram_fields():
    raw_barcode = (
        "PHS=2|CLC=SHOULD-NOT-BE-DERIVED|LOT=LOT-42|"
        "SERIAL=SERIAL-000000987654|LBL=LABEL-77"
    )
    display = compact_scan_value(raw_barcode, item_code=ITEM_CODE)

    assert display == f"{ITEM_CODE} · SN …00000987654"
    assert "CLC" not in display
    assert "|" not in display
    assert "=" not in display
    assert raw_barcode not in display


def test_unknown_or_unsafe_format_fails_closed_to_stable_short_hash():
    raw_barcode = "PHS=2|CLC=AAA9999999999|QT=60|UNRECOGNIZED=SECRET-TELEGRAM"
    expected_hash = hashlib.sha256(raw_barcode.encode("utf-8")).hexdigest()[:10]

    first = compact_scan_value(raw_barcode, item_code=ITEM_CODE)
    second = compact_scan_value(raw_barcode, item_code=ITEM_CODE)

    assert first == second == f"{ITEM_CODE} · ID #{expected_hash}"
    assert "|" not in first
    assert "=" not in first
    assert "SECRET" not in first


def test_item_code_is_never_derived_from_raw_clc_field():
    raw_barcode = "PHS=2|CLC=AAA9999999999|QT=60|LOT=LOT-7"

    display = compact_scan_value(raw_barcode, item_code="")

    assert display == "품목 미확인 · LOT LOT-7"
    assert "AAA9999999999" not in display
