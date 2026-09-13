"""Recorded and generated equivalence against the pre-extraction CA policy."""
from copy import deepcopy
from dataclasses import asdict
import random
from types import SimpleNamespace

import pytest

from item_catalog import ItemCatalog
import product_identity_port as port
import product_scan
from tests.fixtures import product_admission_w5b2_baseline as baseline


ITEM = "AAA2270730100"
OTHER = "BBB2270730100"
PRODUCT = ITEM + "-001"
# name, raw, current item, scanned history, capacity, catalog codes, final status/reason
VECTORS = [
    ("normal", PRODUCT, ITEM, [], 2, [ITEM], "accepted", None),
    ("embedded_item", "SERIAL-" + PRODUCT, ITEM, [], 2, [ITEM], "accepted", None),
    ("length_12", ITEM[:-1], ITEM, [], 2, [ITEM], "format_error", "barcode_too_short"),
    ("length_13", ITEM, ITEM, [], 2, [ITEM], "format_error", "barcode_too_short"),
    ("length_14", ITEM + "1", ITEM, [], 2, [ITEM], "accepted", None),
    ("length_128", ITEM + "x" * 115, ITEM, [], 2, [ITEM], "accepted", None),
    ("length_129", ITEM + "x" * 116, ITEM, [], 2, [ITEM], "format_error", "barcode_too_long"),
    ("nested_short", PRODUCT, ITEM, [], 2, [ITEM[:9], ITEM], "accepted", None),
    ("longer_different", PRODUCT, ITEM[:9], [], 2, [ITEM[:9], ITEM], "mismatch", None),
    ("separate_short", ITEM[:9] + "-" + PRODUCT, ITEM, [], 2, [ITEM[:9], ITEM], "mismatch", None),
    ("multiple", PRODUCT + "-" + OTHER, ITEM, [], 2, [ITEM, OTHER], "mismatch", None),
    ("duplicate_rows", PRODUCT, ITEM, [], 2, [ITEM, ITEM], "accepted", None),
    ("no_catalog_match", PRODUCT, ITEM, [], 2, [OTHER], "accepted", None),
    ("raw_duplicate", PRODUCT, ITEM, [PRODUCT], 2, [ITEM], "duplicate", None),
    ("case_distinct", PRODUCT + "a", ITEM, [PRODUCT + "A"], 2, [ITEM], "accepted", None),
    ("capacity_equal", PRODUCT, ITEM, [ITEM + "-002"], 1, [ITEM], "tray_full", None),
    ("capacity_exceeded", PRODUCT, ITEM, ["x", "x"], 1, [ITEM], "tray_full", None),
    ("duplicate_before_capacity", PRODUCT, ITEM, [PRODUCT], 1, [ITEM], "duplicate", None),
    ("duplicate_before_catalog", PRODUCT + OTHER, ITEM, [PRODUCT + OTHER], 1, [ITEM, OTHER], "duplicate", None),
    ("mismatch_before_duplicate", OTHER + "1", ITEM, [OTHER + "1"], 1, [ITEM], "mismatch", None),
    ("unicode_serial", PRODUCT + "한글１２é\u0301\u200b", ITEM, [], 2, [ITEM], "accepted", None),
    ("unicode_item", "앞-품목１２３４５６７８９０-뒤", "품목１２３４５６７８９０", [], 2, [], "accepted", None),
    ("c1_retained", PRODUCT + "\x85x", ITEM, [], 2, [ITEM], "accepted", None),
    ("control", ITEM + "\n001", ITEM, [], 2, [ITEM], "format_error", "control_character"),
    ("del", PRODUCT + "\x7f", ITEM, [], 2, [ITEM], "format_error", "control_character"),
    ("edge_whitespace", PRODUCT + "\n", ITEM, [], 2, [ITEM], "format_error", "leading_or_trailing_whitespace"),
    ("formula", "=" + PRODUCT, ITEM, [], 2, [ITEM], "format_error", "formula_prefix"),
    ("html", PRODUCT + "<x>", ITEM, [], 2, [ITEM], "format_error", "html_or_script_marker"),
    ("path", PRODUCT + "/../x", ITEM, [], 2, [ITEM], "format_error", "path_traversal_marker"),
    ("list_contract", PRODUCT, ITEM, {PRODUCT}, 2, [ITEM], "format_error", "malformed_scanned_barcodes"),
    ("invalid_capacity_before_mismatch", OTHER + "1", ITEM, [], False, [ITEM], "format_error", "invalid_tray_capacity"),
]


def _assert_equivalent(raw, item, scanned, capacity, codes, length=13):
    tray = SimpleNamespace(item_code=item, scanned_barcodes=scanned, tray_size=capacity)
    rows = [{"Item Code": code, "Item Name": str(index)} for index, code in enumerate(codes)]
    original = deepcopy((tray, rows))
    actual_catalog, old_catalog = ItemCatalog(rows), baseline.ItemCatalog(rows)
    actual_codes = actual_catalog.matching_codes_in_barcode(raw)
    assert actual_codes == old_catalog.matching_codes_in_barcode(raw)
    assert actual_catalog.find_in_barcode(raw) == old_catalog.find_in_barcode(raw)
    assert actual_catalog.find_by_code(item) == old_catalog.find_by_code(item)
    actual = product_scan.decide_product_scan(tray, raw, item_code_length=length)
    assert actual == port.decide_product_admission(
        raw, item_code=item, scanned_barcodes=scanned, capacity=capacity, item_code_length=length,
    )
    assert type(actual) is product_scan.ProductScanDecision
    old = baseline.decide_product_scan(tray, raw, item_code_length=length)
    assert asdict(actual) == asdict(old)
    if actual.event_detail.get("reason") in {
        "barcode_too_short", "barcode_too_long", "leading_or_trailing_whitespace",
        "control_character", "formula_prefix", "html_or_script_marker", "path_traversal_marker",
    }:
        # U06 adds an action; the recorded diagnosis and all decision fields stay exact.
        diagnosis = old.format_error_message.split(". ", 1)[0]
        assert diagnosis in actual.format_error_message
        assert "확인" in actual.format_error_message
        if actual.event_detail["reason"] == "barcode_too_short":
            assert "제품 라벨 확인 후 다시 스캔하세요" in actual.format_error_message
            assert "같은 오류가 계속되면" in actual.format_error_message
            assert "담당자에게 라벨 형식을 확인" in actual.format_error_message
    else:
        assert actual.format_error_message == old.format_error_message
    if actual.accepted:
        actual = product_scan.decide_catalog_product_match(item, raw, actual_codes)
        old = baseline.decide_catalog_product_match(item, raw, actual_codes)
        assert asdict(actual) == asdict(old)
    assert (tray, rows) == original
    return actual


@pytest.mark.parametrize(
    "name,raw,item,scanned,capacity,codes,status,reason", VECTORS,
    ids=[vector[0] for vector in VECTORS],
)
def test_recorded_admission_vectors(name, raw, item, scanned, capacity, codes, status, reason):
    decision = _assert_equivalent(raw, item, scanned, capacity, codes)
    assert decision.status == status
    assert decision.event_detail.get("reason") == reason


def test_generated_admission_equivalence():
    """Seeded property checks span interacting gates, invalid context and raw Unicode."""
    rng = random.Random(857203)
    alphabet = "abAB01한글１２é\u0301\u200b\x00\x1f\x7f\x85 =+-@<>`/\\:;|"
    for _ in range(1200):
        fragment = "".join(rng.choices(alphabet, k=rng.randrange(140)))
        raw = rng.choice([fragment, ITEM + fragment, fragment + ITEM, PRODUCT, None, 123])
        scanned = rng.choice([[], [PRODUCT], [raw], ["x", "x"], None, "bad", {PRODUCT}, [1]])
        _assert_equivalent(
            raw, rng.choice([ITEM, " " + ITEM + " ", ITEM[:9], "", None, OTHER]), scanned,
            rng.choice([1, 2, 0, -1, "2", "bad", None, True, 1.9]),
            rng.choice([[ITEM], [ITEM[:9], ITEM], [ITEM, OTHER], [], [" " + ITEM, ITEM]]),
            rng.choice([13, 9, "13", 0, -1, None, True, "bad", 1.9]),
        )


def test_generated_catalog_equivalence():
    """Generate overlapping/repeated spans and permuted duplicate catalog rows."""
    rng = random.Random(857204)
    for _ in range(1200):
        codes = ["".join(rng.choices("AB１２", k=rng.randrange(1, 6))) for _ in range(8)]
        codes += codes[:2] + ["", " "]
        raw = "-".join(rng.choices(codes, k=6))
        _assert_equivalent(raw, codes[0], [], 2, codes, length=1)


def test_start_item_code_gate_preserves_inline_length_check():
    # This compatibility gate receives the caller's text, without new normalization.
    for raw in ("", ITEM[:-1], ITEM, ITEM + "1", " " + ITEM, "품" * 13, "A" * 12 + "\n"):
        for length in (9, 13, "13", 0, True, None):
            assert port.is_start_item_code(raw, item_code_length=length) == (len(raw) == length)


def test_tray_facade_preserves_missing_attribute_defaults():
    for tray in (None, SimpleNamespace(), SimpleNamespace(item_code=ITEM),
                 SimpleNamespace(item_code=ITEM, tray_size=2)):
        assert asdict(product_scan.decide_product_scan(tray, PRODUCT, item_code_length=13)) == asdict(
            baseline.decide_product_scan(tray, PRODUCT, item_code_length=13)
        )
