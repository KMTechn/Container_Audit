from __future__ import annotations

from product_exchange import (
    MAX_EXCHANGE_TARGET_QUANTITY,
    ProductExchangeSession,
    apply_exchange_scan,
    validate_exchange_completion,
)


class _Catalog:
    @staticmethod
    def matching_codes_in_barcode(_barcode):
        return ["AAA2270730100"]

    @staticmethod
    def find_in_barcode(_barcode):
        return {
            "Item Code": "AAA2270730100",
            "Item Name": "테스트 품목",
            "Spec": "TEST",
        }


def test_product_exchange_contract_is_limited_to_one_or_two_pairs():
    assert MAX_EXCHANGE_TARGET_QUANTITY == 2

    session = ProductExchangeSession(target_quantity=3, current_step="scan_defective")
    result = apply_exchange_scan(
        session,
        "AAA2270730100-OLD-1",
        item_catalog=_Catalog(),
        item_code_length=13,
    )

    assert result.status == "error"
    assert session.defective_barcodes == []


def test_completion_cannot_bypass_two_pair_limit():
    session = ProductExchangeSession(
        item_code="AAA2270730100",
        target_quantity=3,
        current_step="scan_good",
        defective_barcodes=[
            "AAA2270730100-OLD-1",
            "AAA2270730100-OLD-2",
            "AAA2270730100-OLD-3",
        ],
        good_barcodes=[
            "AAA2270730100-NEW-1",
            "AAA2270730100-NEW-2",
            "AAA2270730100-NEW-3",
        ],
    )

    assert validate_exchange_completion(session).status == "error"
