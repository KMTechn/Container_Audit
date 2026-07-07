from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from event_payloads import product_barcodes_from_completion
from label_qr import inspection_master_item_code, parse_new_format_qr, parse_positive_quantity


REPLACEMENT_REJECT_ITEM_CODE = "reject_item_code"
REPLACEMENT_REJECT_NEW_QTY = "reject_new_qty"
REPLACEMENT_REJECT_OLD_QTY = "reject_old_qty"
REPLACEMENT_FINALIZE = "finalize"
REPLACEMENT_AWAIT_ADDITIONAL = "awaiting_additional_items"
REPLACEMENT_AWAIT_REMOVED = "awaiting_removed_items"


@dataclass(frozen=True)
class ReplacementQuantityDecision:
    action: str
    expected_item_code: str = ""
    new_item_code: str = ""
    old_label_item_code: str = ""
    old_qty: int | None = None
    new_qty: int | None = None
    items_needed: int = 0
    items_to_remove_count: int = 0


def compare_replacement_quantities(
    original_details: Mapping[str, Any],
    new_data: Mapping[str, Any],
) -> ReplacementQuantityDecision:
    expected_item_code = str(
        original_details.get("item_code")
        or original_details.get("item")
        or original_details.get("product_code")
        or ""
    )
    new_item_code = inspection_master_item_code(dict(new_data or {}))
    old_label_data = parse_new_format_qr(str(original_details.get("master_label_code") or ""))
    old_label_item_code = inspection_master_item_code(old_label_data or {})
    if not expected_item_code and old_label_item_code:
        expected_item_code = old_label_item_code
    if expected_item_code and old_label_item_code and expected_item_code != old_label_item_code:
        return ReplacementQuantityDecision(
            action=REPLACEMENT_REJECT_ITEM_CODE,
            expected_item_code=expected_item_code,
            new_item_code=new_item_code,
            old_label_item_code=old_label_item_code,
        )
    if expected_item_code and new_item_code and expected_item_code != new_item_code:
        return ReplacementQuantityDecision(
            action=REPLACEMENT_REJECT_ITEM_CODE,
            expected_item_code=expected_item_code,
            new_item_code=new_item_code,
            old_label_item_code=old_label_item_code,
        )

    try:
        old_qty = _old_quantity(original_details)
    except ValueError:
        old_qty = None
    new_qty = parse_positive_quantity(dict(new_data))
    if old_qty is None:
        return ReplacementQuantityDecision(
            action=REPLACEMENT_REJECT_OLD_QTY,
            expected_item_code=expected_item_code,
            new_item_code=new_item_code,
            old_label_item_code=old_label_item_code,
            old_qty=None,
            new_qty=new_qty,
        )
    if new_qty is None:
        return ReplacementQuantityDecision(
            action=REPLACEMENT_REJECT_NEW_QTY,
            expected_item_code=expected_item_code,
            new_item_code=new_item_code,
            old_label_item_code=old_label_item_code,
            old_qty=old_qty,
        )

    if old_qty == new_qty:
        action = REPLACEMENT_FINALIZE
    elif new_qty > old_qty:
        action = REPLACEMENT_AWAIT_ADDITIONAL
    else:
        action = REPLACEMENT_AWAIT_REMOVED

    return ReplacementQuantityDecision(
        action=action,
        expected_item_code=expected_item_code,
        new_item_code=new_item_code,
        old_label_item_code=old_label_item_code,
        old_qty=old_qty,
        new_qty=new_qty,
        items_needed=max(0, new_qty - old_qty),
        items_to_remove_count=max(0, old_qty - new_qty),
    )


def _old_quantity(original_details: Mapping[str, Any]) -> int | None:
    product_barcode_count = len(product_barcodes_from_completion(dict(original_details)))
    is_partial_submission = original_details.get("is_partial_submission", False)
    if not isinstance(is_partial_submission, bool):
        raise ValueError("is_partial_submission must be boolean")
    old_qty = product_barcode_count or None
    if old_qty is None and (is_partial_submission or original_details.get("quantity_basis") == "PRODUCT_BARCODE"):
        return None
    if old_qty is None:
        old_details_data = parse_new_format_qr(str(original_details.get("master_label_code") or ""))
        old_qty = parse_positive_quantity(old_details_data) if old_details_data else None
    return int(old_qty) if old_qty is not None else None
