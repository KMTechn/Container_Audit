from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SCAN_ACCEPTED = "accepted"
SCAN_FORMAT_ERROR = "format_error"
SCAN_MISMATCH = "mismatch"
SCAN_DUPLICATE = "duplicate"
SCAN_TRAY_FULL = "tray_full"


@dataclass(frozen=True)
class ProductScanDecision:
    status: str
    event_name: str = ""
    event_detail: dict[str, Any] = field(default_factory=dict)

    @property
    def accepted(self) -> bool:
        return self.status == SCAN_ACCEPTED


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _scanned_barcodes(value: Any) -> list[str] | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return value


def _format_error_decision(raw_barcode: str, *, reason: str, item_code_length: Any) -> ProductScanDecision:
    return ProductScanDecision(
        status=SCAN_FORMAT_ERROR,
        event_name="SCAN_FAIL_FORMAT",
        event_detail={
            "raw_barcode": raw_barcode,
            "reason": reason,
            "item_code_length": item_code_length,
        },
    )


def decide_product_scan(tray: Any, barcode: str, *, item_code_length: int) -> ProductScanDecision:
    raw_barcode = str(barcode or "")
    required_item_code_length = _positive_int(item_code_length)
    if required_item_code_length is None:
        return _format_error_decision(raw_barcode, reason="invalid_item_code_length", item_code_length=item_code_length)
    if len(raw_barcode) <= required_item_code_length:
        return _format_error_decision(raw_barcode, reason="barcode_too_short", item_code_length=required_item_code_length)
    item_code = str(getattr(tray, "item_code", "") or "").strip()
    if not item_code:
        return _format_error_decision(raw_barcode, reason="missing_item_code", item_code_length=required_item_code_length)
    scanned_barcodes = _scanned_barcodes(getattr(tray, "scanned_barcodes", []))
    if scanned_barcodes is None:
        return _format_error_decision(raw_barcode, reason="malformed_scanned_barcodes", item_code_length=required_item_code_length)
    tray_capacity = _positive_int(getattr(tray, "tray_size", 0))
    if tray_capacity is None:
        return _format_error_decision(raw_barcode, reason="invalid_tray_capacity", item_code_length=required_item_code_length)
    if item_code not in raw_barcode:
        return ProductScanDecision(
            status=SCAN_MISMATCH,
            event_name="SCAN_FAIL_MISMATCH",
            event_detail={"expected": item_code, "scanned": raw_barcode},
        )
    if raw_barcode in scanned_barcodes:
        return ProductScanDecision(
            status=SCAN_DUPLICATE,
            event_name="SCAN_FAIL_DUPLICATE",
            event_detail={"barcode": raw_barcode},
        )
    scanned_count = len(scanned_barcodes)
    if scanned_count >= tray_capacity:
        return ProductScanDecision(
            status=SCAN_TRAY_FULL,
            event_name="SCAN_FAIL_TRAY_FULL",
            event_detail={
                "barcode": raw_barcode,
                "scan_count": scanned_count,
                "tray_capacity": tray_capacity,
            },
        )
    return ProductScanDecision(status=SCAN_ACCEPTED)
