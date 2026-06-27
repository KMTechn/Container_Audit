from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any


SCAN_ACCEPTED = "accepted"
SCAN_FORMAT_ERROR = "format_error"
SCAN_MISMATCH = "mismatch"
SCAN_DUPLICATE = "duplicate"
SCAN_TRAY_FULL = "tray_full"
MAX_PRODUCT_BARCODE_LENGTH = 128
FORMULA_PREFIX_CHARS = ("=", "+", "-", "@")
HTML_OR_SCRIPT_MARKERS = ("<", ">", "`", "javascript:")
PATH_TRAVERSAL_PATTERNS = (re.compile(r"(^|[\\/])\.\.([\\/]|$)"), re.compile(r"^[A-Za-z]:[\\/]"))


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


def _format_error_decision(
    raw_barcode: str,
    *,
    reason: str,
    item_code_length: Any,
    redact_raw_barcode: bool = False,
) -> ProductScanDecision:
    if redact_raw_barcode:
        event_detail = {
            "raw_barcode_sha256": hashlib.sha256(raw_barcode.encode("utf-8")).hexdigest(),
            "raw_barcode_length": len(raw_barcode),
            "reason": reason,
            "item_code_length": item_code_length,
        }
    else:
        event_detail = {
            "raw_barcode": raw_barcode,
            "reason": reason,
            "item_code_length": item_code_length,
        }
    return ProductScanDecision(
        status=SCAN_FORMAT_ERROR,
        event_name="SCAN_FAIL_FORMAT",
        event_detail=event_detail,
    )


def _unsafe_barcode_reason(raw_barcode: str) -> str | None:
    if len(raw_barcode) > MAX_PRODUCT_BARCODE_LENGTH:
        return "barcode_too_long"
    if raw_barcode != raw_barcode.strip():
        return "leading_or_trailing_whitespace"
    if any(ord(char) < 32 or ord(char) == 127 for char in raw_barcode):
        return "control_character"
    if raw_barcode[:1] in FORMULA_PREFIX_CHARS:
        return "formula_prefix"
    normalized = raw_barcode.lower()
    if any(marker in normalized for marker in HTML_OR_SCRIPT_MARKERS):
        return "html_or_script_marker"
    if raw_barcode.startswith(("/", "\\")) or any(pattern.search(raw_barcode) for pattern in PATH_TRAVERSAL_PATTERNS):
        return "path_traversal_marker"
    return None


def decide_product_scan(tray: Any, barcode: str, *, item_code_length: int) -> ProductScanDecision:
    raw_barcode = str(barcode or "")
    required_item_code_length = _positive_int(item_code_length)
    if required_item_code_length is None:
        return _format_error_decision(raw_barcode, reason="invalid_item_code_length", item_code_length=item_code_length)
    unsafe_reason = _unsafe_barcode_reason(raw_barcode)
    if unsafe_reason is not None:
        return _format_error_decision(
            raw_barcode,
            reason=unsafe_reason,
            item_code_length=required_item_code_length,
            redact_raw_barcode=True,
        )
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
