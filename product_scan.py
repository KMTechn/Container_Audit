"""Tray-object compatibility facade for the explicit CA product identity port."""
from __future__ import annotations

from typing import Any

from product_identity_port import (
    FORMULA_PREFIX_CHARS,
    HTML_OR_SCRIPT_MARKERS,
    MAX_PRODUCT_BARCODE_LENGTH,
    PATH_TRAVERSAL_PATTERNS,
    SCAN_ACCEPTED,
    SCAN_DUPLICATE,
    SCAN_FORMAT_ERROR,
    SCAN_MISMATCH,
    SCAN_TRAY_FULL,
    ProductScanDecision,
    decide_catalog_product_match,
    decide_product_admission,
)


def decide_product_scan(tray: Any, barcode: str, *, item_code_length: int) -> ProductScanDecision:
    return decide_product_admission(
        barcode,
        item_code=getattr(tray, "item_code", ""),
        scanned_barcodes=getattr(tray, "scanned_barcodes", []),
        capacity=getattr(tray, "tray_size", 0),
        item_code_length=item_code_length,
    )
