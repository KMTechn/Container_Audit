# Frozen behavior oracle from 00c5deb1085a5b2c7b95b975fe0443bae56061a5.
# Only tests consume this copy; do not update it to match the port.
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

    @property
    def format_error_message(self) -> str:
        reason = self.event_detail.get("reason")
        if reason == "barcode_too_short":
            length = _positive_int(self.event_detail.get("item_code_length"))
            if length is not None:
                return f"제품 바코드는 {length}자리보다 길어야 합니다."
        return {
            "barcode_too_long": f"제품 바코드는 {MAX_PRODUCT_BARCODE_LENGTH}자 이하여야 합니다.",
            "leading_or_trailing_whitespace": "제품 바코드 앞뒤에 공백이 있습니다. 스캐너 입력을 확인하세요.",
            "control_character": "제품 바코드에 제어 문자가 있습니다. 스캐너 입력을 확인하세요.",
            "formula_prefix": "제품 바코드에 허용되지 않는 시작 문자가 있습니다.",
            "html_or_script_marker": "제품 바코드에 허용되지 않는 문자 형식이 있습니다.",
            "path_traversal_marker": "제품 바코드에 허용되지 않는 경로 형식이 있습니다.",
            "invalid_item_code_length": "품목코드 길이 설정을 확인해야 합니다. 관리자에게 문의하세요.",
            "missing_item_code": "현재 트레이의 품목 정보가 없습니다. 현품표를 확인하세요.",
            "malformed_scanned_barcodes": "현재 트레이의 스캔 기록을 확인해야 합니다. 관리자에게 문의하세요.",
            "invalid_tray_capacity": "현재 트레이의 목표 수량을 확인해야 합니다. 관리자에게 문의하세요.",
        }.get(reason, "제품 바코드 형식이 올바르지 않습니다. 제품 라벨을 확인하세요.")


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
    unsafe_reason = _unsafe_barcode_reason(raw_barcode)
    if required_item_code_length is None:
        return _format_error_decision(raw_barcode, reason="invalid_item_code_length", item_code_length=item_code_length,
                                      redact_raw_barcode=unsafe_reason is not None)
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


def decide_catalog_product_match(
    expected_item_code: str, raw_barcode: str, matching_codes: list[str],
) -> ProductScanDecision:
    """Apply catalog ambiguity rules after the basic product-scan gate."""
    codes = list(dict.fromkeys(matching_codes))
    if len(codes) > 1:
        event_name = "SCAN_FAIL_AMBIGUOUS_ITEM_CODE"
        detail = {"matching_item_codes": codes}
    elif len(codes) == 1 and codes[0] != expected_item_code:
        event_name = "SCAN_FAIL_MISMATCH"
        detail = {"matched_item_code": codes[0]}
    else:
        return ProductScanDecision(status=SCAN_ACCEPTED)
    return ProductScanDecision(
        status=SCAN_MISMATCH,
        event_name=event_name,
        event_detail={"expected": expected_item_code, "scanned": raw_barcode, **detail},
    )



from typing import Any, Dict, Iterable, List, Mapping, Optional


class ItemCatalog:
    """Lookup wrapper for Item.csv rows."""

    def __init__(self, rows: Iterable[Mapping[str, Any]]):
        self.source_id = id(rows)
        self._rows: List[Dict[str, Any]] = []
        self._by_code: Dict[str, Dict[str, Any]] = {}
        for source_row in rows:
            row = dict(source_row)
            code = str(row.get("Item Code") or "").strip()
            if code:
                row["Item Code"] = code
            self._rows.append(row)
            if code and code not in self._by_code:
                self._by_code[code] = row

    def rows(self) -> List[Dict[str, Any]]:
        return [dict(row) for row in self._rows]

    def find_by_code(self, item_code: str) -> Optional[Dict[str, Any]]:
        return self._by_code.get(str(item_code or "").strip())

    def find_in_barcode(self, barcode: str) -> Optional[Dict[str, Any]]:
        matches = self.matching_codes_in_barcode(barcode)
        if len(matches) != 1:
            return None
        return self.find_by_code(matches[0])

    def matching_codes_in_barcode(self, barcode: str) -> List[str]:
        text = str(barcode or "")
        spans_by_code: Dict[str, List[tuple[int, int]]] = {}
        for code in self._by_code:
            start = 0
            spans: List[tuple[int, int]] = []
            while True:
                index = text.find(code, start)
                if index < 0:
                    break
                spans.append((index, index + len(code)))
                start = index + 1
            if spans:
                spans_by_code[code] = spans

        matches: List[str] = []
        for code, spans in spans_by_code.items():
            longer_spans = [
                other_span
                for other_code, other_spans in spans_by_code.items()
                if other_code != code and len(other_code) > len(code)
                for other_span in other_spans
            ]
            if longer_spans and all(
                any(other_start <= start and end <= other_end for other_start, other_end in longer_spans)
                for start, end in spans
            ):
                continue
            matches.append(code)
        return matches
