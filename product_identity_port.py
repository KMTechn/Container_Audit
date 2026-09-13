"""Pure CA-current product identity gates; callers own state, catalog loading and effects."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Mapping


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
                return f"제품 바코드는 {length}자리보다 길어야 합니다. 제품 라벨 확인 후 다시 스캔하세요. 같은 오류가 계속되면 담당자에게 라벨 형식을 확인하세요."
        return {
            "barcode_too_short": "제품 바코드 형식이 올바르지 않습니다. 제품 라벨 확인 후 다시 스캔하세요. 같은 오류가 계속되면 담당자에게 라벨 형식을 확인하세요.",
            "barcode_too_long": f"제품 바코드는 {MAX_PRODUCT_BARCODE_LENGTH}자 이하여야 합니다. 제품 라벨 형식을 담당자에게 확인하세요.",
            "leading_or_trailing_whitespace": "제품 바코드 앞뒤에 공백이 있습니다. 스캐너 설정을 확인하고 다시 스캔하세요.",
            "control_character": "제품 바코드에 제어 문자가 있습니다. 스캐너 설정을 확인하고 다시 스캔하세요.",
            "formula_prefix": "제품 바코드에 허용되지 않는 시작 문자가 있습니다. 제품 라벨과 스캐너 설정을 담당자에게 확인하세요.",
            "html_or_script_marker": "제품 바코드에 허용되지 않는 문자 형식이 있습니다. 제품 라벨과 스캐너 설정을 담당자에게 확인하세요.",
            "path_traversal_marker": "제품 바코드에 허용되지 않는 경로 형식이 있습니다. 제품 라벨과 스캐너 설정을 담당자에게 확인하세요.",
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


def unsafe_product_input_reason(raw_barcode: str) -> str | None:
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


def is_start_item_code(raw_barcode: str, *, item_code_length: int) -> bool:
    """Legacy start gate only; no normalization or generic QR parsing."""
    return len(raw_barcode) == item_code_length


def exceeds_item_code_length(raw_barcode: str, *, item_code_length: int) -> bool:
    """The product must be longer than the item code; its position is unrestricted."""
    return len(raw_barcode) > item_code_length


def matches_current_item(raw_barcode: str, *, item_code: str) -> bool:
    return item_code in raw_barcode


def is_raw_duplicate(raw_barcode: str, *, scanned_barcodes: list[str]) -> bool:
    return raw_barcode in scanned_barcodes


def is_at_capacity(*, scanned_barcodes: list[str], capacity: int) -> bool:
    return len(scanned_barcodes) >= capacity


def decide_product_admission(
    raw_barcode: str, *, item_code: Any, scanned_barcodes: Any,
    capacity: Any, item_code_length: int,
) -> ProductScanDecision:
    """Preserve gate order and raw/list semantics for an explicit tray snapshot."""
    raw_barcode = str(raw_barcode or "")
    required_item_code_length = _positive_int(item_code_length)
    unsafe_reason = unsafe_product_input_reason(raw_barcode)
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
    if not exceeds_item_code_length(raw_barcode, item_code_length=required_item_code_length):
        return _format_error_decision(raw_barcode, reason="barcode_too_short", item_code_length=required_item_code_length)
    item_code = str(item_code or "").strip()
    if not item_code:
        return _format_error_decision(raw_barcode, reason="missing_item_code", item_code_length=required_item_code_length)
    scanned_barcodes = _scanned_barcodes(scanned_barcodes)
    if scanned_barcodes is None:
        return _format_error_decision(raw_barcode, reason="malformed_scanned_barcodes", item_code_length=required_item_code_length)
    tray_capacity = _positive_int(capacity)
    if tray_capacity is None:
        return _format_error_decision(raw_barcode, reason="invalid_tray_capacity", item_code_length=required_item_code_length)
    if not matches_current_item(raw_barcode, item_code=item_code):
        return ProductScanDecision(
            status=SCAN_MISMATCH,
            event_name="SCAN_FAIL_MISMATCH",
            event_detail={"expected": item_code, "scanned": raw_barcode},
        )
    if is_raw_duplicate(raw_barcode, scanned_barcodes=scanned_barcodes):
        return ProductScanDecision(
            status=SCAN_DUPLICATE,
            event_name="SCAN_FAIL_DUPLICATE",
            event_detail={"barcode": raw_barcode},
        )
    scanned_count = len(scanned_barcodes)
    if is_at_capacity(scanned_barcodes=scanned_barcodes, capacity=tray_capacity):
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


def find_catalog_item(item_code: str, *, catalog_view: Mapping[str, dict[str, Any]]) -> dict[str, Any] | None:
    return catalog_view.get(str(item_code or "").strip())


def matching_catalog_codes(barcode: str, *, catalog_view: Mapping[str, Any]) -> list[str]:
    """Keep catalog order; suppress a shorter code only when every span is covered."""
    text = str(barcode or "")
    spans_by_code: dict[str, list[tuple[int, int]]] = {}
    for code in catalog_view:
        start = 0
        spans: list[tuple[int, int]] = []
        while True:
            index = text.find(code, start)
            if index < 0:
                break
            spans.append((index, index + len(code)))
            start = index + 1
        if spans:
            spans_by_code[code] = spans

    matches: list[str] = []
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
