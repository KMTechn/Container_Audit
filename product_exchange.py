from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List
import uuid

from event_contracts import stable_hash


EXCHANGE_CONTRACT_VERSION = "container-audit-product-exchange-v1"
MAX_EXCHANGE_TARGET_QUANTITY = 2


@dataclass
class ProductExchangeSession:
    """Session data for individual product exchanges."""

    item_code: str = ""
    item_name: str = ""
    item_spec: str = ""
    target_quantity: int = 1
    exchange_id: str = field(default_factory=lambda: f"exchange-{uuid.uuid4().hex}")
    defective_barcodes: List[str] = field(default_factory=list)
    good_barcodes: List[str] = field(default_factory=list)
    exchange_pairs: List[Dict[str, str]] = field(default_factory=list)
    current_step: str = "not_started"


@dataclass(frozen=True)
class ExchangeScanResult:
    status: str
    title: str = ""
    message: str = ""
    play_success_sound: bool = False
    complete_ready: bool = False


def apply_exchange_scan(
    session: ProductExchangeSession,
    barcode: str,
    *,
    item_catalog: Any,
    item_code_length: int,
) -> ExchangeScanResult:
    if session.current_step not in {"scan_defective", "scan_good"}:
        return ExchangeScanResult(status="ignored")
    if (
        isinstance(session.target_quantity, bool)
        or not isinstance(session.target_quantity, int)
        or session.target_quantity < 1
        or session.target_quantity > MAX_EXCHANGE_TARGET_QUANTITY
    ):
        return ExchangeScanResult(status="error", title="교환 오류", message="교환 목표 수량이 올바르지 않습니다.")
    if isinstance(item_code_length, bool) or not isinstance(item_code_length, int) or item_code_length < 1:
        return ExchangeScanResult(status="error", title="교환 오류", message="제품 바코드 길이 설정이 올바르지 않습니다.")
    if not isinstance(barcode, str) or not barcode.strip():
        return ExchangeScanResult(status="error", title="바코드 형식 오류", message="제품 바코드가 올바르지 않습니다.")
    if not _valid_exchange_barcodes(session.defective_barcodes) or not _valid_exchange_barcodes(session.good_barcodes):
        return ExchangeScanResult(status="error", title="교환 오류", message="교환 바코드 목록이 올바르지 않습니다.")

    if len(barcode) <= item_code_length:
        return ExchangeScanResult(
            status="error",
            title="바코드 형식 오류",
            message=f"제품 바코드는 {item_code_length}자리보다 길어야 합니다.",
        )

    matching_codes = (
        item_catalog.matching_codes_in_barcode(barcode)
        if hasattr(item_catalog, "matching_codes_in_barcode")
        else []
    )
    if len(set(matching_codes)) > 1:
        return ExchangeScanResult(
            status="error",
            title="품목 코드 모호",
            message="제품 바코드에 여러 품목 코드가 포함되어 있습니다.",
        )

    matched_item = item_catalog.find_in_barcode(barcode) if hasattr(item_catalog, "find_in_barcode") else None
    item_code = matched_item.get("Item Code") if matched_item else barcode[:item_code_length]

    if not session.item_code:
        if not matched_item:
            return ExchangeScanResult(
                status="error",
                title="품목 없음",
                message=f"품목 코드 '{item_code}' 정보를 찾을 수 없습니다.",
            )
        session.item_code = item_code
        session.item_name = matched_item.get("Item Name", item_code)
        session.item_spec = matched_item.get("Spec", "")

    if matched_item and item_code != session.item_code:
        return ExchangeScanResult(
            status="error",
            title="품목 코드 불일치",
            message=f"다른 품목의 제품입니다.\n[기준: {session.item_code}]",
        )

    if session.item_code not in barcode:
        return ExchangeScanResult(
            status="error",
            title="품목 코드 불일치",
            message=f"다른 품목의 제품입니다.\n[기준: {session.item_code}]",
        )

    if barcode in session.defective_barcodes + session.good_barcodes:
        return ExchangeScanResult(status="warning", title="바코드 중복", message="이미 스캔된 바코드입니다.")

    if session.current_step == "scan_defective":
        if len(session.defective_barcodes) >= session.target_quantity:
            return ExchangeScanResult(status="warning", title="수량 초과", message="불량품 스캔 수량이 목표 수량에 도달했습니다.")
        session.defective_barcodes.append(barcode)
        if len(session.defective_barcodes) >= session.target_quantity:
            session.current_step = "scan_good"
    else:
        if len(session.good_barcodes) >= session.target_quantity:
            return ExchangeScanResult(status="warning", title="수량 초과", message="양품 스캔 수량이 목표 수량에 도달했습니다.")
        session.good_barcodes.append(barcode)

    return ExchangeScanResult(
        status="accepted",
        play_success_sound=True,
        complete_ready=(
            len(session.defective_barcodes) == session.target_quantity
            and len(session.good_barcodes) == session.target_quantity
        ),
    )


def build_exchange_pairs(session: ProductExchangeSession) -> List[Dict[str, str]]:
    return [
        {"defective": defective, "good": good}
        for defective, good in zip(session.defective_barcodes, session.good_barcodes)
    ]


def _valid_exchange_barcodes(barcodes: List[str]) -> bool:
    if not isinstance(barcodes, list):
        return False
    seen: set[str] = set()
    for barcode in barcodes:
        if not isinstance(barcode, str) or not barcode.strip():
            return False
        if barcode in seen:
            return False
        seen.add(barcode)
    return True


def validate_exchange_completion(session: ProductExchangeSession) -> ExchangeScanResult:
    if (
        isinstance(session.target_quantity, bool)
        or not isinstance(session.target_quantity, int)
        or session.target_quantity <= 0
        or session.target_quantity > MAX_EXCHANGE_TARGET_QUANTITY
    ):
        return ExchangeScanResult(status="error", title="교환 오류", message="교환 목표 수량이 올바르지 않습니다.")
    if not isinstance(session.item_code, str) or not session.item_code.strip():
        return ExchangeScanResult(status="error", title="교환 오류", message="교환 품목 코드가 올바르지 않습니다.")
    if not _valid_exchange_barcodes(session.defective_barcodes):
        return ExchangeScanResult(status="error", title="교환 오류", message="불량품 바코드 목록이 올바르지 않습니다.")
    if not _valid_exchange_barcodes(session.good_barcodes):
        return ExchangeScanResult(status="error", title="교환 오류", message="양품 바코드 목록이 올바르지 않습니다.")
    item_code = session.item_code.strip()
    if any(item_code not in barcode for barcode in [*session.defective_barcodes, *session.good_barcodes]):
        return ExchangeScanResult(status="error", title="교환 오류", message="교환 바코드 품목 코드가 일치하지 않습니다.")
    if set(session.defective_barcodes) & set(session.good_barcodes):
        return ExchangeScanResult(status="error", title="교환 오류", message="불량품과 양품에 같은 바코드가 포함되어 있습니다.")
    if len(session.defective_barcodes) != session.target_quantity:
        return ExchangeScanResult(
            status="error",
            title="교환 오류",
            message="불량품 스캔 수량이 목표 수량과 일치하지 않습니다.",
        )
    if len(session.good_barcodes) != session.target_quantity:
        return ExchangeScanResult(
            status="error",
            title="교환 오류",
            message="양품 스캔 수량이 목표 수량과 일치하지 않습니다.",
        )
    if len(session.defective_barcodes) != len(session.good_barcodes):
        return ExchangeScanResult(status="error", title="교환 오류", message="불량품과 양품의 수량이 일치하지 않습니다.")
    if session.current_step != "scan_good":
        return ExchangeScanResult(status="error", title="교환 오류", message="제품 교환 완료 단계가 올바르지 않습니다.")
    return ExchangeScanResult(status="accepted")


def build_exchange_completion_detail(session: ProductExchangeSession) -> Dict[str, Any]:
    validation = validate_exchange_completion(session)
    if validation.status != "accepted":
        raise ValueError(validation.message)
    exchange_pairs = build_exchange_pairs(session)
    detail = {
        "exchange_contract_version": EXCHANGE_CONTRACT_VERSION,
        "exchange_id": session.exchange_id,
        "target_quantity": session.target_quantity,
        "exchange_pairs": exchange_pairs,
        "item_code": session.item_code,
        "item_name": session.item_name,
        "item_spec": session.item_spec,
        "defective_barcodes": list(session.defective_barcodes),
        "good_barcodes": list(session.good_barcodes),
        "pair_count": len(exchange_pairs),
        "exchange_count": len(exchange_pairs),
    }
    detail["evidence_hash"] = stable_hash(detail)
    return detail
