import datetime
import math
from typing import Any, Callable, Dict, Iterable, List

from label_qr import canonical_master_label_key, parse_new_format_qr, parse_positive_quantity


def product_barcodes_from_completion(details: Dict[str, Any]) -> List[str]:
    non_empty_aliases: list[tuple[str, List[str]]] = []
    for key in ("product_barcodes", "scanned_product_barcodes", "scanned_barcodes"):
        value = details.get(key)
        if isinstance(value, list) and value:
            if not all(isinstance(barcode, str) for barcode in value):
                raise ValueError("completion product barcode aliases must contain only text values")
            non_empty_aliases.append((key, list(value)))
    if not non_empty_aliases:
        return []
    first_key, first_values = non_empty_aliases[0]
    for key, values in non_empty_aliases[1:]:
        if values != first_values:
            raise ValueError(f"completion product barcode aliases conflict: {first_key}, {key}")
    if len(set(first_values)) != len(first_values):
        raise ValueError("completion product barcode aliases must be unique")
    return first_values


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be non-empty text")
    return value


def _require_positive_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def _require_non_negative_finite_number(value: Any, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be a non-negative finite number")
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"{field_name} must be a non-negative finite number")
    return parsed


def _validated_scanned_barcodes(value: Any) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(barcode, str) for barcode in value):
        raise ValueError("scanned_barcodes must be a list of text values")
    if len(set(value)) != len(value):
        raise ValueError("scanned_barcodes must be unique")
    return list(value)


def inspection_trace_from_master_label_fields(
    master_label_code: str,
    master_label_fields: Dict[str, Any],
) -> Dict[str, Any]:
    fields = dict(master_label_fields or {})
    trace = {
        "input_tag_id": str(fields.get("ITG") or "").strip(),
        "input_tag_label_id": str(fields.get("LBL") or "").strip(),
        "input_tag_core_hash": str(fields.get("HSH_CORE") or "").strip(),
        "input_tag_label_hash": str(fields.get("HSH_LABEL") or "").strip(),
        "master_label_phase": str(fields.get("PHS") or "").strip(),
    }
    if trace["input_tag_id"]:
        trace["inspection_session_key"] = trace["input_tag_id"]
    identity_key = canonical_master_label_key(master_label_code)
    if identity_key:
        trace["master_label_identity_key"] = identity_key
    return {key: value for key, value in trace.items() if value}


def build_tray_complete_detail(
    tray: Any,
    *,
    master_label_fields: Dict[str, Any],
    end_time: datetime.datetime,
) -> Dict[str, Any]:
    scanned_barcodes = _validated_scanned_barcodes(getattr(tray, "scanned_barcodes", None))
    tray_capacity = _require_positive_int(getattr(tray, "tray_size", None), "tray_capacity")
    if len(scanned_barcodes) > tray_capacity:
        raise ValueError("scan_count must not exceed tray_capacity")
    master_label_code = _require_text(getattr(tray, "master_label_code", None), "master_label_code")
    item_code = _require_text(getattr(tray, "item_code", None), "item_code")
    if not isinstance(master_label_fields, dict):
        raise ValueError("master_label_fields must be a mapping")
    label_fields = dict(master_label_fields or {})
    label_item_code = str(label_fields.get("CLC") or "").strip()
    if label_item_code and label_item_code != item_code:
        raise ValueError("master_label_fields CLC must match item_code")
    if "QT" in label_fields and str(label_fields.get("QT") or "").strip():
        label_quantity = parse_positive_quantity(label_fields)
        if label_quantity is None:
            raise ValueError("master_label_fields QT must be a positive integer")
        if label_quantity != tray_capacity:
            raise ValueError("master_label_fields QT must match tray_capacity")
    detail = {
        "master_label_code": master_label_code,
        "item_code": item_code,
        "item_name": tray.item_name,
        "item_spec": tray.item_spec,
        "spec": tray.item_spec,
        "scan_count": len(scanned_barcodes),
        "tray_capacity": tray_capacity,
        "scanned_product_barcodes": scanned_barcodes,
        "product_barcodes": scanned_barcodes,
        "work_time_sec": tray.stopwatch_seconds,
        "error_count": tray.mismatch_error_count,
        "total_idle_seconds": tray.total_idle_seconds,
        "has_error_or_reset": tray.has_error_or_reset,
        "is_partial_submission": tray.is_partial_submission,
        "is_restored_session": tray.is_restored_session,
        "is_test_tray": tray.is_test_tray,
        "start_time": tray.start_time.isoformat() if tray.start_time else None,
        "end_time": end_time.isoformat(),
        "master_label_fields": label_fields,
        "quantity_basis": "PRODUCT_BARCODE" if scanned_barcodes else "SESSION_QTY",
        "confidence": "BARCODE" if scanned_barcodes else "LOW_CONFIDENCE",
        "qty_uom": "piece",
        "measure_code": "STATE_QTY",
        "barcode_count": len(set(scanned_barcodes)),
    }
    inspection_trace = inspection_trace_from_master_label_fields(master_label_code, label_fields)
    if any(inspection_trace.get(key) for key in ("input_tag_id", "input_tag_label_id", "input_tag_core_hash", "input_tag_label_hash")):
        detail.update({
            key: inspection_trace[key]
            for key in (
                "input_tag_id",
                "input_tag_label_id",
                "input_tag_core_hash",
                "input_tag_label_hash",
            )
            if key in inspection_trace
        })
        detail.setdefault("source_session_id", inspection_trace["input_tag_id"])
        detail["inspection_trace"] = inspection_trace
    return detail


def build_scan_ok_detail(
    barcode: str,
    *,
    interval_sec: float,
    scan_position: int,
    scan_contract_version: str,
) -> Dict[str, Any]:
    product_barcode = _require_text(barcode, "product_barcode")
    interval = _require_non_negative_finite_number(interval_sec, "interval_sec")
    position = _require_positive_int(scan_position, "scan_position")
    contract_version = _require_text(scan_contract_version, "scan_contract_version")
    return {
        "barcode": product_barcode,
        "interval_sec": f"{interval:.2f}",
        "scan_position": position,
        "barcode_role": "product",
        "raw_barcode": product_barcode,
        "parsed_barcode": product_barcode,
        "product_barcode": product_barcode,
        "scan_contract_version": contract_version,
    }


def corrected_product_barcodes(
    original_details: Dict[str, Any],
    *,
    additional_items: Iterable[str] = (),
    removed_items: Iterable[str] = (),
) -> List[str]:
    corrected = product_barcodes_from_completion(original_details)
    corrected.extend(additional_items or [])
    removed = set(removed_items or [])
    if removed:
        corrected = [barcode for barcode in corrected if barcode not in removed]
    return corrected


def _replacement_item_code(original_details: Dict[str, Any], new_master_label_fields: Dict[str, Any]) -> str:
    for key in ("item_code", "item", "product_code"):
        value = str(original_details.get(key) or "").strip()
        if value:
            return value
    return str(new_master_label_fields.get("CLC") or "").strip()


def _barcodes_without_item_code(barcodes: Iterable[str], item_code: str) -> List[str]:
    expected = str(item_code or "").strip()
    if not expected:
        return []
    return [barcode for barcode in barcodes if expected not in barcode]


def validate_replacement_delta(
    original_details: Dict[str, Any],
    *,
    additional_items: Iterable[str] = (),
    removed_items: Iterable[str] = (),
    new_qty: int | None = None,
    expected_item_code: str = "",
) -> None:
    original_barcodes = product_barcodes_from_completion(original_details)
    original_set = set(original_barcodes)
    added_barcodes = list(additional_items or [])
    removed_barcodes = list(removed_items or [])
    if len(set(added_barcodes)) != len(added_barcodes):
        raise ValueError("replacement additional product barcodes must be unique")
    if len(set(removed_barcodes)) != len(removed_barcodes):
        raise ValueError("replacement removed product barcodes must be unique")
    missing_removed = [barcode for barcode in removed_barcodes if barcode not in original_set]
    if missing_removed:
        raise ValueError("replacement removed product barcode is not in original completion")
    overlapping_added = [barcode for barcode in added_barcodes if barcode in original_set]
    if overlapping_added:
        raise ValueError("replacement additional product barcode already exists in original completion")
    corrected_barcodes = corrected_product_barcodes(
        original_details,
        additional_items=added_barcodes,
        removed_items=removed_barcodes,
    )
    if _barcodes_without_item_code(added_barcodes, expected_item_code):
        raise ValueError("replacement additional product barcode item_code mismatch")
    if _barcodes_without_item_code(corrected_barcodes, expected_item_code):
        raise ValueError("replacement corrected product barcode item_code mismatch")
    corrected_count = len(corrected_product_barcodes(
        original_details,
        additional_items=added_barcodes,
        removed_items=removed_barcodes,
    ))
    if new_qty is not None and int(new_qty) != corrected_count:
        raise ValueError("replacement corrected barcode count does not match new quantity")


def build_master_label_replacement_detail(
    *,
    original_details: Dict[str, Any],
    old_label: str,
    new_label: str,
    source_system: str,
    source_transport_or_dataset: str,
    source_file_id: str,
    source_row_number: int,
    source_byte_offset: Any,
    operator: str,
    stable_hash_func: Callable[[Dict[str, Any]], str],
    old_row_hash: str | None = None,
    old_qty: int | None = None,
    new_qty: int | None = None,
    additional_items: Iterable[str] = (),
    removed_items: Iterable[str] = (),
) -> Dict[str, Any]:
    original_details = dict(original_details)
    original_master_label = str(original_details.get("master_label_code") or "").strip()
    if (
        original_master_label
        and old_label
        and canonical_master_label_key(original_master_label) != canonical_master_label_key(old_label)
    ):
        raise ValueError("replacement old master label does not match original completion")
    corrected_details = dict(original_details)
    corrected_details["master_label_code"] = new_label
    for trace_key in (
        "master_label_fields",
        "input_tag_id",
        "input_tag_label_id",
        "input_tag_core_hash",
        "input_tag_label_hash",
        "inspection_trace",
    ):
        corrected_details.pop(trace_key, None)
    added_barcodes = list(additional_items or [])
    removed_barcodes = list(removed_items or [])
    new_master_label_fields = parse_new_format_qr(new_label) or {}
    expected_item_code = _replacement_item_code(original_details, new_master_label_fields)
    new_label_item_code = str(new_master_label_fields.get("CLC") or "").strip()
    if expected_item_code and new_label_item_code and expected_item_code != new_label_item_code:
        raise ValueError("replacement new master label item_code does not match corrected item_code")
    if expected_item_code and not str(corrected_details.get("item_code") or "").strip():
        corrected_details["item_code"] = expected_item_code
    validate_replacement_delta(
        original_details,
        additional_items=added_barcodes,
        removed_items=removed_barcodes,
        new_qty=new_qty,
        expected_item_code=expected_item_code,
    )
    corrected_barcodes = corrected_product_barcodes(
        corrected_details,
        additional_items=added_barcodes,
        removed_items=removed_barcodes,
    )
    corrected_details["scanned_product_barcodes"] = corrected_barcodes
    corrected_details["product_barcodes"] = corrected_barcodes
    corrected_details["scan_count"] = len(corrected_barcodes)
    corrected_details["barcode_count"] = len(set(corrected_barcodes))
    if new_master_label_fields:
        corrected_details["master_label_fields"] = new_master_label_fields
        inspection_trace = inspection_trace_from_master_label_fields(new_label, new_master_label_fields)
        if any(
            inspection_trace.get(key)
            for key in ("input_tag_id", "input_tag_label_id", "input_tag_core_hash", "input_tag_label_hash")
        ):
            corrected_details.update({
                key: inspection_trace[key]
                for key in (
                    "input_tag_id",
                    "input_tag_label_id",
                    "input_tag_core_hash",
                    "input_tag_label_hash",
                )
                if key in inspection_trace
            })
            corrected_details.setdefault("source_session_id", inspection_trace["input_tag_id"])
            corrected_details["inspection_trace"] = inspection_trace
        parsed_capacity = parse_positive_quantity(new_master_label_fields)
        if parsed_capacity is not None:
            corrected_details["tray_capacity"] = parsed_capacity

    old_payload_hash = stable_hash_func(original_details)
    new_payload_hash = stable_hash_func(corrected_details)
    old_row_hash = old_row_hash or old_payload_hash
    new_row_hash = stable_hash_func(
        {
            "source_system": source_system,
            "source_transport_or_dataset": source_transport_or_dataset,
            "source_file_id": source_file_id,
            "source_row_number": source_row_number,
            "source_byte_offset": source_byte_offset,
            "payload_hash": new_payload_hash,
        }
    )

    return {
        "transfer_id": original_details.get("transfer_id")
        or original_details.get("bundle_id")
        or original_details.get("packaging_set_identity"),
        "item_code": expected_item_code
        or original_details.get("item_code")
        or original_details.get("item")
        or original_details.get("product_code"),
        "product_barcodes": corrected_barcodes,
        "old_master_label": old_label,
        "new_master_label": new_label,
        "original_event_identity": {
            "source_system": source_system,
            "source_transport_or_dataset": source_transport_or_dataset,
            "source_file_id": source_file_id,
            "source_row_number": source_row_number,
            "source_byte_offset": source_byte_offset,
            "row_hash": old_row_hash,
            "raw_event_name": "TRAY_COMPLETE",
        },
        "supersedes_identity": {
            "source_system": source_system,
            "source_transport_or_dataset": source_transport_or_dataset,
            "source_file_id": source_file_id,
            "source_row_number": source_row_number,
            "source_byte_offset": source_byte_offset,
            "row_hash": old_row_hash,
            "old_payload_hash": old_payload_hash,
        },
        "old_qty": old_qty,
        "new_qty": new_qty,
        "added_product_barcodes": added_barcodes,
        "removed_product_barcodes": removed_barcodes,
        "projection_schema_version": "container-audit-corrected-completion-v1",
        "corrected_completion_projection": corrected_details,
        "old_payload_hash": old_payload_hash,
        "new_payload_hash": new_payload_hash,
        "old_row_hash": old_row_hash,
        "new_row_hash": new_row_hash,
        "reason": "operator_master_label_replacement",
        "operator": operator,
        "evidence_hash": stable_hash_func(
            {
                "old_payload_hash": old_payload_hash,
                "new_payload_hash": new_payload_hash,
                "operator": operator,
                "source_file_id": source_file_id,
                "source_row_number": source_row_number,
            }
        ),
    }
