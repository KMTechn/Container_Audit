import base64
import binascii
import json
from typing import Dict, Optional


class _MalformedQrJson(ValueError):
    pass


def _normalized_json_object(pairs):
    parsed_data = {}
    for key, value in pairs:
        normalized_key = str(key).strip()
        if not normalized_key or normalized_key in parsed_data:
            raise _MalformedQrJson("malformed QR JSON object")
        parsed_data[normalized_key] = str(value).strip()
    return parsed_data


def parse_new_format_qr(qr_data: str) -> Optional[Dict[str, str]]:
    if qr_data.strip().startswith("{") and qr_data.strip().endswith("}"):
        try:
            parsed = json.loads(qr_data, object_pairs_hook=_normalized_json_object)
            if isinstance(parsed, dict):
                return parsed
            return None
        except (json.JSONDecodeError, _MalformedQrJson):
            pass

    if "=" in qr_data and "|" in qr_data:
        parsed_data = {}
        try:
            pairs = qr_data.split("|")
            for pair in pairs:
                if not pair.strip():
                    continue
                if "=" not in pair:
                    return None
                key, value = pair.split("=", 1)
                key = key.strip()
                if not key or key in parsed_data:
                    return None
                parsed_data[key] = value.strip()
            return parsed_data if parsed_data else None
        except Exception:
            return None

    return None


def normalize_master_label_input(raw_value: str) -> str:
    value = str(raw_value or "").strip()
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return value
    return decoded if parse_new_format_qr(decoded) else value


def canonical_master_label_key(raw_value: str) -> str:
    value = normalize_master_label_input(raw_value)
    parsed = parse_new_format_qr(value)
    if parsed:
        return "qr:" + json.dumps(parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "raw:" + value


def inspection_master_item_code(qr_data: Dict[str, str]) -> str:
    if not qr_data:
        return ""
    clc = str(qr_data.get("CLC") or "").strip()
    item = str(qr_data.get("ITEM") or qr_data.get("ITEM_CODE") or "").strip()
    if clc.upper() == "INSPECTION" and item:
        return item
    return clc


def parse_positive_quantity(qr_data: Dict[str, str], *, default: Optional[int] = None) -> Optional[int]:
    raw_quantity = None
    if qr_data:
        for key in ("QT", "QTY", "QUANTITY"):
            if qr_data.get(key) not in (None, ""):
                raw_quantity = qr_data.get(key)
                break
    if raw_quantity in (None, ""):
        return default
    try:
        quantity = int(str(raw_quantity).strip())
    except (TypeError, ValueError):
        return None
    return quantity if quantity > 0 else None
