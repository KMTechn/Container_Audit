import base64
import binascii
import json
from typing import Dict, List, Optional, Tuple

# Transition mode records every completion under one of these classes; LM uses the same names.
TRANSITION_LEGACY = "LEGACY"
TRANSITION_PHS2_CENTRAL = "PHS2_CENTRAL"
TRANSITION_PHS2_LOCAL = "PHS2_LOCAL"
TRANSITION_PHS2_MALFORMED = "PHS2_MALFORMED"
TRANSITION_CLASSES = (
    TRANSITION_LEGACY,
    TRANSITION_PHS2_CENTRAL,
    TRANSITION_PHS2_LOCAL,
    TRANSITION_PHS2_MALFORMED,
)
# Seal status of a transition completion recorded on this PC only (no lease, seal or ledger).
TRANSITION_LOCAL_SEAL_STATUS = {
    TRANSITION_LEGACY: "LEGACY_LOCAL_ONLY",
    TRANSITION_PHS2_LOCAL: "PHS2_LOCAL_ONLY",
    TRANSITION_PHS2_MALFORMED: "PHS2_MALFORMED_LOCAL_ONLY",
}


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


def parse_label_fields_leniently(qr_data: str) -> Optional[Tuple[Dict[str, str], List[str]]]:
    """Read a label as CA v2.0.9 did (last duplicate key wins, stray segments skipped).

    Returns the fields with the defects the strict parser refuses, or None when
    the input is not a QR label at all (for example a 13-digit item code).
    """
    text = str(qr_data or "")
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        duplicate = False

        def keep_last(pairs):
            nonlocal duplicate
            parsed_pairs = {}
            for key, value in pairs:
                key = str(key).strip()
                duplicate = duplicate or key in parsed_pairs
                parsed_pairs[key] = value
            return parsed_pairs

        try:
            parsed = json.loads(stripped, object_pairs_hook=keep_last)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            fields = {key: str(value).strip() for key, value in parsed.items()}
            return fields, ["DUPLICATE_KEY"] if duplicate else []

    if "=" in text and "|" in text:
        fields: Dict[str, str] = {}
        defects: List[str] = []
        for pair in text.split("|"):
            if not pair.strip():
                continue
            key, separator, value = pair.partition("=")
            key = key.strip()
            if not separator or not key:
                defects.append("FORMAT_INVALID")
                continue
            if key in fields:
                defects.append("DUPLICATE_KEY")
            fields[key] = value.strip()
        if fields:
            return fields, list(dict.fromkeys(defects))
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
