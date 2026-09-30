import base64
import binascii
import json
import re
import unicodedata
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
# Values only the new system prints on a label.
NEW_SYSTEM_IDENTITY_KEYS = (
    "ITG", "LBL", "HSH", "HSH_CORE", "HSH_LABEL", "BND", "BUNDLE_ID", "SOURCE_BUNDLE_ID",
)
# Local CSV classification stays fixed; valid PHS2_LOCAL also queues a deferred seal.
TRANSITION_LOCAL_SEAL_STATUS = {
    TRANSITION_LEGACY: "LEGACY_LOCAL_ONLY",
    TRANSITION_PHS2_LOCAL: "PHS2_LOCAL_ONLY",
    TRANSITION_PHS2_MALFORMED: "PHS2_MALFORMED_LOCAL_ONLY",
}


def transition_reason_code(code: object) -> str:
    """A reason in the shared code shape (A-Z, 0-9, _), e.g. from a server error code."""
    return re.sub(r"[^A-Z0-9_]+", "_", str(code or "").upper()).strip("_") or "UNKNOWN"


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
        if qr_data.startswith("PHS=2|") and "|QT=" in qr_data and len(qr_data.split("|")) == 7:
            segments = qr_data.split("|")
            if ([segment.split("=", 1)[0] for segment in segments]
                != ["PHS", "SRC", "ITG", "CLC", "LBL", "HSH", "QT"]
                or not re.fullmatch(r"QT=[1-9][0-9]{0,3}", segments[-1])):
                return None
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


def is_new_system_label_pair(key: str, value: object) -> bool:
    """PHS=2, SRC=KMTECH_INPUT_TAG or any new-system identity value."""
    text = str(value or "").strip()
    return bool(
        (key == "PHS" and text == "2")
        or (key == "SRC" and text.upper() == "KMTECH_INPUT_TAG")
        or (key in NEW_SYSTEM_IDENTITY_KEYS and text)
    )


# ---- Transition label rules shared by Container_Audit (label_qr.py) and
# Label_Match (label_transition.py).  Keep this block identical in both; both
# run the same vectors (tests/transition_label_vectors.json).
TRANSITION_LABEL_LEGACY = "LEGACY"
TRANSITION_LABEL_NEW = "NEW"
TRANSITION_LABEL_MALFORMED = "MALFORMED"
# Every label defect is recorded once, in this order; then DUPLICATE_LABEL,
# then what blocked the central path.
TRANSITION_REASON_ORDER = (
    "DUPLICATE_KEY", "PHS_EMPTY", "PHS_MISSING", "PHS_NOT_2", "LINEAGE_MISSING",
    "QT_INVALID", "FORMAT_INVALID", "SEALED_QR_INVALID", "ITEM_UNCONFIRMED",
)
# Keys only the new system prints: present at all, they mark a new label.
_TRANSITION_LINEAGE_KEYS = frozenset(("TRF", "BND", "ITG"))
# Values only the new system prints: a non-empty one marks a new label.
_TRANSITION_IDENTITY_VALUE_KEYS = frozenset((
    "LBL", "HSH", "HSH_CORE", "HSH_LABEL", "BUNDLE_ID", "SOURCE_BUNDLE_ID",
))
_TRANSITION_QUANTITY_KEYS = frozenset(("QT", "QTY", "QUANTITY"))
_TRANSITION_COMPACT_KEYS = ("PHS", "SRC", "ITG", "CLC", "LBL", "HSH")


class _TransitionJsonPairs(list):
    pass


def transition_label_pairs(text):
    """(pairs, is_json): every (KEY, value) of a pipe or JSON label in scan
    order with repeats kept; value None when a segment has no '='.  Keys are
    upper-case, keys and values trimmed, empty segments skipped.  No pairs:
    not a label (13 digits, no '|', another separator)."""

    stripped = str(text or "").strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            parsed = json.loads(stripped, object_pairs_hook=_TransitionJsonPairs)
        except ValueError:
            parsed = None
        if isinstance(parsed, _TransitionJsonPairs):
            return [(str(key).strip().upper(), str(value).strip()) for key, value in parsed], True
    if "|" not in stripped:
        return [], False
    pairs = []
    for segment in stripped.split("|"):
        if segment.strip():
            key, separator, value = segment.partition("=")
            pairs.append((key.strip().upper(), value.strip() if separator else None))
    return pairs, False


def _transition_old_qr_readable(pairs, is_json):
    """Whether the old QR reader (CLC, SPC and PHS, with the CLC=INSPECTION
    aliases; the last value wins) reads the label."""

    if is_json:
        return False
    fields = {key: value for key, value in pairs if value is not None}
    if str(fields.get("CLC") or "").upper() == "INSPECTION":
        item = str(fields.get("ITEM") or fields.get("ITEM_CODE") or "")
        if not item:
            return False
        fields = dict(fields, CLC=item)
        fields.setdefault("SPC", str(fields.get("ITEM_NAME") or item))
        fields.setdefault("PHS", str(fields.get("PHASE") or "INSPECTION"))
    return all(fields.get(key) for key in ("CLC", "SPC", "PHS"))


def transition_label_item_code(pairs):
    """The label's item: CLC, or ITEM/ITEM_CODE for CLC=INSPECTION or no CLC."""

    fields = {key: value for key, value in pairs if value}
    clc = str(fields.get("CLC") or "")
    alias = str(fields.get("ITEM") or fields.get("ITEM_CODE") or "")
    return alias if clc.upper() == "INSPECTION" else (clc or alias)


def transition_label_text_defects(pairs):
    """Defects of any label's text: a repeated key (two quantity keys count),
    a quantity that is not a positive integer, a segment without '=' or key."""

    keys = [key for key, _value in pairs]
    defects = []
    if (
        any(keys.count(key) > 1 for key in keys if key)
        or sum(key in _TRANSITION_QUANTITY_KEYS for key in keys) > 1
    ):
        defects.append("DUPLICATE_KEY")
    if any(
        key in _TRANSITION_QUANTITY_KEYS and not re.fullmatch(r"[0-9]*[1-9][0-9]*", value or "")
        for key, value in pairs
    ):
        defects.append("QT_INVALID")
    if any(value is None or not key for key, value in pairs):
        defects.append("FORMAT_INVALID")
    return defects


def _transition_compact_label(text):
    """Central identity, optionally followed by the printed positive quantity."""

    fields = {}
    parts = str(text or "").strip().split("|")
    for part, expected in zip(parts, _TRANSITION_COMPACT_KEYS):
        key, separator, value = part.partition("=")
        if key.strip() != expected or not separator or "=" in value or not value.strip():
            return False
        fields[expected] = value.strip()
    return (
        (len(parts) == len(_TRANSITION_COMPACT_KEYS) or (
            len(parts) == len(_TRANSITION_COMPACT_KEYS) + 1
            and re.fullmatch(r"QT=[1-9][0-9]{0,3}", parts[-1]) is not None
        ))
        and fields["PHS"] == "2"
        and fields["SRC"].upper() == "KMTECH_INPUT_TAG"
        and re.fullmatch(r"[0-9A-Fa-f]{16}", fields["HSH"]) is not None
        and all(
            len(fields[key]) <= 256
            and not any(unicodedata.category(character).startswith("C") for character in fields[key])
            for key in ("ITG", "CLC", "LBL")
        )
    )


def transition_ordered_reasons(reasons):
    order = {code: index for index, code in enumerate(TRANSITION_REASON_ORDER)}
    return tuple(sorted(dict.fromkeys(reasons), key=lambda code: order.get(code, len(order))))


def classify_transition_label(text):
    """(kind, reasons, item_code) of one decoded start label.

    LEGACY: no new-system marker, or an old QR the old reader reads without a
    lineage key (an old phase QR with PHS=2 or an LBL value stays LEGACY).
    A marker is PHS=2, SRC=KMTECH_INPUT_TAG, a TRF/BND/ITG key or an
    LBL/HSH/HSH_CORE/HSH_LABEL/BUNDLE_ID/SOURCE_BUNDLE_ID value, in any
    occurrence.  NEW: the exact compact central label.  MALFORMED: any other
    marked label, with every defect.
    """

    pairs, is_json = transition_label_pairs(text)
    keys = {key for key, _value in pairs}
    fields = {key: value for key, value in pairs if value}
    item_code = transition_label_item_code(pairs)
    lineage = bool(_TRANSITION_LINEAGE_KEYS & keys) or any(
        key == "SRC" and str(value or "").upper() == "KMTECH_INPUT_TAG" for key, value in pairs
    )
    marked = lineage or any(
        (key == "PHS" and value == "2") or (key in _TRANSITION_IDENTITY_VALUE_KEYS and value)
        for key, value in pairs
    )
    reasons = transition_label_text_defects(pairs)
    if not marked or (not lineage and _transition_old_qr_readable(pairs, is_json)):
        return TRANSITION_LABEL_LEGACY, transition_ordered_reasons(reasons), item_code
    phases = [value for key, value in pairs if key == "PHS"]
    if not phases:
        reasons.append("PHS_MISSING")
    if "" in phases:
        reasons.append("PHS_EMPTY")
    if any(value and value != "2" for value in phases):
        reasons.append("PHS_NOT_2")
    if not all(fields.get(key) for key in ("SRC", "ITG", "LBL", "HSH")):
        reasons.append("LINEAGE_MISSING")
    elif item_code and not reasons and not _transition_compact_label(text):
        reasons.append("FORMAT_INVALID")
    if not item_code:
        reasons.append("ITEM_UNCONFIRMED")
    kind = TRANSITION_LABEL_MALFORMED if reasons else TRANSITION_LABEL_NEW
    return kind, transition_ordered_reasons(reasons), item_code


def transition_start_reasons(label_reasons=(), *, item_unconfirmed=False, duplicate=False, blocked=()):
    """A start's reasons in the shared order: label defects, ITEM_UNCONFIRMED,
    DUPLICATE_LABEL, then what blocked the central path."""

    reasons = list(transition_ordered_reasons(
        [*label_reasons, *(["ITEM_UNCONFIRMED"] if item_unconfirmed else [])]
    ))
    if duplicate:
        reasons.append("DUPLICATE_LABEL")
    return list(dict.fromkeys([*reasons, *blocked]))
# ---- End of the shared transition label rules.


def decode_transition_label(raw_value: str) -> str:
    """Scanner Base64 as Label_Match reads it (carrier_identity_port.decode_carrier_scan).

    Transition mode applies it to a label the strict decoder below left
    encoded (URL-safe, or a label the strict parser refuses).
    """
    text = str(raw_value or "").strip()
    if not text or "|" in text or len(text) <= 20:
        return text
    try:
        padded = text.replace("-", "+").replace("_", "/")
        decoded = base64.b64decode(padded + "=" * (-len(padded) % 4)).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return text
    return decoded if "|" in decoded and "=" in decoded else text


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
