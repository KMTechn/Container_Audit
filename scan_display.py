"""Display-only formatting for the Container Audit current-tray scan list.

Raw product barcodes remain the source of truth for tray state, duplicate
checks, event payloads, and ledger/API handoff.  This module only creates a
short, non-sensitive label for an operator-facing list row.
"""

from __future__ import annotations

import hashlib
import re


UNKNOWN_ITEM_LABEL = "품목 미확인"
HASH_PREFIX = "ID #"
HASH_HEX_LENGTH = 10
MAX_IDENTIFIER_CHARS = 12
LONG_IDENTIFIER_HASH_HEX_LENGTH = 5

_SAFE_ITEM_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,23}$")
_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_SIMPLE_SEPARATOR_RE = re.compile(r"^[-_./:]+")
_STRUCTURED_SEPARATOR = r"(?:^|[|;,])"
_IDENTIFIER_KEYS: tuple[tuple[str, str], ...] = (
    ("SERIAL", "SN"),
    ("SNO", "SN"),
    ("SN", "SN"),
    ("ITG", "ITG"),
    ("LBL", "LBL"),
    ("WID", "WID"),
    ("BND", "BND"),
    ("TRACE", "TRACE"),
    ("LOT", "LOT"),
)


def _raw_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return str(value)


def _safe_item_code(value: object) -> str:
    item_code = _raw_text(value).strip()
    if _SAFE_ITEM_CODE_RE.fullmatch(item_code):
        return item_code
    return UNKNOWN_ITEM_LABEL


def _stable_identifier(raw_barcode: str) -> str:
    digest = hashlib.sha256(raw_barcode.encode("utf-8", errors="replace")).hexdigest()
    return f"{HASH_PREFIX}{digest[:HASH_HEX_LENGTH]}"


def _bounded_identifier(value: str) -> str | None:
    candidate = value.strip()
    if not candidate or not _SAFE_IDENTIFIER_RE.fullmatch(candidate):
        return None
    if len(candidate) <= MAX_IDENTIFIER_CHARS:
        return candidate
    digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    suffix_length = MAX_IDENTIFIER_CHARS - LONG_IDENTIFIER_HASH_HEX_LENGTH - 2
    return (
        f"#{digest[:LONG_IDENTIFIER_HASH_HEX_LENGTH]}"
        f"…{candidate[-suffix_length:]}"
    )


def _structured_identifier(raw_barcode: str) -> str | None:
    """Return the highest-priority safe identifier field, if one exists."""

    for field_name, display_name in _IDENTIFIER_KEYS:
        pattern = re.compile(
            rf"{_STRUCTURED_SEPARATOR}\s*{re.escape(field_name)}\s*[:=]\s*([^|;,]+)",
            re.IGNORECASE,
        )
        match = pattern.search(raw_barcode)
        if match is None:
            continue
        identifier = _bounded_identifier(match.group(1))
        if identifier is not None:
            return f"{display_name} {identifier}"
    return None


def compact_scan_value(raw_barcode: object, *, item_code: object) -> str:
    """Return ``item code · concise ID`` without exposing a full telegram.

    The item code is accepted only from the caller's active tray context.  It
    is never inferred from a CLC or similar field embedded in the raw scan.
    Unknown or unsafe formats fail closed to a stable short SHA-256 identity.
    """

    raw_text = _raw_text(raw_barcode)
    display_item_code = _safe_item_code(item_code)

    identifier = _structured_identifier(raw_text)
    trusted_item_code = display_item_code if display_item_code != UNKNOWN_ITEM_LABEL else ""
    if identifier is None and trusted_item_code and raw_text.startswith(trusted_item_code):
        suffix = _SIMPLE_SEPARATOR_RE.sub("", raw_text[len(trusted_item_code):], count=1)
        identifier = _bounded_identifier(suffix)
    if identifier is None:
        identifier = _stable_identifier(raw_text)

    return f"{display_item_code} · {identifier}"


def format_scan_list_row(position: object, raw_barcode: object, *, item_code: object) -> str:
    """Format one newest-first Listbox row without mutating the raw scan."""

    if isinstance(position, bool):
        row_number = "?"
    else:
        try:
            parsed_position = int(position)
        except (TypeError, ValueError, OverflowError):
            row_number = "?"
        else:
            row_number = str(parsed_position) if parsed_position > 0 else "?"
    return f"({row_number}) {compact_scan_value(raw_barcode, item_code=item_code)}"
