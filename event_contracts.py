import hashlib
import json
import unicodedata
from typing import Any, Dict


def plan_b_event_detail(
    event_type: str,
    detail: Dict[str, Any],
    *,
    source_system: str,
    source_transport_or_dataset: str,
    canonical_event_name: str | None = None,
) -> Dict[str, Any]:
    enriched = dict(detail or {})
    enriched["source_system"] = source_system
    enriched["source_transport_or_dataset"] = source_transport_or_dataset
    enriched["raw_event_name"] = event_type
    enriched["canonical_event_name"] = canonical_event_name or event_type
    enriched["dispatch_key"] = f"{source_system}|{source_transport_or_dataset}|{event_type}"
    enriched["identity_class"] = "LEGACY_FALLBACK"
    enriched["integrity_requirement"] = "UNSIGNED_LEGACY_ALLOWED"
    enriched["integrity_status"] = "UNSIGNED_LEGACY"
    enriched["parser_mapping_version"] = "container-audit-plan-b-v1"
    return enriched


def _normalize_for_json(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize_for_json(item) for item in value]
    if isinstance(value, dict):
        normalized: Dict[str, Any] = {}
        for key in sorted(value):
            normalized_key = unicodedata.normalize("NFC", str(key))
            if normalized_key in normalized:
                raise ValueError("stable_hash keys collide after Unicode normalization")
            normalized[normalized_key] = _normalize_for_json(value[key])
        return normalized
    return value


def stable_hash(data: Dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            _normalize_for_json(data or {}),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
