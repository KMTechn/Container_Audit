"""Durable exact-membership transfer sealing for Container Audit."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import quote, unquote, urlencode, urlsplit

from logistics_runtime_profile import (
    LogisticsRuntimeConfigurationError,
    load_logistics_runtime_profile,
    logistics_runtime_required,
)


SCHEMA_VERSION = "container-audit-transfer-seal-v1"
CONTRACT_VERSION = "logistics-v1"
COMMAND_TYPE = "SEAL_TRANSFER_BUNDLE"
PENDING_STATUSES = ("PREPARED", "COMMAND_READY", "RETRY_WAIT")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _normalize_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not normalized or "\x00" in normalized:
        raise ValueError(f"{field} must be non-empty safe text")
    return normalized


def normalize_barcode(value: Any) -> str:
    return _normalize_identifier(value, "barcode").upper()


def membership_hash(member_ids: Iterable[str]) -> str:
    members = sorted(_normalize_identifier(value, "member_id") for value in member_ids)
    if not members or len(set(members)) != len(members):
        raise ValueError("membership must be non-empty and unique")
    return _sha256(members)


def _deterministic_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{_sha256(value)[:24].upper()}"


def source_identity_from_label(master_label_fields: Mapping[str, Any]) -> dict[str, str]:
    fields = dict(master_label_fields or {})
    clc = str(fields.get("CLC") or "").strip()
    item_alias = str(fields.get("ITEM") or fields.get("ITEM_CODE") or "").strip()
    item_id = item_alias if clc.upper() == "INSPECTION" and item_alias else (clc or item_alias)
    input_tag_id = str(fields.get("ITG") or "").strip()
    input_tag_label_id = str(fields.get("LBL") or "").strip()
    source_kind = str(fields.get("SRC") or "").strip()
    input_tag_hash_prefix = (
        str(fields.get("HSH") or "").strip().lower()
        if str(fields.get("PHS") or "").strip() == "2"
        and source_kind.upper() == "KMTECH_INPUT_TAG"
        else ""
    )
    compat_work_order_id = str(fields.get("WID") or fields.get("WORK_ORDER_ID") or "").strip()
    is_input_tag = source_kind.upper() == "KMTECH_INPUT_TAG" or bool(input_tag_id)
    source_bundle_id = str(
        fields.get("BND") or fields.get("BUNDLE_ID") or fields.get("SOURCE_BUNDLE_ID") or ""
    ).strip()
    authority_scope_id = str(
        fields.get("AUTH_SCOPE") or fields.get("AUTHORITY_SCOPE_ID") or ""
    ).strip()
    return {
        "source_bundle_id": source_bundle_id,
        "input_tag_id": input_tag_id,
        "input_tag_label_id": input_tag_label_id,
        "input_tag_hash_prefix": input_tag_hash_prefix,
        "compat_work_order_id": compat_work_order_id,
        "source_kind": source_kind,
        "external_label": "" if is_input_tag else str(
            fields.get("PHS_EXTERNAL_ID") or compat_work_order_id or ""
        ).strip(),
        "authority_scope_id": authority_scope_id,
        "item_id": item_id,
    }


class TransferSealError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 0,
        retryable: bool = False,
        committed: bool | None = False,
        details: Mapping[str, Any] | None = None,
    ):
        super().__init__(message)
        self.code = str(code or "transfer_seal_error")
        self.status_code = int(status_code or 0)
        self.retryable = bool(retryable)
        self.committed = committed
        self.details = dict(details or {})


@dataclass(frozen=True)
class TransferSourcePreflight:
    """Validated completed PHS source used to size one transfer tray."""

    source_bundle_id: str
    source_session_id: str
    authority_scope_id: str
    ledger_plane: str
    plane_epoch: int
    item_id: str
    uom: str
    source_iin: str
    member_ids: tuple[str, ...]
    normalized_barcodes: tuple[str, ...]
    membership_hash: str
    barcode_membership_hash: str
    input_tag_id: str
    input_tag_label_id: str
    input_tag_hash_prefix: str
    input_tag_core_hash: str
    input_tag_label_hash: str
    source_resolution_basis: str = "IMMUTABLE_INPUT_TAG"
    source_bundle_ids: tuple[str, ...] = ()
    source_session_ids: tuple[str, ...] = ()
    source_bundles: tuple[dict[str, Any], ...] = ()
    entity_versions: dict[str, int] = field(default_factory=dict)
    phs_work_group: dict[str, Any] = field(default_factory=dict)
    remainder_cover_groups: tuple[dict[str, Any], ...] = ()
    topology_hash: str = ""
    transfer_bundle_id: str = ""
    transfer_external_label: str = ""
    canonical_input_tag_qr: str = ""
    active_label_qr_payload: str = ""
    active_label_id: str = ""
    active_label_business_date: str = ""
    active_label_worker_code: str = ""
    active_label_resolution: str = "LEGACY_ACTIVE"
    scanned_label_id: str = ""
    replaced_scan: bool = False

    @property
    def member_count(self) -> int:
        return len(self.member_ids)

    def audit_detail(self) -> dict[str, Any]:
        return {
            "contract_version": "container-audit-phs2-preflight-v1",
            "quantity_basis": "CENTRAL_EXACT_MEMBERSHIP",
            "source_bundle_id": self.source_bundle_id,
            "source_session_id": self.source_session_id,
            "authority_scope_id": self.authority_scope_id,
            "ledger_plane": self.ledger_plane,
            "plane_epoch": self.plane_epoch,
            "item_id": self.item_id,
            "uom": self.uom,
            "source_iin": self.source_iin,
            "member_count": self.member_count,
            "membership_hash": self.membership_hash,
            "barcode_membership_hash": self.barcode_membership_hash,
            "input_tag_id": self.input_tag_id,
            "input_tag_label_id": self.input_tag_label_id,
            "input_tag_hash_prefix": self.input_tag_hash_prefix,
            "input_tag_lifecycle": "INSPECTION_COMPLETED",
            "source_resolution_basis": self.source_resolution_basis,
            "source_bundle_ids": list(self.source_bundle_ids),
            "source_session_ids": list(self.source_session_ids),
            "source_bundle_count": len(self.source_bundle_ids),
            "topology_hash": self.topology_hash,
            "transfer_bundle_id": self.transfer_bundle_id,
            "canonical_input_tag_qr": self.canonical_input_tag_qr,
            "active_label_qr_payload": self.active_label_qr_payload,
            "active_label_id": self.active_label_id,
            "active_label_business_date": self.active_label_business_date,
            "active_label_worker_code": self.active_label_worker_code,
            "active_label_resolution": self.active_label_resolution,
            "scanned_label_id": self.scanned_label_id,
            "replaced_scan": self.replaced_scan,
        }


def _phs2_contract_error(code: str, message: str, **details: Any) -> TransferSealError:
    return TransferSealError(code, message, details=details)


def validate_compact_phs2_fields(master_label_fields: Mapping[str, Any]) -> dict[str, str]:
    """Validate the compact central PHS=2 QR without trusting a QR quantity."""

    fields = {
        unicodedata.normalize("NFKC", str(key)).strip().upper():
        unicodedata.normalize("NFKC", str(value)).strip()
        for key, value in dict(master_label_fields or {}).items()
    }
    required = ("PHS", "SRC", "ITG", "CLC", "LBL", "HSH")
    missing = [key for key in required if not fields.get(key)]
    unexpected = sorted(set(fields) - set(required))
    if missing:
        raise _phs2_contract_error(
            "PHS2_CANONICAL_EVIDENCE_REQUIRED",
            "중앙 PHS=2 현품표의 ITG/LBL/HSH 식별 증거가 누락됐습니다.",
            missing_fields=missing,
        )
    if unexpected:
        raise _phs2_contract_error(
            "PHS2_COMPACT_FORMAT_REQUIRED",
            "중앙 PHS=2 현품표는 QT 없는 compact 식별 형식이어야 합니다.",
            unexpected_fields=unexpected,
        )
    if fields["PHS"] != "2" or fields["SRC"].upper() != "KMTECH_INPUT_TAG":
        raise _phs2_contract_error(
            "PHS2_CENTRAL_SOURCE_REQUIRED",
            "PHS=2 현품표는 중앙 KMTECH_INPUT_TAG 형식만 이적할 수 있습니다.",
        )
    for key in ("ITG", "CLC", "LBL"):
        value = fields[key]
        if len(value) > 256 or "\x00" in value or any(
            unicodedata.category(character).startswith("C") for character in value
        ):
            raise _phs2_contract_error(
                "PHS2_IDENTITY_INVALID",
                f"중앙 PHS=2 {key} 식별자가 올바르지 않습니다.",
                field=key,
            )
    hash_prefix = fields["HSH"].lower()
    if len(hash_prefix) != 16 or any(value not in "0123456789abcdef" for value in hash_prefix):
        raise _phs2_contract_error(
            "PHS2_HASH_PREFIX_INVALID",
            "중앙 PHS=2 HSH는 16자리 SHA-256 축약값이어야 합니다.",
        )
    fields["HSH"] = hash_prefix
    return fields


def _compact_phs2_fields_from_payload(payload: Any) -> dict[str, str]:
    normalized = unicodedata.normalize("NFKC", str(payload or "")).strip()
    parsed: dict[str, str] = {}
    for segment in normalized.split("|"):
        if "=" not in segment:
            raise _phs2_contract_error(
                "PHS2_COMPACT_FORMAT_REQUIRED",
                "중앙 PHS=2 현품표 QR 형식이 올바르지 않습니다.",
            )
        key, value = segment.split("=", 1)
        key = unicodedata.normalize("NFKC", key).strip().upper()
        if not key or key in parsed:
            raise _phs2_contract_error(
                "PHS2_COMPACT_FORMAT_REQUIRED",
                "중앙 PHS=2 현품표 QR에 중복되거나 빈 필드가 있습니다.",
            )
        parsed[key] = unicodedata.normalize("NFKC", value).strip()
    return validate_compact_phs2_fields(parsed)


def _physical_label_from_resolution(
    *,
    scanned_fields: Mapping[str, str],
    response: Mapping[str, Any],
    canonical_fields: Mapping[str, str],
) -> tuple[dict[str, Any], str, str, bool]:
    """Resolve one physical ACTIVE label while retaining the immutable tag."""

    raw_resolution = response.get("phs_label_resolution")
    if raw_resolution is None:
        if any(
            scanned_fields[key] != canonical_fields[key]
            for key in ("ITG", "CLC", "LBL", "HSH")
        ):
            raise _phs2_contract_error(
                "PHS2_REGISTRY_IDENTITY_MISMATCH",
                "중앙 PHS=2 QR과 immutable input-tag registry가 일치하지 않습니다.",
            )
        return (
            {
                "label_id": canonical_fields["LBL"],
                "qr_payload": (
                    f"PHS=2|SRC=KMTECH_INPUT_TAG|ITG={canonical_fields['ITG']}|"
                    f"CLC={canonical_fields['CLC']}|LBL={canonical_fields['LBL']}|"
                    f"HSH={canonical_fields['HSH']}"
                ),
                "hash_prefix": canonical_fields["HSH"],
                "scan_anchor_input_tag_id": canonical_fields["ITG"],
                "item_id": canonical_fields["CLC"],
                "state": "ACTIVE",
            },
            "LEGACY_ACTIVE",
            canonical_fields["LBL"],
            False,
        )
    if not isinstance(raw_resolution, Mapping):
        raise _phs2_contract_error(
            "PHS2_LABEL_RESOLUTION_CORRUPT",
            "중앙 PHS=2 physical label resolution이 올바르지 않습니다.",
        )
    resolution = dict(raw_resolution)
    resolution_kind = str(resolution.get("resolution") or "").strip().upper()
    status = str(resolution.get("status") or "").strip().upper()
    scanned = resolution.get("scanned_label")
    if not isinstance(scanned, Mapping):
        raise _phs2_contract_error(
            "PHS2_LABEL_RESOLUTION_CORRUPT",
            "중앙 physical label resolution에 scanned label 증거가 없습니다.",
        )
    scanned = dict(scanned)
    scanned_qr = unicodedata.normalize(
        "NFKC", str(scanned.get("qr_payload") or "")
    ).strip()
    parsed_scanned = _compact_phs2_fields_from_payload(scanned_qr)
    if (
        any(
            parsed_scanned[key] != scanned_fields[key]
            for key in ("ITG", "CLC", "LBL", "HSH")
        )
        or str(scanned.get("label_id") or "").strip() != scanned_fields["LBL"]
        or str(scanned.get("hash_prefix") or "").strip().lower()
        != scanned_fields["HSH"]
        or str(scanned.get("scan_anchor_input_tag_id") or "").strip()
        != scanned_fields["ITG"]
        or str(scanned.get("item_id") or "").strip() != scanned_fields["CLC"]
    ):
        raise _phs2_contract_error(
            "PHS2_LABEL_RESOLUTION_MISMATCH",
            "스캔한 PHS=2 physical label과 중앙 resolution 증거가 일치하지 않습니다.",
        )
    if resolution_kind == "OVERLAY_NOT_ACTIVE" or status in {
        "PENDING_ACTIVATION",
        "PRINT_FAILED",
    }:
        raise _phs2_contract_error(
            "PHS2_LABEL_NOT_ACTIVE",
            "아직 ACTIVE가 아닌 새 현품표는 이적 작업에 사용할 수 없습니다.",
            label_id=scanned_fields["LBL"],
            label_state=status,
        )
    if resolution_kind not in {
        "OVERLAY_ACTIVE",
        "OVERLAY_REPLACED",
        "LEGACY_ACTIVE",
    }:
        raise _phs2_contract_error(
            "PHS2_LABEL_RESOLUTION_CORRUPT",
            "중앙 PHS=2 physical label resolution 상태를 확정할 수 없습니다.",
            resolution=resolution_kind,
        )
    effective = resolution.get("effective_labels")
    if (
        not isinstance(effective, list)
        or len(effective) != 1
        or not isinstance(effective[0], Mapping)
    ):
        raise _phs2_contract_error(
            "PHS2_ACTIVE_LABEL_AMBIGUOUS",
            "중앙 PHS=2 현품표의 현재 ACTIVE successor를 하나로 확정하지 못했습니다.",
            active_label_count=len(effective) if isinstance(effective, list) else None,
        )
    active = dict(effective[0])
    active_qr = unicodedata.normalize(
        "NFKC", str(active.get("qr_payload") or "")
    ).strip()
    active_fields = _compact_phs2_fields_from_payload(active_qr)
    if (
        str(active.get("state") or "").strip().upper() != "ACTIVE"
        or active_fields["ITG"] != canonical_fields["ITG"]
        or active_fields["CLC"] != canonical_fields["CLC"]
        or str(active.get("label_id") or "").strip() != active_fields["LBL"]
        or str(active.get("hash_prefix") or "").strip().lower()
        != active_fields["HSH"]
        or str(active.get("scan_anchor_input_tag_id") or "").strip()
        != canonical_fields["ITG"]
        or str(active.get("item_id") or "").strip() != canonical_fields["CLC"]
    ):
        raise _phs2_contract_error(
            "PHS2_ACTIVE_LABEL_INVALID",
            "중앙 PHS=2 ACTIVE physical label이 immutable input-tag anchor와 다릅니다.",
        )
    replaced = resolution_kind == "OVERLAY_REPLACED"
    if replaced and status != "REPLACED":
        raise _phs2_contract_error(
            "PHS2_LABEL_RESOLUTION_CORRUPT",
            "교체된 PHS=2 라벨의 중앙 상태가 일치하지 않습니다.",
        )
    if not replaced and status != "ACTIVE":
        raise _phs2_contract_error(
            "PHS2_LABEL_NOT_ACTIVE",
            "현재 ACTIVE가 아닌 PHS=2 현품표는 사용할 수 없습니다.",
            label_state=status,
        )
    if resolution_kind in {"OVERLAY_ACTIVE", "LEGACY_ACTIVE"} and (
        active_fields["LBL"] != scanned_fields["LBL"]
        or active_fields["HSH"] != scanned_fields["HSH"]
    ):
        raise _phs2_contract_error(
            "PHS2_ACTIVE_LABEL_INVALID",
            "현재 ACTIVE physical label과 스캔한 라벨이 일치하지 않습니다.",
        )
    return active, resolution_kind, scanned_fields["LBL"], replaced


def _work_group_members(
    value: Any,
    *,
    field_name: str,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
            "중앙 현품표 topology의 제품 목록 형식이 올바르지 않습니다.",
            field=field_name,
        )
    try:
        members = tuple(
            sorted(_normalize_identifier(member, field_name) for member in value)
        )
    except (TypeError, ValueError) as exc:
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
            "중앙 현품표 topology의 제품 식별자가 올바르지 않습니다.",
            field=field_name,
        ) from exc
    if (
        len(members) != len(value)
        or len(members) != len(set(members))
        or (not allow_empty and not members)
    ):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
            "중앙 현품표 topology의 제품 목록이 비어 있거나 중복됐습니다.",
            field=field_name,
        )
    return members


def _work_group_version(value: Any, *, field_name: str, minimum: int = 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
            "중앙 현품표 topology의 version 증거가 올바르지 않습니다.",
            field=field_name,
        )
    return value


def _validated_completed_input_tag(
    value: Any,
    *,
    expected_item_id: str,
    expected_uom: str,
    field_name: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    if not isinstance(value, Mapping):
        raise _phs2_contract_error(
            "PHS2_SOURCE_REGISTRY_EVIDENCE_REQUIRED",
            "중앙 PHS=2 완료 registry 검증 증거가 없습니다.",
            field=field_name,
        )
    projection = dict(value)
    required = (
        "input_tag_id",
        "label_id",
        "item_id",
        "uom",
        "tag_core_hash",
        "label_instance_hash",
        "hash_prefix",
        "lifecycle",
        "qr_payload",
        "session_id",
    )
    missing = [key for key in required if projection.get(key) in (None, "")]
    if missing:
        raise _phs2_contract_error(
            "PHS2_SOURCE_REGISTRY_EVIDENCE_REQUIRED",
            "중앙 PHS=2 완료 registry 응답이 불완전합니다.",
            field=field_name,
            missing_fields=missing,
        )
    qr_payload = unicodedata.normalize(
        "NFKC", str(projection["qr_payload"])
    ).strip()
    qr_fields = _compact_phs2_fields_from_payload(qr_payload)
    input_tag_id = str(projection["input_tag_id"]).strip()
    label_id = str(projection["label_id"]).strip()
    item_id = str(projection["item_id"]).strip()
    uom = str(projection["uom"]).strip()
    core_hash = str(projection["tag_core_hash"]).strip().lower()
    label_hash = str(projection["label_instance_hash"]).strip().lower()
    hash_prefix = str(projection["hash_prefix"]).strip().lower()
    if (
        input_tag_id != qr_fields["ITG"]
        or str(projection["session_id"]).strip() != input_tag_id
        or label_id != qr_fields["LBL"]
        or item_id != qr_fields["CLC"]
        or item_id != expected_item_id
        or uom != expected_uom
        or hash_prefix != qr_fields["HSH"]
        or str(projection["lifecycle"]).strip().upper()
        != "INSPECTION_COMPLETED"
        or len(core_hash) != 64
        or len(label_hash) != 64
        or any(
            character not in "0123456789abcdef"
            for character in core_hash + label_hash
        )
        or label_hash[:16] != hash_prefix
    ):
        raise _phs2_contract_error(
            "PHS2_SOURCE_REGISTRY_IDENTITY_MISMATCH",
            "중앙 PHS=2 완료 registry 식별자가 올바르지 않습니다.",
            field=field_name,
        )
    return projection, qr_fields


def _validated_work_group_proof(
    value: Any,
    *,
    field_name: str,
    expected_item_id: str,
    expected_uom: str,
    require_state: bool,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    if not isinstance(value, Mapping):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
            "중앙 현품표 group 증거가 없습니다.",
            field=field_name,
        )
    proof = dict(value)
    group_id = str(proof.get("group_id") or "").strip()
    label_id = str(proof.get("label_id") or "").strip()
    scan_payload = unicodedata.normalize(
        "NFKC", str(proof.get("scan_payload") or "")
    ).strip()
    anchor_id = str(proof.get("scan_anchor_input_tag_id") or "").strip()
    item_id = str(proof.get("item_id") or "").strip()
    uom = str(proof.get("uom") or "").strip()
    members = _work_group_members(
        proof.get("member_ids"),
        field_name=f"{field_name}.member_ids",
    )
    if (
        not group_id
        or not label_id
        or not scan_payload
        or not anchor_id
        or item_id != expected_item_id
        or uom != expected_uom
        or (
            require_state
            and str(proof.get("state") or "").strip().upper() != "ACTIVE"
        )
        or isinstance(proof.get("member_count"), bool)
        or not isinstance(proof.get("member_count"), int)
        or proof.get("member_count") != len(members)
        or str(proof.get("membership_hash") or "")
        != membership_hash(members)
    ):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
            "중앙 현품표 group의 identity 또는 membership이 일치하지 않습니다.",
            field=field_name,
        )
    scan_fields = _compact_phs2_fields_from_payload(scan_payload)
    if (
        scan_fields["ITG"] != anchor_id
        or scan_fields["CLC"] != item_id
        or scan_fields["LBL"] != label_id
    ):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
            "중앙 현품표 group과 physical label 식별자가 일치하지 않습니다.",
            field=field_name,
        )
    for version_field in (
        "membership_version",
        "label_version",
        "group_entity_version",
        "label_entity_version",
    ):
        _work_group_version(
            proof.get(version_field),
            field_name=f"{field_name}.{version_field}",
        )
    return proof, members


def _validate_work_group_phs2_preflight(
    fields: Mapping[str, str],
    response: Mapping[str, Any],
) -> TransferSourcePreflight:
    """Validate one ACTIVE physical work label across all current PHS owners."""

    candidate_count = response.get("candidate_count")
    if (
        isinstance(candidate_count, bool)
        or not isinstance(candidate_count, int)
        or candidate_count != 1
    ):
        raise _phs2_contract_error(
            "PHS2_SOURCE_AMBIGUOUS",
            "중앙 현품표가 이적 원본 topology를 하나로 확정하지 못했습니다.",
            candidate_count=candidate_count,
        )
    source_value = response.get("work_group_source")
    if not isinstance(source_value, Mapping):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
            "중앙 현품표 source topology가 없습니다.",
        )
    source = dict(source_value)
    authority_scope_id = str(source.get("authority_scope_id") or "").strip()
    ledger_plane = str(source.get("ledger_plane") or "").strip().upper()
    plane_epoch = _work_group_version(
        source.get("plane_epoch"),
        field_name="work_group_source.plane_epoch",
    )
    item_id = str(source.get("item_id") or "").strip()
    uom = str(source.get("uom") or "").strip()
    source_iin = str(source.get("source_iin") or "").strip()
    if (
        not authority_scope_id
        or ledger_plane not in {"AUTHORITATIVE", "SHADOW_CANDIDATE"}
        or item_id != fields["CLC"]
        or not uom
        or not source_iin
        or str(response.get("authority_scope_id") or "").strip()
        != authority_scope_id
        or str(response.get("ledger_plane") or "").strip().upper()
        != ledger_plane
        or response.get("plane_epoch") != plane_epoch
    ):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_SOURCE_IDENTITY_MISMATCH",
            "중앙 현품표 source의 품목·UOM·authority 상태가 일치하지 않습니다.",
        )

    anchor_tag, anchor_fields = _validated_completed_input_tag(
        response.get("input_tag"),
        expected_item_id=item_id,
        expected_uom=uom,
        field_name="input_tag",
    )
    if anchor_fields["ITG"] != fields["ITG"]:
        raise _phs2_contract_error(
            "PHS2_REGISTRY_IDENTITY_MISMATCH",
            "스캔한 physical label의 immutable input-tag anchor가 일치하지 않습니다.",
        )
    (
        active_label,
        active_label_resolution,
        scanned_label_id,
        replaced_scan,
    ) = _physical_label_from_resolution(
        scanned_fields=fields,
        response=response,
        canonical_fields=anchor_fields,
    )
    group, group_members = _validated_work_group_proof(
        response.get("phs_work_group"),
        field_name="phs_work_group",
        expected_item_id=item_id,
        expected_uom=uom,
        require_state=True,
    )
    active_members = _work_group_members(
        active_label.get("member_ids"),
        field_name="phs_label_resolution.effective_labels[0].member_ids",
    )
    scanned_qr = (
        f"PHS=2|SRC=KMTECH_INPUT_TAG|ITG={fields['ITG']}|"
        f"CLC={fields['CLC']}|LBL={fields['LBL']}|HSH={fields['HSH']}"
    )
    if (
        str(group["scan_anchor_input_tag_id"]) != fields["ITG"]
        or str(group["scan_payload"]) != scanned_qr
        or str(group["group_id"]) != str(active_label.get("group_id") or "")
        or str(group["label_id"]) != str(active_label.get("label_id") or "")
        or str(group["scan_payload"])
        != str(active_label.get("qr_payload") or "")
        or group_members != active_members
        or active_label.get("member_count") != len(group_members)
        or str(active_label.get("membership_hash") or "")
        != membership_hash(group_members)
        or active_label.get("membership_version")
        != group["membership_version"]
        or active_label.get("label_version") != group["label_version"]
        or active_label.get("entity_version")
        != group["label_entity_version"]
    ):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_MEMBERSHIP_MISMATCH",
            "스캔한 ACTIVE physical label과 중앙 work group이 일치하지 않습니다.",
        )

    source_members = _work_group_members(
        source.get("member_ids"),
        field_name="work_group_source.member_ids",
    )
    raw_member_rows = source.get("members")
    if not isinstance(raw_member_rows, list):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_MEMBERSHIP_MISMATCH",
            "중앙 현품표의 제품 barcode mapping이 없습니다.",
        )
    mapped_ids: list[str] = []
    normalized_barcodes: list[str] = []
    for member in raw_member_rows:
        if not isinstance(member, Mapping):
            raise _phs2_contract_error(
                "PHS2_WORK_GROUP_MEMBERSHIP_MISMATCH",
                "중앙 현품표 제품 mapping 형식이 올바르지 않습니다.",
            )
        try:
            unit_id = _normalize_identifier(member.get("unit_id"), "unit_id")
            barcode = normalize_barcode(member.get("normalized_barcode"))
        except (TypeError, ValueError) as exc:
            raise _phs2_contract_error(
                "PHS2_WORK_GROUP_MEMBERSHIP_MISMATCH",
                "중앙 현품표 제품 식별자가 올바르지 않습니다.",
            ) from exc
        if (
            str(member.get("current_inbound_iin") or "").strip() != source_iin
            or str(member.get("item_id") or "").strip() != item_id
            or str(member.get("uom") or "").strip() != uom
            or str(member.get("location_code") or "").strip() != "PHS_GOOD"
            or str(member.get("unit_state") or "").strip().upper()
            not in {"AVAILABLE", "CONSUMED"}
        ):
            raise _phs2_contract_error(
                "PHS2_MIXED_MEMBERSHIP",
                "중앙 현품표에 서로 다른 품목·위치·회계 귀속 제품이 섞여 있습니다.",
            )
        mapped_ids.append(unit_id)
        normalized_barcodes.append(barcode)
    if (
        source_members != group_members
        or tuple(sorted(mapped_ids)) != source_members
        or len(mapped_ids) != len(set(mapped_ids))
        or len(normalized_barcodes) != len(set(normalized_barcodes))
        or isinstance(source.get("member_count"), bool)
        or source.get("member_count") != len(source_members)
        or str(source.get("membership_hash") or "")
        != membership_hash(source_members)
        or isinstance(source.get("barcode_member_count"), bool)
        or source.get("barcode_member_count") != len(normalized_barcodes)
        or str(source.get("barcode_membership_hash") or "")
        != membership_hash(normalized_barcodes)
    ):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_MEMBERSHIP_MISMATCH",
            "중앙 현품표의 exact 제품·barcode membership이 일치하지 않습니다.",
        )

    raw_sources = source.get("source_bundles")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
            "중앙 현품표의 current PHS source partitions가 없습니다.",
        )
    source_bundles: list[dict[str, Any]] = []
    source_bundle_ids: list[str] = []
    source_session_ids: set[str] = set()
    selected_union: set[str] = set()
    full_union: set[str] = set()
    all_remainders: set[str] = set()
    source_remainders: dict[str, set[str]] = {}
    source_cover_ids: dict[str, set[str]] = {}
    source_versions: dict[str, int] = {}
    for index, raw_source in enumerate(raw_sources):
        if not isinstance(raw_source, Mapping):
            raise _phs2_contract_error(
                "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
                "중앙 현품표 source partition 형식이 올바르지 않습니다.",
                source_index=index,
            )
        frozen = dict(raw_source)
        source_id = str(frozen.get("bundle_id") or "").strip()
        source_session_id = str(
            frozen.get("source_session_id") or ""
        ).strip()
        accounting_iin = str(
            frozen.get("accounting_inbound_iin") or ""
        ).strip()
        version = _work_group_version(
            frozen.get("entity_version"),
            field_name=f"source_bundles[{index}].entity_version",
        )
        full = _work_group_members(
            frozen.get("source_member_ids"),
            field_name=f"source_bundles[{index}].source_member_ids",
        )
        selected = _work_group_members(
            frozen.get("selected_member_ids"),
            field_name=f"source_bundles[{index}].selected_member_ids",
        )
        remainder = _work_group_members(
            frozen.get("remainder_member_ids"),
            field_name=f"source_bundles[{index}].remainder_member_ids",
            allow_empty=True,
        )
        raw_cover_ids = frozen.get("remainder_cover_group_ids")
        if not isinstance(raw_cover_ids, list):
            raise _phs2_contract_error(
                "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
                "중앙 현품표 source의 remainder cover 증거가 없습니다.",
                source_bundle_id=source_id,
            )
        cover_ids = {
            _normalize_identifier(value, "remainder_cover_group_id")
            for value in raw_cover_ids
        }
        expected_remainder_id = (
            "PHS-WORK-REMAINDER-"
            + _sha256(
                {
                    "source_bundle_id": source_id,
                    "member_ids": list(remainder),
                }
            )[:24].upper()
            if remainder
            else None
        )
        expected_remainder_label = (
            f"WORK-REMAINDER::{expected_remainder_id}"
            if expected_remainder_id
            else None
        )
        if (
            not source_id
            or source_id in source_bundle_ids
            or not source_session_id
            or not accounting_iin
            or accounting_iin != source_iin
            or str(frozen.get("bundle_type") or "") != "PHS"
            or str(frozen.get("bundle_state") or "") != "AVAILABLE"
            or isinstance(frozen.get("source_member_count"), bool)
            or frozen.get("source_member_count") != len(full)
            or str(frozen.get("source_membership_hash") or "")
            != membership_hash(full)
            or isinstance(frozen.get("selected_member_count"), bool)
            or frozen.get("selected_member_count") != len(selected)
            or str(frozen.get("selected_membership_hash") or "")
            != membership_hash(selected)
            or isinstance(frozen.get("remainder_member_count"), bool)
            or frozen.get("remainder_member_count") != len(remainder)
            or (
                str(frozen.get("remainder_membership_hash") or "")
                if remainder
                else None
            )
            != (membership_hash(remainder) if remainder else None)
            or sorted(full) != sorted((*selected, *remainder))
            or bool(set(selected) & set(remainder))
            or str(frozen.get("remainder_bundle_id") or "")
            != str(expected_remainder_id or "")
            or str(frozen.get("remainder_external_label") or "")
            != str(expected_remainder_label or "")
            or len(cover_ids) != len(raw_cover_ids)
            or (not remainder and cover_ids)
            or bool(full_union.intersection(full))
            or bool(selected_union.intersection(selected))
        ):
            raise _phs2_contract_error(
                "PHS2_WORK_GROUP_SOURCE_PARTITION_MISMATCH",
                "중앙 현품표 source의 full/selected/remainder partition이 일치하지 않습니다.",
                source_bundle_id=source_id,
            )
        source_bundle_ids.append(source_id)
        source_session_ids.add(source_session_id)
        source_versions[source_id] = version
        source_remainders[source_id] = set(remainder)
        source_cover_ids[source_id] = cover_ids
        selected_union.update(selected)
        full_union.update(full)
        all_remainders.update(remainder)
        source_bundles.append(frozen)
    if (
        source_bundle_ids != sorted(source_bundle_ids)
        or selected_union != set(group_members)
        or source.get("source_bundle_count") != len(source_bundle_ids)
        or list(source.get("source_bundle_ids") or []) != source_bundle_ids
        or list(source.get("source_session_ids") or [])
        != sorted(source_session_ids)
    ):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_SOURCE_PARTITION_MISMATCH",
            "중앙 현품표 source partitions가 work-group membership을 정확히 덮지 않습니다.",
        )

    raw_covers = source.get("remainder_cover_groups")
    if not isinstance(raw_covers, list):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
            "중앙 현품표 remainder cover topology가 없습니다.",
        )
    cover_groups: list[dict[str, Any]] = []
    cover_members_by_group: dict[str, set[str]] = {}
    covered_union: set[str] = set()
    cover_label_ids: set[str] = set()
    for index, raw_cover in enumerate(raw_covers):
        cover, cover_members = _validated_work_group_proof(
            raw_cover,
            field_name=f"remainder_cover_groups[{index}]",
            expected_item_id=item_id,
            expected_uom=uom,
            require_state=False,
        )
        covered = _work_group_members(
            cover.get("covered_member_ids"),
            field_name=f"remainder_cover_groups[{index}].covered_member_ids",
        )
        cover_id = str(cover["group_id"])
        cover_label_id = str(cover["label_id"])
        if (
            cover_id == str(group["group_id"])
            or cover_id in cover_members_by_group
            or cover_label_id in cover_label_ids
            or covered != cover_members
            or isinstance(cover.get("covered_member_count"), bool)
            or cover.get("covered_member_count") != len(covered)
            or str(cover.get("covered_membership_hash") or "")
            != membership_hash(covered)
            or bool(covered_union.intersection(covered))
        ):
            raise _phs2_contract_error(
                "PHS2_WORK_GROUP_REMAINDER_COVER_MISMATCH",
                "중앙 현품표 remainder successor label topology가 일치하지 않습니다.",
                group_id=cover_id,
            )
        cover_members_by_group[cover_id] = set(covered)
        cover_label_ids.add(cover_label_id)
        covered_union.update(covered)
        cover_groups.append(cover)
    if covered_union != all_remainders:
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_REMAINDER_COVER_MISMATCH",
            "중앙 현품표 remainder를 ACTIVE successor label이 정확히 덮지 않습니다.",
        )
    for source_id, remainder in source_remainders.items():
        expected_cover_ids = {
            cover_id
            for cover_id, cover_members in cover_members_by_group.items()
            if remainder.intersection(cover_members)
        }
        if source_cover_ids[source_id] != expected_cover_ids:
            raise _phs2_contract_error(
                "PHS2_WORK_GROUP_REMAINDER_COVER_MISMATCH",
                "중앙 현품표 source와 remainder successor label 연결이 일치하지 않습니다.",
                source_bundle_id=source_id,
            )

    raw_source_tags = response.get("source_input_tags")
    if not isinstance(raw_source_tags, list):
        raise _phs2_contract_error(
            "PHS2_SOURCE_REGISTRY_EVIDENCE_REQUIRED",
            "중앙 현품표 실제 source input-tag registry 증거가 없습니다.",
        )
    source_tags: dict[str, dict[str, Any]] = {}
    source_tag_fields: dict[str, dict[str, str]] = {}
    for index, raw_tag in enumerate(raw_source_tags):
        tag, tag_fields = _validated_completed_input_tag(
            raw_tag,
            expected_item_id=item_id,
            expected_uom=uom,
            field_name=f"source_input_tags[{index}]",
        )
        session_id = str(tag["input_tag_id"]).strip()
        if session_id in source_tags:
            raise _phs2_contract_error(
                "PHS2_SOURCE_REGISTRY_IDENTITY_MISMATCH",
                "중앙 현품표 source input-tag registry가 중복됐습니다.",
            )
        source_tags[session_id] = tag
        source_tag_fields[session_id] = tag_fields
    if set(source_tags) != source_session_ids:
        raise _phs2_contract_error(
            "PHS2_SOURCE_REGISTRY_IDENTITY_MISMATCH",
            "중앙 현품표 source sessions와 immutable input-tag registry가 일치하지 않습니다.",
        )
    for source_bundle in source_bundles:
        source_id = str(source_bundle["bundle_id"])
        source_session_id = str(source_bundle["source_session_id"])
        external_label = str(source_bundle.get("external_label") or "")
        source_qr = str(source_tags[source_session_id]["qr_payload"])
        internal_alias = f"WORK-REMAINDER::{source_id}"
        if external_label not in {source_qr, internal_alias}:
            raise _phs2_contract_error(
                "PHS2_SOURCE_REGISTRY_IDENTITY_MISMATCH",
                "중앙 PHS source의 immutable label identity가 registry와 일치하지 않습니다.",
                source_bundle_id=source_id,
            )

    transfer_bundle_id = str(
        source.get("transfer_bundle_id") or ""
    ).strip()
    transfer_external_label = str(
        source.get("transfer_external_label") or ""
    ).strip()
    expected_transfer_id = _deterministic_id(
        "TRANSFER",
        {
            "group_id": str(group["group_id"]),
            "label_id": str(group["label_id"]),
            "member_ids": list(group_members),
        },
    )
    topology_hash = str(source.get("topology_hash") or "").strip().lower()
    expected_topology_hash = _sha256(
        {
            "phs_work_group": group,
            "source_bundles": source_bundles,
            "remainder_cover_groups": cover_groups,
            "source_iin": source_iin,
            "barcode_membership_hash": membership_hash(normalized_barcodes),
            "transfer_bundle_id": transfer_bundle_id,
        }
    )
    if (
        transfer_bundle_id != expected_transfer_id
        or transfer_external_label != transfer_bundle_id
        or topology_hash != expected_topology_hash
        or str(response.get("topology_hash") or "").strip().lower()
        != topology_hash
    ):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_HASH_MISMATCH",
            "중앙 현품표의 deterministic transfer identity 또는 topology hash가 일치하지 않습니다.",
        )

    raw_versions = source.get("entity_versions")
    top_versions = response.get("entity_versions")
    if not isinstance(raw_versions, Mapping) or not isinstance(
        top_versions, Mapping
    ):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
            "중앙 현품표 topology CAS version 증거가 없습니다.",
        )
    versions = dict(raw_versions)
    if versions != dict(top_versions):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
            "중앙 현품표 topology CAS version 응답이 일치하지 않습니다.",
        )
    expected_versions: dict[str, int] = {
        f"phs_work_group:{group['group_id']}": group[
            "group_entity_version"
        ],
        f"phs_work_membership:{group['group_id']}": group[
            "membership_version"
        ],
        f"phs_work_label_version:{group['group_id']}": group[
            "label_version"
        ],
        f"phs_label:{group['label_id']}": group["label_entity_version"],
        **{
            f"bundle:{source_id}": version
            for source_id, version in source_versions.items()
        },
        f"bundle:{transfer_bundle_id}": 0,
    }
    for cover in cover_groups:
        cover_id = str(cover["group_id"])
        expected_versions.update(
            {
                f"phs_work_group:{cover_id}": cover[
                    "group_entity_version"
                ],
                f"phs_work_membership:{cover_id}": cover[
                    "membership_version"
                ],
                f"phs_work_label_version:{cover_id}": cover[
                    "label_version"
                ],
                f"phs_label:{cover['label_id']}": cover[
                    "label_entity_version"
                ],
            }
        )
    if set(versions) != set(expected_versions):
        raise _phs2_contract_error(
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
            "중앙 현품표 topology CAS version key가 불완전합니다.",
        )
    for entity_key, expected_version in expected_versions.items():
        minimum = 0 if entity_key == f"bundle:{transfer_bundle_id}" else 1
        actual_version = _work_group_version(
            versions.get(entity_key),
            field_name=f"entity_versions.{entity_key}",
            minimum=minimum,
        )
        if actual_version != expected_version:
            raise _phs2_contract_error(
                "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
                "중앙 현품표 topology CAS version 값이 proof와 일치하지 않습니다.",
                entity_key=entity_key,
            )

    return TransferSourcePreflight(
        source_bundle_id=(
            source_bundle_ids[0] if len(source_bundle_ids) == 1 else ""
        ),
        source_session_id=(
            next(iter(source_session_ids))
            if len(source_session_ids) == 1
            else ""
        ),
        authority_scope_id=authority_scope_id,
        ledger_plane=ledger_plane,
        plane_epoch=plane_epoch,
        item_id=item_id,
        uom=uom,
        source_iin=source_iin,
        member_ids=source_members,
        normalized_barcodes=tuple(sorted(normalized_barcodes)),
        membership_hash=membership_hash(source_members),
        barcode_membership_hash=membership_hash(normalized_barcodes),
        input_tag_id=str(anchor_tag["input_tag_id"]),
        input_tag_label_id=str(anchor_tag["label_id"]),
        input_tag_hash_prefix=str(anchor_tag["hash_prefix"]).lower(),
        input_tag_core_hash=str(anchor_tag["tag_core_hash"]).lower(),
        input_tag_label_hash=str(
            anchor_tag["label_instance_hash"]
        ).lower(),
        source_resolution_basis="PHS_WORK_GROUP_EXACT_MEMBERSHIP",
        source_bundle_ids=tuple(source_bundle_ids),
        source_session_ids=tuple(sorted(source_session_ids)),
        source_bundles=tuple(source_bundles),
        entity_versions={
            str(key): int(value) for key, value in versions.items()
        },
        phs_work_group=group,
        remainder_cover_groups=tuple(cover_groups),
        topology_hash=topology_hash,
        transfer_bundle_id=transfer_bundle_id,
        transfer_external_label=transfer_external_label,
        canonical_input_tag_qr=str(anchor_tag["qr_payload"]),
        active_label_qr_payload=str(active_label.get("qr_payload") or ""),
        active_label_id=str(active_label.get("label_id") or ""),
        active_label_business_date=str(
            active_label.get("business_date") or ""
        ),
        active_label_worker_code=str(
            active_label.get("worker_code") or ""
        ),
        active_label_resolution=active_label_resolution,
        scanned_label_id=scanned_label_id,
        replaced_scan=replaced_scan,
    )


def validate_compact_phs2_preflight(
    master_label_fields: Mapping[str, Any],
    resolved: Mapping[str, Any],
) -> TransferSourcePreflight:
    """Fail closed unless one completed central source owns one exact PHS."""

    fields = validate_compact_phs2_fields(master_label_fields)
    response = dict(resolved or {})
    source_resolution_basis = str(
        response.get("source_resolution_basis") or "IMMUTABLE_INPUT_TAG"
    ).strip().upper()
    if source_resolution_basis not in {
        "IMMUTABLE_INPUT_TAG",
        "PHS_WORK_GROUP_EXACT_MEMBERSHIP",
    }:
        raise _phs2_contract_error(
            "PHS2_SOURCE_RESOLUTION_INVALID",
            "중앙 PHS=2 원본 선택 근거를 확인할 수 없습니다.",
        )
    work_group_resolution = (
        source_resolution_basis == "PHS_WORK_GROUP_EXACT_MEMBERSHIP"
    )
    if work_group_resolution and "work_group_source" in response:
        return _validate_work_group_phs2_preflight(fields, response)
    candidate_count = response.get("candidate_count")
    bundle_value = response.get("bundle")
    if (
        isinstance(candidate_count, bool)
        or not isinstance(candidate_count, int)
        or candidate_count != 1
        or not isinstance(bundle_value, Mapping)
    ):
        raise _phs2_contract_error(
            "PHS2_SOURCE_AMBIGUOUS",
            "중앙 PHS=2 현품표가 완료 PHS를 정확히 하나로 확정하지 못했습니다.",
            candidate_count=candidate_count,
        )
    bundle = dict(bundle_value)
    input_tag_value = response.get("input_tag")
    if not isinstance(input_tag_value, Mapping):
        raise _phs2_contract_error(
            "PHS2_REGISTRY_EVIDENCE_REQUIRED",
            "중앙 PHS=2 registry 검증 증거가 없습니다.",
        )
    input_tag = dict(input_tag_value)
    canonical_input_tag_fields = (
        "input_tag_id",
        "label_id",
        "item_id",
        "tag_core_hash",
        "label_instance_hash",
        "hash_prefix",
        "lifecycle",
        "qr_payload",
    )
    missing_registry = [key for key in canonical_input_tag_fields if input_tag.get(key) in (None, "")]
    if missing_registry:
        raise _phs2_contract_error(
            "PHS2_REGISTRY_EVIDENCE_REQUIRED",
            "중앙 PHS=2 registry 응답이 불완전합니다.",
            missing_fields=missing_registry,
        )

    input_tag_id = str(input_tag["input_tag_id"]).strip()
    label_id = str(input_tag["label_id"]).strip()
    registry_item = str(input_tag["item_id"]).strip()
    core_hash = str(input_tag["tag_core_hash"]).strip().lower()
    label_hash = str(input_tag["label_instance_hash"]).strip().lower()
    hash_prefix = str(input_tag["hash_prefix"]).strip().lower()
    lifecycle = str(input_tag["lifecycle"]).strip().upper()
    registry_qr_payload = unicodedata.normalize(
        "NFKC", str(input_tag["qr_payload"])
    ).strip()
    canonical_fields = _compact_phs2_fields_from_payload(registry_qr_payload)
    expected_qr_payload = (
        f"PHS=2|SRC=KMTECH_INPUT_TAG|ITG={canonical_fields['ITG']}|"
        f"CLC={canonical_fields['CLC']}|LBL={canonical_fields['LBL']}|"
        f"HSH={canonical_fields['HSH']}"
    )
    bundle_external_label = unicodedata.normalize(
        "NFKC", str(bundle.get("external_label") or "")
    ).strip()
    if (
        input_tag_id != fields["ITG"]
        or input_tag_id != canonical_fields["ITG"]
        or label_id != canonical_fields["LBL"]
        or registry_item != fields["CLC"]
        or registry_item != canonical_fields["CLC"]
        or hash_prefix != canonical_fields["HSH"]
        or lifecycle != "INSPECTION_COMPLETED"
        or registry_qr_payload != expected_qr_payload
        or (
            not work_group_resolution
            and bundle_external_label != expected_qr_payload
        )
    ):
        raise _phs2_contract_error(
            "PHS2_REGISTRY_IDENTITY_MISMATCH",
            "중앙 PHS=2 QR과 완료 registry 식별자가 일치하지 않습니다.",
        )
    if (
        len(core_hash) != 64
        or len(label_hash) != 64
        or any(value not in "0123456789abcdef" for value in core_hash + label_hash)
        or label_hash[:16] != hash_prefix
    ):
        raise _phs2_contract_error(
            "PHS2_REGISTRY_HASH_INVALID",
            "중앙 PHS=2 registry hash 증거가 올바르지 않습니다.",
        )
    (
        active_label,
        active_label_resolution,
        scanned_label_id,
        replaced_scan,
    ) = _physical_label_from_resolution(
        scanned_fields=fields,
        response=response,
        canonical_fields=canonical_fields,
    )
    active_label_qr_payload = unicodedata.normalize(
        "NFKC", str(active_label.get("qr_payload") or "")
    ).strip()
    active_label_id = str(active_label.get("label_id") or "").strip()
    active_label_business_date = str(
        active_label.get("business_date") or ""
    ).strip()
    active_label_worker_code = str(
        active_label.get("worker_code") or ""
    ).strip()
    source_input_tag_value = (
        response.get("source_input_tag")
        if work_group_resolution
        else input_tag
    )
    if not isinstance(source_input_tag_value, Mapping):
        raise _phs2_contract_error(
            "PHS2_SOURCE_REGISTRY_EVIDENCE_REQUIRED",
            "중앙 PHS=2 실제 원본 registry 검증 증거가 없습니다.",
        )
    source_input_tag = dict(source_input_tag_value)
    missing_source_registry = [
        key
        for key in canonical_input_tag_fields
        if source_input_tag.get(key) in (None, "")
    ]
    if missing_source_registry:
        raise _phs2_contract_error(
            "PHS2_SOURCE_REGISTRY_EVIDENCE_REQUIRED",
            "중앙 PHS=2 실제 원본 registry 응답이 불완전합니다.",
            missing_fields=missing_source_registry,
        )
    source_registry_qr = unicodedata.normalize(
        "NFKC", str(source_input_tag["qr_payload"])
    ).strip()
    source_registry_fields = _compact_phs2_fields_from_payload(
        source_registry_qr
    )
    source_registry_core_hash = str(
        source_input_tag["tag_core_hash"]
    ).strip().lower()
    source_registry_label_hash = str(
        source_input_tag["label_instance_hash"]
    ).strip().lower()
    source_registry_hash_prefix = str(
        source_input_tag["hash_prefix"]
    ).strip().lower()
    if (
        str(source_input_tag["input_tag_id"]).strip()
        != source_registry_fields["ITG"]
        or str(source_input_tag["label_id"]).strip()
        != source_registry_fields["LBL"]
        or str(source_input_tag["item_id"]).strip()
        != source_registry_fields["CLC"]
        or source_registry_hash_prefix != source_registry_fields["HSH"]
        or str(source_input_tag["lifecycle"]).strip().upper()
        != "INSPECTION_COMPLETED"
        or len(source_registry_core_hash) != 64
        or len(source_registry_label_hash) != 64
        or any(
            value not in "0123456789abcdef"
            for value in source_registry_core_hash + source_registry_label_hash
        )
        or source_registry_label_hash[:16] != source_registry_hash_prefix
    ):
        raise _phs2_contract_error(
            "PHS2_SOURCE_REGISTRY_IDENTITY_MISMATCH",
            "중앙 PHS=2 실제 원본 registry 식별자가 올바르지 않습니다.",
        )

    source_bundle_id = str(bundle.get("bundle_id") or "").strip()
    source_session_id = str(bundle.get("source_session_id") or "").strip()
    item_id = str(bundle.get("item_id") or "").strip()
    uom = str(bundle.get("uom") or "").strip()
    source_iin = str(bundle.get("source_iin") or "").strip()
    authority_scope_id = str(bundle.get("authority_scope_id") or "").strip()
    ledger_plane = str(bundle.get("ledger_plane") or "").strip().upper()
    plane_epoch = bundle.get("plane_epoch")
    label_resolution_value = response.get("phs_label_resolution")
    resolution_scope = (
        str(label_resolution_value.get("authority_scope_id") or "").strip()
        if isinstance(label_resolution_value, Mapping)
        else ""
    )
    if (
        bundle.get("bundle_role") != "TRANSFER_SOURCE"
        or bundle.get("bundle_type") != "PHS"
        or bundle.get("bundle_state") != "AVAILABLE"
        or not source_bundle_id
        or (
            not work_group_resolution
            and source_session_id != fields["ITG"]
        )
        or source_session_id
        != str(source_input_tag["input_tag_id"]).strip()
        or bundle_external_label != source_registry_qr
        or item_id != fields["CLC"]
        or item_id != str(source_input_tag["item_id"]).strip()
        or not uom
        or not source_iin
        or not authority_scope_id
        or (resolution_scope and resolution_scope != authority_scope_id)
        or ledger_plane not in {"AUTHORITATIVE", "SHADOW_CANDIDATE"}
        or isinstance(plane_epoch, bool)
        or not isinstance(plane_epoch, int)
        or plane_epoch < 1
    ):
        raise _phs2_contract_error(
            "PHS2_SOURCE_IDENTITY_MISMATCH",
            "중앙 PHS=2 완료 PHS의 품목·세션·authority 상태가 일치하지 않습니다.",
        )

    raw_member_ids = bundle.get("member_ids")
    raw_members = bundle.get("members")
    member_count = bundle.get("member_count")
    barcode_member_count = bundle.get("barcode_member_count")
    if not isinstance(raw_member_ids, list) or not isinstance(raw_members, list):
        raise _phs2_contract_error(
            "PHS2_MEMBERSHIP_INVALID",
            "중앙 PHS=2 exact membership 응답이 없습니다.",
        )
    try:
        member_ids = tuple(sorted(_normalize_identifier(value, "member_id") for value in raw_member_ids))
    except (TypeError, ValueError) as exc:
        raise _phs2_contract_error(
            "PHS2_MEMBERSHIP_INVALID",
            "중앙 PHS=2 member 식별자가 올바르지 않습니다.",
        ) from exc
    if (
        not member_ids
        or len(member_ids) != len(set(member_ids))
        or isinstance(member_count, bool)
        or not isinstance(member_count, int)
        or member_count != len(member_ids)
        or str(bundle.get("membership_hash") or "") != membership_hash(member_ids)
        or isinstance(barcode_member_count, bool)
        or not isinstance(barcode_member_count, int)
        or barcode_member_count != len(member_ids)
        or len(raw_members) != len(member_ids)
    ):
        raise _phs2_contract_error(
            "PHS2_MEMBERSHIP_INVALID",
            "중앙 PHS=2 member 수량 또는 membership hash가 일치하지 않습니다.",
        )
    if work_group_resolution:
        raw_work_group_members = active_label.get("member_ids")
        try:
            work_group_members = (
                tuple(
                    sorted(
                        _normalize_identifier(value, "member_id")
                        for value in raw_work_group_members
                    )
                )
                if isinstance(raw_work_group_members, list)
                else ()
            )
        except (TypeError, ValueError) as exc:
            raise _phs2_contract_error(
                "PHS2_WORK_GROUP_MEMBERSHIP_MISMATCH",
                "현재 ACTIVE 현품표의 제품 식별자가 올바르지 않습니다.",
            ) from exc
        if (
            work_group_members != member_ids
            or isinstance(active_label.get("member_count"), bool)
            or not isinstance(active_label.get("member_count"), int)
            or active_label.get("member_count") != len(member_ids)
            or str(active_label.get("membership_hash") or "")
            != membership_hash(member_ids)
        ):
            raise _phs2_contract_error(
                "PHS2_WORK_GROUP_MEMBERSHIP_MISMATCH",
                "현재 ACTIVE 현품표와 실제 원본 PHS membership이 일치하지 않습니다.",
            )
    if (
        work_group_resolution
        and (
            str(source_input_tag.get("session_id") or "").strip()
            != source_session_id
            or str(source_input_tag.get("uom") or "").strip() != uom
            or isinstance(source_input_tag.get("member_count"), bool)
            or not isinstance(source_input_tag.get("member_count"), int)
            or source_input_tag.get("member_count") != len(member_ids)
            or str(source_input_tag.get("membership_hash") or "")
            != membership_hash(member_ids)
        )
    ):
        raise _phs2_contract_error(
            "PHS2_SOURCE_REGISTRY_MEMBERSHIP_MISMATCH",
            "실제 원본 registry와 PHS bundle membership이 일치하지 않습니다.",
        )

    mapped_ids: list[str] = []
    normalized_barcodes: list[str] = []
    member_locations: set[str] = set()
    member_items: set[str] = set()
    member_uoms: set[str] = set()
    member_accounting_iins: set[str] = set()
    for member in raw_members:
        if not isinstance(member, Mapping):
            raise _phs2_contract_error(
                "PHS2_MEMBERSHIP_INVALID",
                "중앙 PHS=2 member mapping이 올바르지 않습니다.",
            )
        try:
            mapped_ids.append(_normalize_identifier(member.get("unit_id"), "unit_id"))
            normalized_barcodes.append(normalize_barcode(member.get("normalized_barcode")))
        except (TypeError, ValueError) as exc:
            raise _phs2_contract_error(
                "PHS2_MEMBERSHIP_INVALID",
                "중앙 PHS=2 제품 식별자가 올바르지 않습니다.",
            ) from exc
        member_locations.add(str(member.get("location_code") or "").strip())
        member_items.add(str(member.get("item_id") or "").strip())
        member_uoms.add(str(member.get("uom") or "").strip())
        member_accounting_iins.add(str(member.get("current_inbound_iin") or "").strip())
        if str(member.get("unit_state") or "").strip().upper() not in {
            "AVAILABLE",
            "CONSUMED",
        }:
            raise _phs2_contract_error(
                "PHS2_MEMBER_NOT_AVAILABLE",
                "중앙 PHS=2에 이적 불가능한 제품 상태가 섞여 있습니다.",
            )

    current_locations = bundle.get("current_locations")
    if not isinstance(current_locations, list):
        current_locations = []
    if (
        tuple(sorted(mapped_ids)) != member_ids
        or len(normalized_barcodes) != len(set(normalized_barcodes))
        or str(bundle.get("barcode_membership_hash") or "")
        != membership_hash(normalized_barcodes)
        or member_locations != {"PHS_GOOD"}
        or str(bundle.get("current_location") or "").strip() != "PHS_GOOD"
        or {str(value or "").strip() for value in current_locations} != {"PHS_GOOD"}
        or member_items != {item_id}
        or member_uoms != {uom}
        or member_accounting_iins != {source_iin}
    ):
        raise _phs2_contract_error(
            "PHS2_MIXED_MEMBERSHIP",
            "중앙 PHS=2에 서로 다른 품목·위치·회계 귀속 제품이 섞여 있습니다.",
        )

    return TransferSourcePreflight(
        source_bundle_id=source_bundle_id,
        source_session_id=source_session_id,
        authority_scope_id=authority_scope_id,
        ledger_plane=ledger_plane,
        plane_epoch=plane_epoch,
        item_id=item_id,
        uom=uom,
        source_iin=source_iin,
        member_ids=member_ids,
        normalized_barcodes=tuple(sorted(normalized_barcodes)),
        membership_hash=membership_hash(member_ids),
        barcode_membership_hash=membership_hash(normalized_barcodes),
        input_tag_id=input_tag_id,
        input_tag_label_id=label_id,
        input_tag_hash_prefix=hash_prefix,
        input_tag_core_hash=core_hash,
        input_tag_label_hash=label_hash,
        canonical_input_tag_qr=registry_qr_payload,
        active_label_qr_payload=active_label_qr_payload,
        active_label_id=active_label_id,
        active_label_business_date=active_label_business_date,
        active_label_worker_code=active_label_worker_code,
        active_label_resolution=active_label_resolution,
        scanned_label_id=scanned_label_id,
        replaced_scan=replaced_scan,
    )


class LogisticsTransferClient:
    """Authenticated logistics-v1 client with lost-ACK receipt recovery."""

    def __init__(
        self,
        base_url: str,
        token: str,
        source_host_id: str,
        *,
        device_id: str = "",
        timeout_seconds: float = 10.0,
        session: Any = None,
        authority_scope_id: str = "",
        authority_epoch: int = 0,
        authority_plane: str = "",
        ledger_plane: str = "",
        plane_epoch: int = 0,
        authoritative_required: bool = False,
    ) -> None:
        self.base_url = str(base_url or "").rstrip("/")
        self.token = str(token or "").strip()
        self.source_host_id = str(source_host_id or "").strip()
        self.device_id = str(device_id or source_host_id or "").strip()
        self.timeout_seconds = max(float(timeout_seconds), 0.1)
        self.authority_scope_id = str(authority_scope_id or "").strip()
        self.authority_epoch = int(authority_epoch or 0)
        self.authority_plane = str(authority_plane or "").strip().upper()
        self.ledger_plane = str(ledger_plane or authority_plane or "").strip().upper()
        self.plane_epoch = int(plane_epoch or 0)
        self.authoritative_required = bool(authoritative_required)
        if not self.base_url or not self.token or not self.source_host_id:
            raise ValueError("base_url, token, and source_host_id are required")
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("logistics base_url must be credential-free HTTPS")
        if self.authoritative_required and (
            not self.authority_scope_id
            or self.authority_epoch < 1
            or self.authority_plane != "AUTHORITATIVE"
            or self.ledger_plane not in {"AUTHORITATIVE", "SHADOW_CANDIDATE"}
            or self.plane_epoch < 1
        ):
            raise ValueError("authoritative logistics profile is incomplete")
        if session is None:
            import requests

            session = requests.Session()
        self.session = session
        self._test1_phs_reconciliation_prepare_ack_dropped = False

    def assert_authority(
        self,
        scope_id: str,
        *,
        authority_epoch: int | None = None,
        ledger_plane: str = "",
        plane_epoch: int | None = None,
    ) -> None:
        scope = str(scope_id or "").strip()
        if self.authority_scope_id and scope != self.authority_scope_id:
            raise TransferSealError(
                "AUTHORITY_PROFILE_MISMATCH",
                "스캔 데이터의 authority scope가 설치된 물류 프로필과 다릅니다.",
            )
        if self.authority_epoch and authority_epoch is not None and int(authority_epoch) != self.authority_epoch:
            raise TransferSealError("AUTHORITY_PROFILE_MISMATCH", "authority epoch가 설치 프로필과 다릅니다.")
        if self.ledger_plane and ledger_plane and str(ledger_plane).upper() != self.ledger_plane:
            raise TransferSealError("AUTHORITY_PROFILE_MISMATCH", "ledger plane이 설치 프로필과 다릅니다.")
        if self.plane_epoch and plane_epoch is not None and int(plane_epoch) != self.plane_epoch:
            raise TransferSealError("AUTHORITY_PROFILE_MISMATCH", "plane epoch가 설치 프로필과 다릅니다.")

    def _headers(self, idempotency_key: str = "") -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "X-Logistics-Source-Host-Id": self.source_host_id,
            "X-Logistics-Device-Id": self.device_id,
            "X-Logistics-Program": "Container_Audit",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, Any] | None = None,
        idempotency_key: str = "",
        allow_not_found: bool = False,
    ) -> dict[str, Any] | None:
        response = self.session.request(
            method,
            f"{self.base_url}{path}",
            headers=self._headers(idempotency_key),
            json=dict(payload) if payload is not None else None,
            timeout=self.timeout_seconds,
        )
        status_code = int(getattr(response, "status_code", 0) or 0)
        try:
            body = response.json()
        except Exception as exc:
            raise TransferSealError(
                "INVALID_SERVER_RESPONSE",
                "물류 서버가 JSON 응답을 반환하지 않았습니다.",
                status_code=status_code,
                retryable=True,
                committed=None,
            ) from exc
        if allow_not_found and status_code == 404:
            return None
        if not 200 <= status_code < 300 or not isinstance(body, dict) or body.get("ok") is False:
            error = body.get("error") if isinstance(body, dict) else {}
            error = error if isinstance(error, dict) else {}
            raise TransferSealError(
                str(error.get("code") or "LOGISTICS_SERVER_REJECTED"),
                str(error.get("message") or "물류 서버 요청이 거부되었습니다."),
                status_code=status_code,
                retryable=bool(body.get("retryable")) if isinstance(body, dict) else False,
                committed=body.get("committed") if isinstance(body, dict) else None,
                details=error.get("details") if isinstance(error.get("details"), dict) else {},
            )
        data = body.get("data")
        return dict(data) if isinstance(data, dict) else {}

    def resolve_source(self, identity: Mapping[str, Any]) -> dict[str, Any]:
        params = {
            key: str(identity.get(key) or "").strip()
            for key in (
                "bundle_id",
                "input_tag_id",
                "external_label",
                "item_id",
                "authority_scope_id",
            )
            if str(identity.get(key) or "").strip()
        }
        input_tag_hash_prefix = str(identity.get("input_tag_hash_prefix") or "").strip()
        if input_tag_hash_prefix:
            input_tag_label_id = str(identity.get("input_tag_label_id") or "").strip()
            if not input_tag_label_id:
                raise TransferSealError(
                    "SOURCE_IDENTITY_REQUIRED",
                    "중앙 PHS=2 현품표에 LBL 식별자가 없습니다.",
                )
            params["input_tag_label_id"] = input_tag_label_id
            params["input_tag_hash_prefix"] = input_tag_hash_prefix
        params["bundle_role"] = "TRANSFER_SOURCE"
        if self.authority_scope_id:
            supplied_scope = str(params.get("authority_scope_id") or "").strip()
            if supplied_scope and supplied_scope != self.authority_scope_id:
                self.assert_authority(supplied_scope)
            params["authority_scope_id"] = self.authority_scope_id
        if not any(params.get(key) for key in ("bundle_id", "input_tag_id", "external_label")):
            raise TransferSealError(
                "SOURCE_IDENTITY_REQUIRED",
                "현품표에 서버 PHS를 식별할 BND, ITG 또는 외부 라벨 값이 없습니다.",
            )
        result = self._request("GET", f"/logistics/api/v1/bundles/resolve?{urlencode(params)}")
        return dict(result or {})

    def resolve_phs_label(
        self,
        *,
        authority_scope_id: str,
        scan_payload: str,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        query = urlencode(
            {
                "authority_scope_id": scope,
                "scan_payload": _normalize_identifier(
                    scan_payload, "scan_payload"
                ),
            }
        )
        result = self._request(
            "GET", f"/logistics/api/v1/phs-labels/resolve?{query}"
        )
        return dict(result or {})

    def resolve_phs_reconciliation_actions(
        self,
        *,
        authority_scope_id: str,
        scan_payload: str,
        process_context: str = "transfer",
        limit: int = 20,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        query = urlencode(
            {
                "authority_scope_id": scope,
                "scan_payload": _normalize_identifier(
                    scan_payload, "scan_payload"
                ),
                "process_context": str(
                    process_context or ""
                ).strip().lower(),
                "limit": int(limit),
            }
        )
        result = self._request(
            "GET",
            (
                "/logistics/api/v1/phs-work-reconciliations/"
                f"actions/resolve?{query}"
            ),
        )
        return dict(result or {})

    def list_phs_work_instruction_candidates(
        self,
        *,
        authority_scope_id: str,
        business_date: str,
        item_id: str,
        target_qty_pcs: int,
        limit: int = 20,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        query = urlencode(
            {
                "authority_scope_id": scope,
                "business_date": _normalize_identifier(
                    business_date, "business_date"
                ),
                "item_id": _normalize_identifier(item_id, "item_id"),
                "target_qty_pcs": int(target_qty_pcs),
                "limit": int(limit),
            }
        )
        result = self._request(
            "GET",
            f"/logistics/api/v1/phs-work-instructions/candidates?{query}",
        )
        return dict(result or {})

    def adopt_phs_label(
        self,
        *,
        authority_scope_id: str,
        qr_payload: str,
        business_date: str = "",
        expected_session_version: int | None = None,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        payload: dict[str, Any] = {
            "authority_scope_id": scope,
            "qr_payload": _normalize_identifier(qr_payload, "qr_payload"),
        }
        if str(business_date or "").strip():
            payload["business_date"] = str(business_date).strip()
        if expected_session_version is not None:
            payload["expected_session_version"] = int(
                expected_session_version
            )
        result = self._request(
            "POST",
            "/logistics/api/v1/phs-labels/adopt",
            payload=payload,
        )
        return dict(result or {})

    def prepare_phs_label_exchange(
        self,
        *,
        authority_scope_id: str,
        exchange_kind: str,
        sources: list[dict[str, Any]],
        targets: list[dict[str, Any]],
        idempotency_key: str,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        result = self._request(
            "POST",
            "/logistics/api/v1/phs-label-exchanges/prepare",
            payload={
                "authority_scope_id": scope,
                "exchange_kind": str(exchange_kind or "").strip().upper(),
                "sources": list(sources),
                "targets": list(targets),
            },
            idempotency_key=_normalize_identifier(
                idempotency_key, "idempotency_key"
            ),
        )
        return dict(result or {})

    def prepare_phs_reconciliation_label_exchange(
        self,
        reconciliation_id: str,
        *,
        authority_scope_id: str,
        action_ids: list[str],
        expected_reconciliation_version: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        normalized_reconciliation_id = _normalize_identifier(
            reconciliation_id, "reconciliation_id"
        )
        self.assert_authority(scope)
        result = self._request(
            "POST",
            "/logistics/api/v1/phs-work-reconciliations/"
            f"{quote(normalized_reconciliation_id, safe='')}"
            "/label-exchange/prepare",
            payload={
                "authority_scope_id": scope,
                "action_ids": [
                    _normalize_identifier(value, "action_id")
                    for value in list(action_ids or [])
                ],
                "expected_reconciliation_version": int(
                    expected_reconciliation_version
                ),
            },
            idempotency_key=_normalize_identifier(
                idempotency_key, "idempotency_key"
            ),
        )
        exchange = (
            dict(result.get("exchange"))
            if isinstance(result, Mapping)
            and isinstance(result.get("exchange"), Mapping)
            else {}
        )
        exchange_id = str(exchange.get("exchange_id") or "").strip()
        drop_ack_reconciliation_id = os.environ.get(
            "KMTECH_TEST1_DROP_PHS_RECONCILIATION_PREPARE_ACK_ONCE",
            "",
        )
        if (
            not self._test1_phs_reconciliation_prepare_ack_dropped
            and scope == "TEST1-GOAL-20260722-EXACT-SIX"
            and self.device_id == "test1-common-host"
            and drop_ack_reconciliation_id == normalized_reconciliation_id
            and exchange_id
        ):
            self._test1_phs_reconciliation_prepare_ack_dropped = True
            raise TransferSealError(
                "PHS_RECONCILIATION_PREPARE_ACK_UNKNOWN",
                "중앙 prepare 성공 후 응답 ACK를 확인하지 못했습니다.",
                retryable=True,
                committed=None,
                details={
                    "reconciliation_id": normalized_reconciliation_id,
                    "exchange_id": exchange_id,
                },
            )
        return dict(result or {})

    def get_phs_label_exchange(
        self,
        exchange_id: str,
        *,
        authority_scope_id: str,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        query = urlencode({"authority_scope_id": scope})
        result = self._request(
            "GET",
            "/logistics/api/v1/phs-label-exchanges/"
            f"{quote(_normalize_identifier(exchange_id, 'exchange_id'), safe='')}"
            f"?{query}",
        )
        return dict(result or {})

    def request_phs_label_print(
        self,
        exchange_id: str,
        *,
        authority_scope_id: str,
        label_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        result = self._request(
            "POST",
            "/logistics/api/v1/phs-label-exchanges/"
            f"{quote(_normalize_identifier(exchange_id, 'exchange_id'), safe='')}"
            "/prints",
            payload={
                "authority_scope_id": scope,
                "label_id": _normalize_identifier(label_id, "label_id"),
            },
            idempotency_key=_normalize_identifier(
                idempotency_key, "idempotency_key"
            ),
        )
        return dict(result or {})

    def complete_phs_label_print(
        self,
        print_attempt_id: str,
        *,
        authority_scope_id: str,
        succeeded: bool,
        rendered_artifact_hash: str = "",
        proof: Mapping[str, Any] | None = None,
        error_code: str = "",
        error_message: str = "",
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        payload: dict[str, Any] = {
            "authority_scope_id": scope,
            "succeeded": bool(succeeded),
        }
        if succeeded:
            payload["rendered_artifact_hash"] = str(
                rendered_artifact_hash or ""
            ).strip().lower()
            payload["proof"] = dict(proof or {})
        else:
            payload["error_code"] = str(error_code or "").strip()
            payload["error_message"] = str(error_message or "").strip()
            if proof is not None:
                payload["proof"] = dict(proof)
        result = self._request(
            "POST",
            "/logistics/api/v1/phs-label-print-attempts/"
            f"{quote(_normalize_identifier(print_attempt_id, 'print_attempt_id'), safe='')}"
            "/complete",
            payload=payload,
        )
        return dict(result or {})

    def activate_phs_label_exchange(
        self,
        exchange_id: str,
        *,
        authority_scope_id: str,
        expected_exchange_version: int,
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        result = self._request(
            "POST",
            "/logistics/api/v1/phs-label-exchanges/"
            f"{quote(_normalize_identifier(exchange_id, 'exchange_id'), safe='')}"
            "/activate",
            payload={
                "authority_scope_id": scope,
                "expected_exchange_version": int(
                    expected_exchange_version
                ),
            },
        )
        return dict(result or {})

    def get_authority(self, scope_id: str) -> dict[str, Any]:
        self.assert_authority(scope_id)
        result = self._request(
            "GET", f"/logistics/api/v1/authority/{quote(str(scope_id), safe='')}"
        )
        return dict(result or {})

    def get_capabilities(self) -> dict[str, Any]:
        result = self._request("GET", "/logistics/api/v1/capabilities")
        return dict(result or {})

    def resolve_good_source(
        self, *, authority_scope_id: str, barcode: str
    ) -> dict[str, Any]:
        scope = _normalize_identifier(authority_scope_id, "authority_scope_id")
        self.assert_authority(scope)
        normalized_barcode = normalize_barcode(barcode)
        query = urlencode(
            {"authority_scope_id": scope, "barcode": normalized_barcode}
        )
        result = self._request(
            "GET",
            "/logistics/api/v1/replacements/good-source/resolve?" + query,
        )
        return dict(result or {})

    def get_receipt(self, scope_id: str, idempotency_key: str) -> dict[str, Any] | None:
        self.assert_authority(scope_id)
        return self._request(
            "GET",
            "/logistics/api/v1/receipts/"
            f"{quote(str(scope_id), safe='')}/{quote(str(idempotency_key), safe='')}",
            allow_not_found=True,
        )

    def seal_transfer(self, context: Mapping[str, Any]) -> dict[str, Any]:
        scope_id = str(context.get("authority_scope_id") or "").strip()
        idempotency_key = str(context.get("idempotency_key") or "").strip()
        if not scope_id or not idempotency_key:
            raise ValueError("command context requires scope and idempotency key")
        self.assert_authority(
            scope_id,
            authority_epoch=context.get("authority_epoch"),
            ledger_plane=str(context.get("ledger_plane") or ""),
            plane_epoch=context.get("plane_epoch"),
        )
        try:
            result = self._request(
                "POST",
                "/logistics/api/v1/transfers/seal",
                payload=context,
                idempotency_key=idempotency_key,
            )
            return dict(result or {})
        except TransferSealError as exc:
            if exc.committed is not True:
                raise
            recovered = self.get_receipt(scope_id, idempotency_key)
            if recovered is not None:
                return recovered
            raise
        except Exception as exc:
            try:
                recovered = self.get_receipt(scope_id, idempotency_key)
            except Exception:
                recovered = None
            if recovered is not None:
                return recovered
            raise TransferSealError(
                "TRANSPORT_ERROR",
                "물류 서버 응답을 확인하지 못했습니다.",
                retryable=True,
                committed=None,
                details={"exception_type": exc.__class__.__name__},
            ) from exc

    def replace_bundle_members(self, context: Mapping[str, Any]) -> dict[str, Any]:
        scope_id = str(context.get("authority_scope_id") or "").strip()
        idempotency_key = str(context.get("idempotency_key") or "").strip()
        payload = context.get("payload")
        target_bundle_id = (
            str(payload.get("target_bundle_id") or "").strip()
            if isinstance(payload, Mapping)
            else ""
        )
        if not scope_id or not idempotency_key or not target_bundle_id:
            raise ValueError("exchange command requires scope, idempotency key, and target bundle")
        self.assert_authority(
            scope_id,
            authority_epoch=context.get("authority_epoch"),
            ledger_plane=str(context.get("ledger_plane") or ""),
            plane_epoch=context.get("plane_epoch"),
        )
        path = (
            "/logistics/api/v1/bundles/"
            + quote(target_bundle_id, safe="")
            + "/members/replace"
        )
        try:
            result = self._request(
                "POST",
                path,
                payload=context,
                idempotency_key=idempotency_key,
            )
            return dict(result or {})
        except TransferSealError as exc:
            should_recover_receipt = (
                exc.committed is True
                or exc.committed is None
                or exc.status_code >= 500
            )
            if not should_recover_receipt:
                raise
            try:
                recovered = self.get_receipt(scope_id, idempotency_key)
            except Exception:
                raise exc
            if recovered is not None:
                return recovered
            raise exc
        except Exception as exc:
            try:
                recovered = self.get_receipt(scope_id, idempotency_key)
            except Exception:
                recovered = None
            if recovered is not None:
                return recovered
            raise TransferSealError(
                "TRANSPORT_ERROR",
                "중앙 제품 교체 응답을 확인하지 못했습니다.",
                retryable=True,
                committed=None,
                details={"exception_type": exc.__class__.__name__},
            ) from exc


@dataclass(frozen=True)
class SealAttempt:
    intent_id: str
    status: str
    command_id: str = ""
    transfer_bundle_id: str = ""
    seal_qr_payload: str = ""
    member_count: int = 0
    membership_hash: str = ""
    receipt_id: str = ""
    source_bundle_id: str = ""
    remainder_bundle_id: str = ""
    authority_scope_id: str = ""
    authority_epoch: int = 0
    ledger_plane: str = ""
    plane_epoch: int = 0
    item_id: str = ""
    inbound_iin: str = ""
    uom: str = ""
    entity_versions: dict[str, int] = field(default_factory=dict)
    retryable: bool = False
    error_code: str = ""
    error_message: str = ""


class TransferSealStore:
    """SQLite outbox that makes prepared scans and command payloads durable."""

    def __init__(self, db_path: str | os.PathLike[str]) -> None:
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            yield conn
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS transfer_seal_intents (
                    intent_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN (
                        'PREPARED','COMMAND_READY','RETRY_WAIT','ACKED','OPERATOR_REVIEW'
                    )),
                    master_label TEXT NOT NULL,
                    source_identity_json TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    operator TEXT NOT NULL,
                    scanned_barcodes_json TEXT NOT NULL,
                    scan_count INTEGER NOT NULL CHECK(scan_count > 0),
                    intent_hash TEXT NOT NULL UNIQUE,
                    command_id TEXT UNIQUE,
                    command_json TEXT,
                    command_hash TEXT,
                    receipt_json TEXT,
                    seal_qr_payload TEXT,
                    last_error_code TEXT,
                    last_error_message TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    CHECK((command_json IS NULL) = (command_id IS NULL)),
                    CHECK((command_json IS NULL) = (command_hash IS NULL))
                );
                CREATE TRIGGER IF NOT EXISTS trg_transfer_command_immutable
                BEFORE UPDATE OF command_id, command_json, command_hash
                ON transfer_seal_intents
                WHEN OLD.command_json IS NOT NULL AND (
                    NEW.command_id <> OLD.command_id OR
                    NEW.command_json <> OLD.command_json OR
                    NEW.command_hash <> OLD.command_hash
                )
                BEGIN SELECT RAISE(ABORT, 'transfer seal command is immutable'); END;
                CREATE TABLE IF NOT EXISTS transfer_exchange_block_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    reason_code TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def prepare(
        self,
        *,
        master_label: str,
        source_identity: Mapping[str, Any],
        item_id: str,
        operator: str,
        scanned_barcodes: Iterable[str],
    ) -> sqlite3.Row:
        raw_barcodes = [_normalize_identifier(value, "scanned_barcode") for value in scanned_barcodes]
        normalized = [normalize_barcode(value) for value in raw_barcodes]
        if not raw_barcodes or len(set(normalized)) != len(normalized):
            raise ValueError("scanned barcodes must be non-empty and unique")
        intent_material = {
            "master_label": _normalize_identifier(master_label, "master_label"),
            "source_identity": {key: str(value or "").strip() for key, value in source_identity.items()},
            "item_id": _normalize_identifier(item_id, "item_id"),
            "scanned_barcodes": raw_barcodes,
        }
        digest = _sha256(intent_material)
        intent_id = f"transfer-intent-{digest[:32]}"
        now = _utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT OR IGNORE INTO transfer_seal_intents (
                       intent_id,schema_version,status,master_label,source_identity_json,
                       item_id,operator,scanned_barcodes_json,scan_count,intent_hash,created_at,updated_at
                   ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    intent_id,
                    SCHEMA_VERSION,
                    "PREPARED",
                    intent_material["master_label"],
                    _canonical_json(intent_material["source_identity"]),
                    intent_material["item_id"],
                    str(operator or "").strip(),
                    _canonical_json(raw_barcodes),
                    len(raw_barcodes),
                    digest,
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def load(self, intent_id: str) -> sqlite3.Row:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
        if row is None:
            raise KeyError(intent_id)
        return row

    def precommand_operator_review(
        self,
        *,
        master_label: str,
        scanned_barcodes: Iterable[str],
        error_code: str,
    ) -> sqlite3.Row | None:
        """Return one exact review row only when no central command was durable."""

        raw_barcodes = [
            _normalize_identifier(value, "scanned_barcode")
            for value in scanned_barcodes
        ]
        if not raw_barcodes:
            return None
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT *
                     FROM transfer_seal_intents
                    WHERE status='OPERATOR_REVIEW'
                      AND master_label=?
                      AND scanned_barcodes_json=?
                      AND last_error_code=?
                      AND command_id IS NULL
                      AND command_json IS NULL
                      AND receipt_json IS NULL
                    ORDER BY updated_at DESC
                    LIMIT 2""",
                (
                    _normalize_identifier(master_label, "master_label"),
                    _canonical_json(raw_barcodes),
                    _normalize_identifier(error_code, "error_code"),
                ),
            ).fetchall()
        return rows[0] if len(rows) == 1 else None

    def bind_command(self, intent_id: str, context: Mapping[str, Any]) -> sqlite3.Row:
        command_id = _normalize_identifier(context.get("idempotency_key"), "idempotency_key")
        command_json = _canonical_json(dict(context))
        command_hash = hashlib.sha256(command_json.encode("utf-8")).hexdigest()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            if row is None:
                raise KeyError(intent_id)
            if row["command_json"] is not None:
                if (
                    row["command_id"] != command_id
                    or row["command_json"] != command_json
                    or row["command_hash"] != command_hash
                ):
                    raise ValueError("durable transfer command differs from retry payload")
            else:
                conn.execute(
                    """UPDATE transfer_seal_intents
                          SET status='COMMAND_READY',command_id=?,command_json=?,command_hash=?,
                              last_error_code=NULL,last_error_message=NULL,updated_at=?
                        WHERE intent_id=?""",
                    (command_id, command_json, command_hash, _utc_now(), intent_id),
                )
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def record_error(self, intent_id: str, error: TransferSealError) -> sqlite3.Row:
        operator_review_codes = {
            "AMBIGUOUS_BUNDLE",
            "SOURCE_IDENTITY_MISMATCH",
            "BUNDLE_IDENTITY_MISMATCH",
            "MEMBERSHIP_CONFLICT",
            "BARCODE_NOT_IN_SOURCE_BUNDLE",
            "BARCODE_MAPPING_AMBIGUOUS",
            "PARTIAL_PHS_TRANSFER_FORBIDDEN",
            "STALE_VERSION",
            "RECEIPT_MEMBERSHIP_MISMATCH",
            "SOURCE_IDENTITY_REQUIRED",
            "AUTHORITY_INVALID",
            "AUTHORITY_PROFILE_MISMATCH",
            "RESOLVER_CONTRACT_INVALID",
        }
        terminal_cas_conflict = error.status_code in {409, 412}
        terminal_client_error = (
            400 <= error.status_code < 500
            and error.status_code != 404
            and not error.retryable
        )
        local_contract_error = (
            error.code.upper().startswith("PHS2_")
            and not error.retryable
        )
        status = (
            "OPERATOR_REVIEW"
            if (
                error.code.upper() in operator_review_codes
                or terminal_cas_conflict
                or terminal_client_error
                or local_contract_error
            )
            else "RETRY_WAIT"
        )
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """UPDATE transfer_seal_intents
                      SET status=?,last_error_code=?,last_error_message=?,attempt_count=attempt_count+1,
                          updated_at=? WHERE intent_id=?""",
                (status, error.code, str(error), _utc_now(), intent_id),
            )
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def record_receipt(self, intent_id: str, receipt: Mapping[str, Any], seal_qr_payload: str) -> sqlite3.Row:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """UPDATE transfer_seal_intents
                      SET status='ACKED',receipt_json=?,seal_qr_payload=?,last_error_code=NULL,
                          last_error_message=NULL,attempt_count=attempt_count+1,updated_at=?
                    WHERE intent_id=?""",
                (_canonical_json(dict(receipt)), seal_qr_payload, _utc_now(), intent_id),
            )
            row = conn.execute(
                "SELECT * FROM transfer_seal_intents WHERE intent_id=?", (intent_id,)
            ).fetchone()
            conn.commit()
        assert row is not None
        return row

    def pending_ids(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT intent_id FROM transfer_seal_intents WHERE status IN (?,?,?) ORDER BY created_at",
                PENDING_STATUSES,
            ).fetchall()
        return [str(row["intent_id"]) for row in rows]

    def has_exact_history(self) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM transfer_seal_intents LIMIT 1").fetchone()
        return row is not None

    def record_exchange_block(self, *, reason_code: str, details: Mapping[str, Any]) -> str:
        created_at = _utc_now()
        material = {
            "reason_code": _normalize_identifier(reason_code, "reason_code"),
            "details": dict(details or {}),
            "created_at": created_at,
        }
        receipt_id = _deterministic_id("EXCHANGE-BLOCK", material)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT INTO transfer_exchange_block_receipts (
                       receipt_id,reason_code,details_json,created_at
                   ) VALUES (?,?,?,?)""",
                (receipt_id, material["reason_code"], _canonical_json(material["details"]), created_at),
            )
            conn.commit()
        return receipt_id


class TransferSealCoordinator:
    def __init__(self, store: TransferSealStore, client: LogisticsTransferClient | None) -> None:
        self.store = store
        self.client = client

    def prepare(
        self,
        *,
        master_label: str,
        master_label_fields: Mapping[str, Any],
        item_id: str,
        operator: str,
        scanned_barcodes: Iterable[str],
    ) -> SealAttempt:
        identity = source_identity_from_label(master_label_fields)
        if not identity["item_id"]:
            identity["item_id"] = str(item_id or "").strip()
        row = self.store.prepare(
            master_label=master_label,
            source_identity=identity,
            item_id=item_id,
            operator=operator,
            scanned_barcodes=scanned_barcodes,
        )
        return self._attempt_from_row(row)

    @staticmethod
    def _result_data(receipt: Mapping[str, Any]) -> dict[str, Any]:
        nested = receipt.get("data")
        return dict(nested) if isinstance(nested, Mapping) else dict(receipt)

    @staticmethod
    def _map_scans(bundle: Mapping[str, Any], scanned_barcodes: list[str]) -> list[str]:
        members = bundle.get("members")
        if not isinstance(members, list) or not members:
            raise TransferSealError("MEMBERSHIP_CONFLICT", "서버 PHS에 제품 membership 상세가 없습니다.")
        by_barcode: dict[str, list[str]] = {}
        for member in members:
            if not isinstance(member, Mapping):
                raise TransferSealError("MEMBERSHIP_CONFLICT", "서버 membership 형식이 잘못되었습니다.")
            unit_id = str(member.get("unit_id") or "").strip()
            barcode = str(member.get("normalized_barcode") or "").strip()
            if not unit_id or not barcode:
                raise TransferSealError("MEMBERSHIP_CONFLICT", "서버 membership 식별자가 누락됐습니다.")
            by_barcode.setdefault(normalize_barcode(barcode), []).append(unit_id)
        selected: list[str] = []
        for barcode in scanned_barcodes:
            candidates = by_barcode.get(normalize_barcode(barcode), [])
            if not candidates:
                raise TransferSealError(
                    "BARCODE_NOT_IN_SOURCE_BUNDLE", f"스캔 제품이 원본 PHS에 없습니다: {barcode}"
                )
            if len(candidates) != 1:
                raise TransferSealError(
                    "BARCODE_MAPPING_AMBIGUOUS", f"스캔 제품의 서버 unit 매핑이 하나가 아닙니다: {barcode}"
                )
            selected.append(candidates[0])
        if len(set(selected)) != len(selected):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "스캔 목록이 같은 서버 unit에 중복 매핑됐습니다.")
        server_member_ids = [str(value) for value in bundle.get("member_ids") or []]
        if set(selected) - set(server_member_ids):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "선택 membership이 원본 PHS 범위를 벗어났습니다.")
        return sorted(selected)

    def _build_work_group_command(
        self,
        row: sqlite3.Row,
        identity: Mapping[str, Any],
        resolved: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if self.client is None:
            raise TransferSealError(
                "LOGISTICS_CLIENT_NOT_CONFIGURED",
                "물류 서버 설정이 없어 이적 seal을 보류했습니다.",
                retryable=True,
            )
        fields = {
            "PHS": "2",
            "SRC": "KMTECH_INPUT_TAG",
            "ITG": str(identity.get("input_tag_id") or "").strip(),
            "CLC": str(identity.get("item_id") or row["item_id"]).strip(),
            "LBL": str(identity.get("input_tag_label_id") or "").strip(),
            "HSH": str(identity.get("input_tag_hash_prefix") or "").strip(),
        }
        preflight = validate_compact_phs2_preflight(fields, resolved)
        if preflight.item_id != str(row["item_id"]):
            raise TransferSealError(
                "SOURCE_IDENTITY_MISMATCH",
                "재조회한 중앙 현품표의 품목이 저장된 이적 작업과 일치하지 않습니다.",
            )
        source_value = resolved.get("work_group_source")
        if not isinstance(source_value, Mapping):
            raise TransferSealError(
                "RESOLVER_CONTRACT_INVALID",
                "서버 현품표 resolver 응답에 exact source topology가 없습니다.",
            )
        work_source = dict(source_value)
        scans = list(json.loads(row["scanned_barcodes_json"]))
        selected = self._map_scans(work_source, scans)
        if selected != list(preflight.member_ids):
            raise TransferSealError(
                "PARTIAL_PHS_TRANSFER_FORBIDDEN",
                "현재 physical 현품표의 exact membership 전량을 스캔해야 이적할 수 있습니다.",
            )
        self.client.assert_authority(
            preflight.authority_scope_id,
            ledger_plane=preflight.ledger_plane,
            plane_epoch=preflight.plane_epoch,
        )
        authority_epoch = int(self.client.authority_epoch or 0)
        if authority_epoch < 1:
            authority = self.client.get_authority(
                preflight.authority_scope_id
            )
            authority_epoch_value = authority.get("authority_epoch")
            if (
                isinstance(authority_epoch_value, bool)
                or not isinstance(authority_epoch_value, int)
                or authority_epoch_value < 1
            ):
                raise TransferSealError(
                    "AUTHORITY_INVALID",
                    "서버 authority epoch를 확인할 수 없습니다.",
                )
            authority_epoch = authority_epoch_value
        payload = {
            "source_resolution_basis": (
                "PHS_WORK_GROUP_EXACT_MEMBERSHIP"
            ),
            "phs_work_group": dict(preflight.phs_work_group),
            "source_bundles": [
                dict(value) for value in preflight.source_bundles
            ],
            "remainder_cover_groups": [
                dict(value) for value in preflight.remainder_cover_groups
            ],
            "topology_hash": preflight.topology_hash,
            "transfer_bundle_id": preflight.transfer_bundle_id,
            "external_label": preflight.transfer_external_label,
            "item_id": preflight.item_id,
            "uom": preflight.uom,
            "member_ids": list(preflight.member_ids),
            "membership_hash": preflight.membership_hash,
            "scanned_barcodes": scans,
        }
        return {
            "contract_version": CONTRACT_VERSION,
            "command_type": COMMAND_TYPE,
            "authority_scope_id": preflight.authority_scope_id,
            "authority_epoch": authority_epoch,
            "ledger_plane": preflight.ledger_plane,
            "plane_epoch": preflight.plane_epoch,
            "idempotency_key": f"container-seal:{row['intent_hash']}",
            "expected_versions": dict(preflight.entity_versions),
            "payload": payload,
            "client_exact_evidence": {
                "source_resolution_basis": (
                    "PHS_WORK_GROUP_EXACT_MEMBERSHIP"
                ),
                "phs_work_group": dict(preflight.phs_work_group),
                "source_bundles": [
                    dict(value) for value in preflight.source_bundles
                ],
                "remainder_cover_groups": [
                    dict(value)
                    for value in preflight.remainder_cover_groups
                ],
                "source_bundle_ids": list(preflight.source_bundle_ids),
                "source_session_ids": list(
                    preflight.source_session_ids
                ),
                "topology_hash": preflight.topology_hash,
                "source_member_ids": list(preflight.member_ids),
                "member_barcode_pairs": sorted(
                    [
                        {
                            "unit_id": str(member["unit_id"]),
                            "normalized_barcode": normalize_barcode(
                                member["normalized_barcode"]
                            ),
                        }
                        for member in work_source.get("members") or []
                        if isinstance(member, Mapping)
                    ],
                    key=lambda member: member["unit_id"],
                ),
            },
            "reason": "container_audit_phs_work_group_exact_scan_seal",
            "evidence_refs": [row["intent_id"], row["intent_hash"]],
        }

    def _build_command(self, row: sqlite3.Row) -> Mapping[str, Any]:
        if self.client is None:
            raise TransferSealError(
                "LOGISTICS_CLIENT_NOT_CONFIGURED",
                "물류 서버 설정이 없어 이적 seal을 보류했습니다.",
                retryable=True,
            )
        identity = json.loads(row["source_identity_json"])
        resolve_identity = {
            "bundle_id": identity.get("source_bundle_id"),
            "input_tag_id": identity.get("input_tag_id"),
            "input_tag_label_id": identity.get("input_tag_label_id"),
            "input_tag_hash_prefix": identity.get("input_tag_hash_prefix"),
            "external_label": identity.get("external_label"),
            "authority_scope_id": identity.get("authority_scope_id"),
            "item_id": identity.get("item_id") or row["item_id"],
        }
        try:
            resolved = self.client.resolve_source(resolve_identity)
        except TransferSealError as exc:
            if exc.status_code == 404:
                raise TransferSealError(
                    "SOURCE_NOT_YET_AVAILABLE",
                    "서버에서 원본 PHS를 아직 찾지 못해 이적 seal을 보류했습니다.",
                    retryable=True,
                    details=exc.details,
                ) from exc
            raise
        if (
            isinstance(resolved, Mapping)
            and str(
                resolved.get("source_resolution_basis") or ""
            ).strip().upper()
            == "PHS_WORK_GROUP_EXACT_MEMBERSHIP"
            and "work_group_source" in resolved
        ):
            return self._build_work_group_command(
                row,
                identity,
                resolved,
            )
        bundle_value = resolved.get("bundle") if isinstance(resolved, Mapping) else None
        if not isinstance(bundle_value, Mapping):
            raise TransferSealError(
                "RESOLVER_CONTRACT_INVALID",
                "서버 PHS resolver 응답에 정본 bundle projection이 없습니다.",
            )
        candidate_count = resolved.get("candidate_count")
        if (
            isinstance(candidate_count, bool)
            or not isinstance(candidate_count, int)
            or candidate_count != 1
        ):
            raise TransferSealError(
                "AMBIGUOUS_BUNDLE",
                "서버 PHS resolver가 이적 원본을 정확히 하나로 확정하지 못했습니다.",
            )
        bundle = dict(bundle_value)
        source_bundle_id = _normalize_identifier(bundle.get("bundle_id"), "source_bundle_id")
        if (
            bundle.get("bundle_role") != "TRANSFER_SOURCE"
            or bundle.get("bundle_type") not in {"PHS", "RESIDUAL"}
            or bundle.get("bundle_state") != "AVAILABLE"
        ):
            raise TransferSealError(
                "SOURCE_IDENTITY_MISMATCH", "서버 응답 bundle이 이적 가능한 원본 PHS/잔량이 아닙니다."
            )
        if str(identity.get("input_tag_hash_prefix") or "").strip():
            preflight = validate_compact_phs2_preflight(
                {
                    "PHS": "2",
                    "SRC": "KMTECH_INPUT_TAG",
                    "ITG": str(identity.get("input_tag_id") or "").strip(),
                    "CLC": str(identity.get("item_id") or row["item_id"]).strip(),
                    "LBL": str(identity.get("input_tag_label_id") or "").strip(),
                    "HSH": str(
                        identity.get("input_tag_hash_prefix") or ""
                    ).strip(),
                },
                resolved,
            )
            if (
                preflight.source_bundle_id != source_bundle_id
                or preflight.item_id != str(row["item_id"])
            ):
                raise TransferSealError(
                    "SOURCE_IDENTITY_MISMATCH",
                    "재조회한 중앙 PHS=2 원본이 저장된 이적 작업과 일치하지 않습니다.",
                )
        if str(bundle.get("item_id") or "") != str(row["item_id"]):
            raise TransferSealError(
                "SOURCE_IDENTITY_MISMATCH", "서버 원본 bundle의 품목이 현품표와 일치하지 않습니다."
            )
        raw_source_members = bundle.get("member_ids")
        if not isinstance(raw_source_members, list):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "원본 PHS exact membership이 없습니다.")
        source_members = [str(value or "").strip() for value in raw_source_members]
        source_member_count = bundle.get("member_count")
        if (
            not source_members
            or any(not value for value in source_members)
            or len(set(source_members)) != len(source_members)
            or isinstance(source_member_count, bool)
            or not isinstance(source_member_count, int)
            or source_member_count != len(source_members)
        ):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "원본 PHS membership이 비어 있거나 중복됐습니다.")
        if membership_hash(source_members) != str(bundle.get("membership_hash") or ""):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "원본 PHS membership hash가 일치하지 않습니다.")
        member_rows = bundle.get("members")
        if not isinstance(member_rows, list) or len(member_rows) != len(source_members):
            raise TransferSealError("MEMBERSHIP_CONFLICT", "원본 PHS barcode mapping이 일부만 제공됐습니다.")
        row_unit_ids: list[str] = []
        source_barcodes: list[str] = []
        for member in member_rows:
            if not isinstance(member, Mapping):
                raise TransferSealError("MEMBERSHIP_CONFLICT", "서버 membership 형식이 잘못되었습니다.")
            unit_id = str(member.get("unit_id") or "").strip()
            barcode = str(member.get("normalized_barcode") or "").strip()
            if not unit_id or not barcode:
                raise TransferSealError("MEMBERSHIP_CONFLICT", "서버 membership 식별자가 누락됐습니다.")
            row_unit_ids.append(unit_id)
            source_barcodes.append(normalize_barcode(barcode))
        source_barcodes.sort()
        if (
            len(set(row_unit_ids)) != len(row_unit_ids)
            or set(row_unit_ids) != set(source_members)
            or len(set(source_barcodes)) != len(source_barcodes)
            or isinstance(bundle.get("barcode_member_count"), bool)
            or not isinstance(bundle.get("barcode_member_count"), int)
            or bundle.get("barcode_member_count") != len(source_barcodes)
            or bundle.get("barcode_membership_hash") != membership_hash(source_barcodes)
            or not str(bundle.get("source_iin") or "").strip()
            or not str(bundle.get("uom") or "").strip()
        ):
            raise TransferSealError(
                "MEMBERSHIP_CONFLICT", "원본 PHS barcode membership 증거가 일치하지 않습니다."
            )
        scans = list(json.loads(row["scanned_barcodes_json"]))
        selected = self._map_scans(bundle, scans)
        if bundle.get("bundle_type") == "PHS" and selected != sorted(source_members):
            raise TransferSealError(
                "PARTIAL_PHS_TRANSFER_FORBIDDEN",
                "PHS=2 현품표는 exact membership 전량만 이적할 수 있습니다. 잔량은 RSL1을 사용하세요.",
            )
        selected_hash = membership_hash(selected)
        transfer_bundle_id = _deterministic_id(
            "TRANSFER", {"source_bundle_id": source_bundle_id, "member_ids": selected}
        )
        remainder = sorted(set(source_members) - set(selected))
        payload: dict[str, Any] = {
            "source_bundle_id": source_bundle_id,
            "transfer_bundle_id": transfer_bundle_id,
            "external_label": transfer_bundle_id,
            "item_id": row["item_id"],
            "member_ids": selected,
            "membership_hash": selected_hash,
            "scanned_barcodes": scans,
        }
        if remainder:
            remainder_bundle_id = _deterministic_id(
                "TRANSFER-REMAINDER",
                {"source_bundle_id": source_bundle_id, "member_ids": remainder},
            )
            payload.update(
                {
                    "remainder_bundle_id": remainder_bundle_id,
                }
            )
        scope_id = _normalize_identifier(bundle.get("authority_scope_id"), "authority_scope_id")
        authority_epoch = bundle.get("authority_epoch")
        if not isinstance(authority_epoch, int) or isinstance(authority_epoch, bool):
            authority = self.client.get_authority(scope_id)
            authority_epoch = authority.get("authority_epoch")
        if not isinstance(authority_epoch, int) or isinstance(authority_epoch, bool):
            raise TransferSealError("AUTHORITY_INVALID", "서버 authority epoch를 확인할 수 없습니다.")
        plane_epoch = bundle.get("plane_epoch")
        entity_version = bundle.get("entity_version")
        if not isinstance(plane_epoch, int) or isinstance(plane_epoch, bool) or plane_epoch < 1:
            raise TransferSealError("AUTHORITY_INVALID", "서버 plane epoch가 잘못됐습니다.")
        if str(bundle.get("ledger_plane") or "") not in {"AUTHORITATIVE", "SHADOW_CANDIDATE"}:
            raise TransferSealError("AUTHORITY_INVALID", "서버 ledger plane이 이적 가능한 상태가 아닙니다.")
        if not isinstance(entity_version, int) or isinstance(entity_version, bool) or entity_version < 1:
            raise TransferSealError("MEMBERSHIP_CONFLICT", "원본 PHS version이 잘못됐습니다.")
        idempotency_key = f"container-seal:{row['intent_hash']}"
        return {
            "contract_version": CONTRACT_VERSION,
            "command_type": COMMAND_TYPE,
            "authority_scope_id": scope_id,
            "authority_epoch": authority_epoch,
            "ledger_plane": str(bundle.get("ledger_plane") or ""),
            "plane_epoch": plane_epoch,
            "idempotency_key": idempotency_key,
            "expected_versions": {f"bundle:{source_bundle_id}": entity_version},
            "payload": payload,
            "client_exact_evidence": {
                "source_member_ids": sorted(source_members),
                "remainder_member_ids": remainder,
            },
            "reason": "container_audit_exact_scan_seal",
            "evidence_refs": [row["intent_id"], row["intent_hash"]],
        }

    @staticmethod
    def _seal_qr(context: Mapping[str, Any], data: Mapping[str, Any]) -> str:
        # The server is the sole issuer of the opaque seal identity/token.  A
        # desktop-generated compatibility QR cannot later be invalidated
        # safely, so never synthesize one from membership data.
        qr_payload = str(data.get("seal_qr_payload") or "").strip()
        if not qr_payload:
            raise TransferSealError(
                "RECEIPT_MEMBERSHIP_MISMATCH",
                "서버 receipt에 이적 seal QR이 없습니다.",
            )
        return qr_payload

    @staticmethod
    def _validate_work_group_receipt(
        context: Mapping[str, Any],
        receipt: Mapping[str, Any],
    ) -> dict[str, Any]:
        def mismatch(message: str) -> None:
            raise TransferSealError(
                "RECEIPT_MEMBERSHIP_MISMATCH",
                message,
            )

        try:
            payload_value = context.get("payload")
            if not isinstance(payload_value, Mapping):
                mismatch("저장된 이적 명령 payload가 올바르지 않습니다.")
            payload = dict(payload_value)
            data = TransferSealCoordinator._result_data(receipt)
            receipt_id = str(receipt.get("receipt_id") or "").strip()
            event_ids = receipt.get("event_ids")
            outbox_ids = receipt.get("outbox_ids")
            if (
                not receipt_id
                or receipt.get("contract_version") != CONTRACT_VERSION
                or receipt.get("command_type") != COMMAND_TYPE
                or str(receipt.get("status") or "").upper() != "COMMITTED"
                or receipt.get("authority_scope_id")
                != context["authority_scope_id"]
                or receipt.get("authority_epoch")
                != context["authority_epoch"]
                or str(receipt.get("resolved_ledger_plane") or "").upper()
                != str(context["ledger_plane"]).upper()
                or receipt.get("resolved_plane_epoch")
                != context["plane_epoch"]
                or not str(receipt.get("committed_at") or "").strip()
                or not isinstance(event_ids, (list, tuple))
                or len(event_ids) != 1
                or not str(event_ids[0] or "").strip()
                or not isinstance(outbox_ids, (list, tuple))
                or len(outbox_ids) != 1
                or not str(outbox_ids[0] or "").strip()
            ):
                mismatch("서버 receipt의 COMMITTED 원자 처리 증거가 불완전합니다.")

            group = payload.get("phs_work_group")
            source_specs = payload.get("source_bundles")
            cover_groups = payload.get("remainder_cover_groups")
            if (
                not isinstance(group, Mapping)
                or not isinstance(source_specs, list)
                or not source_specs
                or not all(
                    isinstance(value, Mapping) for value in source_specs
                )
                or not isinstance(cover_groups, list)
                or not all(
                    isinstance(value, Mapping) for value in cover_groups
                )
            ):
                mismatch("저장된 현품표 topology 명령 증거가 불완전합니다.")
            group = dict(group)
            source_specs = [dict(value) for value in source_specs]
            cover_groups = [dict(value) for value in cover_groups]
            source_ids = [str(value["bundle_id"]) for value in source_specs]
            source_sessions = sorted(
                {str(value["source_session_id"]) for value in source_specs}
            )
            transfer_id = str(payload["transfer_bundle_id"])
            expected_member_ids = sorted(
                str(value) for value in payload["member_ids"]
            )
            expected_barcodes = sorted(
                normalize_barcode(value)
                for value in payload["scanned_barcodes"]
            )
            if (
                not expected_member_ids
                or len(expected_member_ids) != len(set(expected_member_ids))
                or len(expected_barcodes) != len(set(expected_barcodes))
                or membership_hash(expected_member_ids)
                != payload["membership_hash"]
            ):
                mismatch("저장된 현품표 exact scan 명령 증거가 올바르지 않습니다.")

            evidence_value = context.get("client_exact_evidence")
            evidence = (
                dict(evidence_value)
                if isinstance(evidence_value, Mapping)
                else {}
            )
            expected_pair_rows = evidence.get("member_barcode_pairs")
            if not isinstance(expected_pair_rows, list):
                mismatch("저장된 제품-barcode exact mapping 증거가 없습니다.")
            expected_pairs = sorted(
                (
                    _normalize_identifier(row.get("unit_id"), "unit_id"),
                    normalize_barcode(row.get("normalized_barcode")),
                )
                for row in expected_pair_rows
                if isinstance(row, Mapping)
            )
            if (
                len(expected_pairs) != len(expected_member_ids)
                or [unit_id for unit_id, _barcode in expected_pairs]
                != expected_member_ids
                or sorted(barcode for _unit_id, barcode in expected_pairs)
                != expected_barcodes
            ):
                mismatch("저장된 제품-barcode exact mapping이 명령과 일치하지 않습니다.")

            expected_remainders: list[dict[str, Any]] = []
            remainder_by_source: dict[str, str] = {}
            for source in source_specs:
                remainder_ids = sorted(
                    str(value)
                    for value in source.get("remainder_member_ids") or []
                )
                remainder_id = str(
                    source.get("remainder_bundle_id") or ""
                )
                if remainder_ids:
                    if not remainder_id:
                        mismatch("SPLIT source의 deterministic remainder ID가 없습니다.")
                    remainder_by_source[str(source["bundle_id"])] = (
                        remainder_id
                    )
                    expected_remainders.append(
                        {
                            "source_bundle_id": str(source["bundle_id"]),
                            "remainder_bundle_id": remainder_id,
                            "remainder_external_label": (
                                f"WORK-REMAINDER::{remainder_id}"
                            ),
                            "remainder_external_label_kind": (
                                "INTERNAL_LOGISTICS_ALIAS_NOT_PHYSICAL"
                            ),
                            "member_ids": remainder_ids,
                            "member_count": len(remainder_ids),
                            "membership_hash": membership_hash(
                                remainder_ids
                            ),
                        }
                    )
                elif remainder_id:
                    mismatch("빈 remainder source에 bundle ID가 남아 있습니다.")
            remainder_ids = [
                value["remainder_bundle_id"]
                for value in expected_remainders
            ]

            raw_versions = receipt.get("entity_versions")
            if not isinstance(raw_versions, Mapping):
                raw_versions = data.get("entity_versions")
            if not isinstance(raw_versions, Mapping):
                mismatch("서버 receipt의 topology CAS version 증거가 없습니다.")
            actual_versions = dict(raw_versions)
            command_versions = context.get("expected_versions")
            if not isinstance(command_versions, Mapping):
                mismatch("저장된 명령의 topology CAS version 증거가 없습니다.")
            expected_versions = {
                str(key): int(value)
                for key, value in command_versions.items()
                if isinstance(value, int) and not isinstance(value, bool)
            }
            if len(expected_versions) != len(command_versions):
                mismatch("저장된 명령의 topology CAS version이 올바르지 않습니다.")
            source_version_keys = {
                f"bundle:{source_id}" for source_id in source_ids
            }
            transfer_version_key = f"bundle:{transfer_id}"
            expected_after: dict[str, int] = {}
            for entity_key, version in expected_versions.items():
                if entity_key in source_version_keys:
                    expected_after[entity_key] = version + 1
                elif entity_key == transfer_version_key:
                    if version != 0:
                        mismatch("deterministic transfer version이 0이 아닙니다.")
                    expected_after[entity_key] = 1
                elif entity_key.startswith("phs_work_group:"):
                    expected_after[entity_key] = version + 1
                else:
                    expected_after[entity_key] = version
            for remainder_id in remainder_ids:
                expected_after[f"bundle:{remainder_id}"] = 1
            if actual_versions != expected_after:
                mismatch("서버 receipt의 topology CAS version 결과가 명령과 일치하지 않습니다.")

            transitions_value = data.get("source_transitions")
            if not isinstance(transitions_value, list):
                mismatch("서버 receipt의 source transition 증거가 없습니다.")
            transitions = {
                str(value.get("source_bundle_id") or ""): dict(value)
                for value in transitions_value
                if isinstance(value, Mapping)
            }
            if (
                len(transitions) != len(source_specs)
                or set(transitions) != set(source_ids)
            ):
                mismatch("서버 receipt의 source transition 수량이 일치하지 않습니다.")
            for source in source_specs:
                source_id = str(source["bundle_id"])
                transition = transitions[source_id]
                full = sorted(
                    str(value)
                    for value in source["source_member_ids"]
                )
                selected = sorted(
                    str(value)
                    for value in source["selected_member_ids"]
                )
                before_version = expected_versions[
                    f"bundle:{source_id}"
                ]
                if (
                    transition.get("entity_version_before")
                    != before_version
                    or transition.get("entity_version_after")
                    != before_version + 1
                    or transition.get("state_before") != "AVAILABLE"
                    or transition.get("state_after") != "CONSUMED"
                    or sorted(
                        str(value)
                        for value in transition.get(
                            "source_member_ids"
                        )
                        or []
                    )
                    != full
                    or transition.get("source_member_count")
                    != len(full)
                    or transition.get("source_membership_hash")
                    != membership_hash(full)
                    or sorted(
                        str(value)
                        for value in transition.get(
                            "selected_member_ids"
                        )
                        or []
                    )
                    != selected
                    or transition.get("selected_member_count")
                    != len(selected)
                    or transition.get("selected_membership_hash")
                    != membership_hash(selected)
                    or str(
                        transition.get("remainder_bundle_id") or ""
                    )
                    != remainder_by_source.get(source_id, "")
                ):
                    mismatch("서버 receipt의 source partition transition이 명령과 일치하지 않습니다.")

            actual_remainders = data.get("remainder_bundles")
            if not isinstance(actual_remainders, list):
                mismatch("서버 receipt의 remainder bundle 증거가 없습니다.")
            if _canonical_json(actual_remainders) != _canonical_json(
                expected_remainders
            ):
                mismatch("서버 receipt의 deterministic remainder bundle이 명령과 일치하지 않습니다.")

            root_specs: set[tuple[str, str, str]] = {
                (
                    str(group["group_id"]),
                    "TRANSFER_BUNDLE",
                    transfer_id,
                )
            }
            for source in source_specs:
                source_id = str(source["bundle_id"])
                remainder_id = remainder_by_source.get(source_id)
                if not remainder_id:
                    continue
                for cover_group_id in source.get(
                    "remainder_cover_group_ids"
                ) or []:
                    root_specs.add(
                        (
                            str(cover_group_id),
                            "PHS_BUNDLE",
                            remainder_id,
                        )
                    )
            expected_root_proof = [
                {
                    "group_id": group_id,
                    "root_type": root_type,
                    "root_id": root_id,
                    "root_role": "SOURCE",
                    "added_receipt_id": receipt_id,
                }
                for group_id, root_type, root_id in sorted(root_specs)
            ]
            root_proof = data.get("root_proof")
            if _canonical_json(root_proof) != _canonical_json(
                expected_root_proof
            ):
                mismatch("서버 receipt의 work-group root proof가 명령과 일치하지 않습니다.")

            expected_group_versions = {
                str(group["group_id"]): expected_versions[
                    f"phs_work_group:{group['group_id']}"
                ]
                + 1,
                **{
                    str(cover["group_id"]): expected_versions[
                        f"phs_work_group:{cover['group_id']}"
                    ]
                    + 1
                    for cover in cover_groups
                },
            }
            if data.get("group_entity_versions_after") != (
                expected_group_versions
            ):
                mismatch("서버 receipt의 work-group CAS 결과가 명령과 일치하지 않습니다.")
            topology_hash_before = str(
                payload.get("topology_hash") or ""
            )
            topology_hash_after = _sha256(
                {
                    "topology_hash_before": topology_hash_before,
                    "transfer_bundle_id": transfer_id,
                    "remainder_bundle_ids": remainder_ids,
                    "root_proof": expected_root_proof,
                    "group_entity_versions": expected_group_versions,
                }
            )
            if (
                data.get("atomic") is not True
                or data.get("receipt_contract_version")
                != "PHS_WORK_GROUP_TRANSFER_V1"
                or data.get("source_resolution_basis")
                != "PHS_WORK_GROUP_EXACT_MEMBERSHIP"
                or _canonical_json(data.get("phs_work_group"))
                != _canonical_json(group)
                or _canonical_json(data.get("source_bundles"))
                != _canonical_json(source_specs)
                or _canonical_json(data.get("remainder_cover_groups"))
                != _canonical_json(cover_groups)
                or data.get("topology_hash_before")
                != topology_hash_before
                or data.get("topology_hash_after")
                != topology_hash_after
                or topology_hash_after == topology_hash_before
            ):
                mismatch("서버 receipt의 atomic topology 증거가 명령과 일치하지 않습니다.")

            def receipt_pairs(value: Any) -> list[tuple[str, str]]:
                if not isinstance(value, list):
                    mismatch("서버 receipt의 제품-barcode mapping 형식이 올바르지 않습니다.")
                pairs = sorted(
                    (
                        _normalize_identifier(row.get("unit_id"), "unit_id"),
                        normalize_barcode(row.get("normalized_barcode")),
                    )
                    for row in value
                    if isinstance(row, Mapping)
                )
                if len(pairs) != len(value):
                    mismatch("서버 receipt의 제품-barcode mapping 일부가 손상됐습니다.")
                return pairs

            actual_member_ids = sorted(
                str(value) for value in data.get("member_ids") or []
            )
            actual_barcodes = sorted(
                normalize_barcode(value)
                for value in data.get("scanned_barcodes") or []
            )
            actual_pairs = receipt_pairs(data.get("members"))
            sealed_pairs = receipt_pairs(data.get("sealed_members"))
            if (
                data.get("source_bundle_ids") != source_ids
                or data.get("source_bundle_count") != len(source_ids)
                or data.get("source_session_ids") != source_sessions
                or str(data.get("source_bundle_id") or "")
                != (source_ids[0] if len(source_ids) == 1 else "")
                or data.get("scan_anchor_input_tag_id")
                != group["scan_anchor_input_tag_id"]
                or data.get("transfer_bundle_id") != transfer_id
                or data.get("transfer_external_label")
                != payload["external_label"]
                or data.get("item_id") != payload["item_id"]
                or data.get("uom") != payload["uom"]
                or not str(data.get("inbound_iin") or "").strip()
                or {
                    str(value["accounting_inbound_iin"])
                    for value in source_specs
                }
                != {str(data.get("inbound_iin") or "")}
                or actual_member_ids != expected_member_ids
                or data.get("member_count") != len(expected_member_ids)
                or data.get("membership_hash")
                != payload["membership_hash"]
                or actual_barcodes != expected_barcodes
                or data.get("scanned_barcode_count")
                != len(expected_barcodes)
                or data.get("scanned_barcode_hash")
                != membership_hash(expected_barcodes)
                or actual_pairs != expected_pairs
                or data.get("remainder_bundle_ids")
                != remainder_ids
                or data.get("post_seal_exchange_policy")
                != "BLOCKED_REQUIRES_TWO_BUNDLE_CAS"
            ):
                mismatch("서버 receipt의 transfer exact membership이 명령과 일치하지 않습니다.")

            seal_qr_payload = str(
                data.get("seal_qr_payload") or ""
            ).strip()
            seal_fields = {
                key.strip().upper(): unquote(value.strip())
                for key, value in (
                    part.split("=", 1)
                    for part in seal_qr_payload.split("|")
                    if "=" in part
                )
            }
            if (
                data.get("seal_contract_version")
                != "transfer-seal-qr-v1"
                or data.get("seal_state") != "ACTIVE"
                or not str(data.get("seal_id") or "").strip()
                or data.get("seal_revision") != 1
                or not str(data.get("seal_token") or "").strip()
                or data.get("sealed_bundle_id") != transfer_id
                or data.get("sealed_bundle_version") != 1
                or sorted(
                    str(value)
                    for value in data.get("sealed_member_ids") or []
                )
                != expected_member_ids
                or sealed_pairs != expected_pairs
                or data.get("sealed_member_count")
                != len(expected_member_ids)
                or data.get("sealed_membership_hash")
                != payload["membership_hash"]
                or sorted(
                    normalize_barcode(value)
                    for value in data.get(
                        "sealed_normalized_barcodes"
                    )
                    or []
                )
                != expected_barcodes
                or data.get("sealed_barcode_membership_hash")
                != membership_hash(expected_barcodes)
                or seal_fields.get("TRF") != "1"
                or seal_fields.get("BND") != transfer_id
                or seal_fields.get("AUTH_SCOPE")
                != context["authority_scope_id"]
                or seal_fields.get("CLC") != payload["item_id"]
                or seal_fields.get("QT")
                != str(len(expected_member_ids))
                or seal_fields.get("HSH")
                != payload["membership_hash"]
                or seal_fields.get("EPOCH")
                != str(context["authority_epoch"])
                or seal_fields.get("PLANE")
                != context["ledger_plane"]
                or seal_fields.get("PE")
                != str(context["plane_epoch"])
                or seal_fields.get("SID") != data.get("seal_id")
                or seal_fields.get("SREV")
                != str(data.get("seal_revision"))
                or seal_fields.get("STK") != data.get("seal_token")
            ):
                mismatch("서버 receipt의 opaque transfer seal 증거가 명령과 일치하지 않습니다.")
            return data
        except TransferSealError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise TransferSealError(
                "RECEIPT_MEMBERSHIP_MISMATCH",
                "서버 receipt의 현품표 원자 이적 증거를 해석할 수 없습니다.",
            ) from exc

    @staticmethod
    def _validate_receipt(context: Mapping[str, Any], receipt: Mapping[str, Any]) -> dict[str, Any]:
        payload_value = context.get("payload")
        if (
            isinstance(payload_value, Mapping)
            and payload_value.get("source_resolution_basis")
            == "PHS_WORK_GROUP_EXACT_MEMBERSHIP"
        ):
            return TransferSealCoordinator._validate_work_group_receipt(
                context,
                receipt,
            )
        data = TransferSealCoordinator._result_data(receipt)
        payload = context["payload"]
        actual_ids = sorted(str(value) for value in data.get("member_ids") or [])
        expected_barcodes = sorted(normalize_barcode(value) for value in payload["scanned_barcodes"])
        actual_barcodes = sorted(str(value) for value in data.get("scanned_barcodes") or [])
        evidence = context.get("client_exact_evidence")
        evidence = evidence if isinstance(evidence, Mapping) else {}
        expected_remainder_ids = sorted(
            str(value) for value in evidence.get("remainder_member_ids") or []
        )
        actual_remainder_ids = sorted(
            str(value) for value in data.get("remainder_member_ids") or []
        )
        source_member_ids = sorted(
            str(value) for value in evidence.get("source_member_ids") or []
        )
        actual_member_pairs = sorted(
            (
                str(row.get("unit_id") or ""),
                normalize_barcode(row.get("normalized_barcode")),
            )
            for row in (data.get("members") or [])
            if isinstance(row, Mapping)
        )
        sealed_member_pairs = sorted(
            (
                str(row.get("unit_id") or ""),
                normalize_barcode(row.get("normalized_barcode")),
            )
            for row in (data.get("sealed_members") or [])
            if isinstance(row, Mapping)
        )
        seal_qr_payload = str(data.get("seal_qr_payload") or "").strip()
        seal_fields = {
            key.strip().upper(): unquote(value.strip())
            for key, value in (
                part.split("=", 1)
                for part in seal_qr_payload.split("|")
                if "=" in part
            )
        }
        raw_versions = receipt.get("entity_versions")
        if not isinstance(raw_versions, Mapping):
            raw_versions = data.get("entity_versions")
        actual_versions = dict(raw_versions) if isinstance(raw_versions, Mapping) else {}
        expected_versions = {
            str(key): int(value) + 1
            for key, value in context.get("expected_versions", {}).items()
        }
        expected_versions[f"bundle:{payload['transfer_bundle_id']}"] = 1
        if payload.get("remainder_bundle_id"):
            expected_versions[f"bundle:{payload['remainder_bundle_id']}"] = 1
        if (
            not str(receipt.get("receipt_id") or "").strip()
            or receipt.get("contract_version") != CONTRACT_VERSION
            or receipt.get("command_type") != COMMAND_TYPE
            or str(receipt.get("status") or "").upper() != "COMMITTED"
            or receipt.get("authority_scope_id") != context["authority_scope_id"]
            or receipt.get("authority_epoch") != context["authority_epoch"]
            or str(receipt.get("resolved_ledger_plane") or "").upper()
            != str(context["ledger_plane"]).upper()
            or receipt.get("resolved_plane_epoch") != context["plane_epoch"]
            or not str(receipt.get("committed_at") or "").strip()
            or not isinstance(receipt.get("event_ids"), (list, tuple))
            or not receipt.get("event_ids")
            or not isinstance(receipt.get("outbox_ids"), (list, tuple))
            or not receipt.get("outbox_ids")
            or any(
                actual_versions.get(key) != version
                for key, version in expected_versions.items()
            )
            or data.get("transfer_bundle_id") != payload["transfer_bundle_id"]
            or data.get("item_id") != payload["item_id"]
            or actual_ids != sorted(payload["member_ids"])
            or data.get("member_count") != len(payload["member_ids"])
            or data.get("membership_hash") != payload["membership_hash"]
            or actual_barcodes != expected_barcodes
            or data.get("scanned_barcode_count") != len(expected_barcodes)
            or data.get("scanned_barcode_hash") != membership_hash(expected_barcodes)
            or actual_remainder_ids != expected_remainder_ids
            or data.get("remainder_member_count") != len(expected_remainder_ids)
            or data.get("remainder_membership_hash")
            != (membership_hash(expected_remainder_ids) if expected_remainder_ids else None)
            or sorted(actual_ids + actual_remainder_ids) != source_member_ids
            or bool(set(actual_ids) & set(actual_remainder_ids))
            or not str(data.get("inbound_iin") or "").strip()
            or not str(data.get("uom") or "").strip()
            or data.get("seal_contract_version") != "transfer-seal-qr-v1"
            or data.get("seal_state") != "ACTIVE"
            or not str(data.get("seal_id") or "").strip()
            or data.get("seal_revision") != 1
            or not str(data.get("seal_token") or "").strip()
            or data.get("sealed_bundle_id") != payload["transfer_bundle_id"]
            or data.get("sealed_bundle_version") != 1
            or sorted(str(value) for value in data.get("sealed_member_ids") or [])
            != sorted(payload["member_ids"])
            or len(actual_member_pairs) != len(payload["member_ids"])
            or sealed_member_pairs != actual_member_pairs
            or len({unit_id for unit_id, _barcode in sealed_member_pairs})
            != len(sealed_member_pairs)
            or len({barcode for _unit_id, barcode in sealed_member_pairs})
            != len(sealed_member_pairs)
            or data.get("sealed_member_count") != len(payload["member_ids"])
            or data.get("sealed_membership_hash") != payload["membership_hash"]
            or sorted(
                normalize_barcode(value)
                for value in data.get("sealed_normalized_barcodes") or []
            )
            != expected_barcodes
            or data.get("sealed_barcode_membership_hash")
            != membership_hash(expected_barcodes)
            or seal_fields.get("TRF") != "1"
            or seal_fields.get("BND") != payload["transfer_bundle_id"]
            or seal_fields.get("AUTH_SCOPE") != context["authority_scope_id"]
            or seal_fields.get("CLC") != payload["item_id"]
            or seal_fields.get("QT") != str(len(payload["member_ids"]))
            or seal_fields.get("HSH") != payload["membership_hash"]
            or seal_fields.get("EPOCH") != str(context["authority_epoch"])
            or seal_fields.get("PLANE") != context["ledger_plane"]
            or seal_fields.get("PE") != str(context["plane_epoch"])
            or seal_fields.get("SID") != data.get("seal_id")
            or seal_fields.get("SREV") != str(data.get("seal_revision"))
            or seal_fields.get("STK") != data.get("seal_token")
        ):
            raise TransferSealError(
                "RECEIPT_MEMBERSHIP_MISMATCH",
                "서버 receipt의 이적 membership이 전송한 명령과 일치하지 않습니다.",
            )
        expected_remainder = str(payload.get("remainder_bundle_id") or "")
        if str(data.get("remainder_bundle_id") or "") != expected_remainder:
            raise TransferSealError(
                "RECEIPT_MEMBERSHIP_MISMATCH", "서버 receipt의 잔여 bundle이 명령과 일치하지 않습니다."
            )
        return data

    def attempt(self, intent_id: str) -> SealAttempt:
        row = self.store.load(intent_id)
        if row["status"] == "ACKED":
            return self._attempt_from_row(row)
        if row["status"] == "OPERATOR_REVIEW":
            return self._attempt_from_row(row)
        try:
            if row["command_json"] is None:
                context = self._build_command(row)
                row = self.store.bind_command(intent_id, context)
            context = json.loads(row["command_json"])
            if self.client is None:
                raise TransferSealError(
                    "LOGISTICS_CLIENT_NOT_CONFIGURED",
                    "물류 서버 설정이 없어 이적 seal을 보류했습니다.",
                    retryable=True,
                )
            receipt = self.client.seal_transfer(context)
            data = self._validate_receipt(context, receipt)
            qr_payload = self._seal_qr(context, data)
            row = self.store.record_receipt(intent_id, receipt, qr_payload)
        except TransferSealError as exc:
            row = self.store.record_error(intent_id, exc)
        except Exception as exc:
            row = self.store.record_error(
                intent_id,
                TransferSealError(
                    "LOCAL_TRANSFER_SEAL_ERROR",
                    f"이적 seal 처리 중 로컬 오류가 발생했습니다: {exc.__class__.__name__}",
                    retryable=True,
                ),
            )
        return self._attempt_from_row(row)

    def drain_pending(self) -> list[SealAttempt]:
        return [self.attempt(intent_id) for intent_id in self.store.pending_ids()]

    @staticmethod
    def _attempt_from_row(row: sqlite3.Row) -> SealAttempt:
        context = json.loads(row["command_json"]) if row["command_json"] else {}
        payload = context.get("payload") if isinstance(context.get("payload"), dict) else {}
        receipt = json.loads(row["receipt_json"]) if row["receipt_json"] else {}
        receipt_data = TransferSealCoordinator._result_data(receipt) if receipt else {}
        raw_versions = receipt.get("entity_versions") or receipt_data.get("entity_versions") or {}
        entity_versions = {
            str(key): int(value)
            for key, value in raw_versions.items()
            if isinstance(value, int) and not isinstance(value, bool)
        } if isinstance(raw_versions, Mapping) else {}
        source_bundle_id = str(payload.get("source_bundle_id") or "")
        if not source_bundle_id:
            source_bundles = payload.get("source_bundles")
            if (
                isinstance(source_bundles, list)
                and len(source_bundles) == 1
                and isinstance(source_bundles[0], Mapping)
            ):
                source_bundle_id = str(
                    source_bundles[0].get("bundle_id") or ""
                )
        remainder_bundle_id = str(
            payload.get("remainder_bundle_id") or ""
        )
        if not remainder_bundle_id:
            receipt_remainders = receipt_data.get("remainder_bundle_ids")
            if (
                isinstance(receipt_remainders, list)
                and len(receipt_remainders) == 1
            ):
                remainder_bundle_id = str(
                    receipt_remainders[0] or ""
                )
        return SealAttempt(
            intent_id=str(row["intent_id"]),
            status=str(row["status"]),
            command_id=str(row["command_id"] or ""),
            transfer_bundle_id=str(payload.get("transfer_bundle_id") or ""),
            seal_qr_payload=str(row["seal_qr_payload"] or ""),
            member_count=len(payload.get("member_ids") or []),
            membership_hash=str(payload.get("membership_hash") or ""),
            receipt_id=str(receipt.get("receipt_id") or ""),
            source_bundle_id=source_bundle_id,
            remainder_bundle_id=remainder_bundle_id,
            authority_scope_id=str(context.get("authority_scope_id") or ""),
            authority_epoch=int(context.get("authority_epoch") or 0),
            ledger_plane=str(context.get("ledger_plane") or ""),
            plane_epoch=int(context.get("plane_epoch") or 0),
            item_id=str(receipt_data.get("item_id") or payload.get("item_id") or ""),
            inbound_iin=str(receipt_data.get("inbound_iin") or ""),
            uom=str(receipt_data.get("uom") or ""),
            entity_versions=entity_versions,
            retryable=row["status"] == "RETRY_WAIT",
            error_code=str(row["last_error_code"] or ""),
            error_message=str(row["last_error_message"] or ""),
        )


def logistics_transfer_client_from_env(
    *,
    session: Any = None,
    probe_required: bool = True,
    environ: Mapping[str, str] | None = None,
    profile_decryptor: Any = None,
) -> LogisticsTransferClient | None:
    values = os.environ if environ is None else environ
    required = logistics_runtime_required(environ)
    profile = load_logistics_runtime_profile(
        required,
        environ=environ,
        decryptor=profile_decryptor,
    )
    if profile is not None:
        client = LogisticsTransferClient(
            profile.base_url,
            profile.bearer_token,
            profile.source_host_id,
            device_id=profile.device_id,
            timeout_seconds=profile.timeout_seconds,
            session=session,
            authority_scope_id=profile.authority_scope,
            authority_epoch=profile.authority_epoch,
            authority_plane=profile.authority_plane,
            ledger_plane=profile.ledger_plane,
            plane_epoch=profile.plane_epoch,
            authoritative_required=required,
        )
    else:
        legacy_fields = {
            "base_url": str(
                values.get("WORKER_ANALYSIS_LOGISTICS_API_BASE_URL")
                or values.get("WORKER_ANALYSIS_SERVER_URL")
                or ""
            ).strip(),
            "token": str(values.get("WORKER_ANALYSIS_LOGISTICS_API_TOKEN") or "").strip(),
            "source_host_id": str(
                values.get("WORKER_ANALYSIS_LOGISTICS_SOURCE_HOST_ID")
                or values.get("COMPUTERNAME")
                or ""
            ).strip(),
        }
        explicitly_configured = bool(
            legacy_fields["base_url"] or legacy_fields["token"]
        )
        if not explicitly_configured:
            return None
        if not all(legacy_fields.values()):
            raise LogisticsRuntimeConfigurationError(
                "legacy Container logistics environment profile is incomplete"
            )
        try:
            timeout = float(values.get("WORKER_ANALYSIS_LOGISTICS_TIMEOUT_SECONDS", "10"))
            client = LogisticsTransferClient(
                legacy_fields["base_url"],
                legacy_fields["token"],
                legacy_fields["source_host_id"],
                device_id=values.get(
                    "WORKER_ANALYSIS_LOGISTICS_DEVICE_ID",
                    legacy_fields["source_host_id"],
                ),
                timeout_seconds=timeout,
                session=session,
            )
        except (TypeError, ValueError) as exc:
            raise LogisticsRuntimeConfigurationError(
                "legacy Container logistics environment profile is invalid"
            ) from exc
    if required and probe_required:
        try:
            capabilities = client.get_capabilities()
            capability = (capabilities.get("capabilities") or {}).get(
                "bundle_member_replacement_v1"
            )
            if (
                "bundle_member_replacement_v1"
                not in (capabilities.get("capability_ids") or [])
                or not isinstance(capability, Mapping)
                or capability.get("enabled") is not True
                or capability.get("command_type") != "REPLACE_BUNDLE_MEMBERS"
                or capability.get("resolver_contract_version")
                != "logistics-good-replacement-source-v1"
                or capability.get("resolver_path")
                != "/logistics/api/v1/replacements/good-source/resolve"
                or capability.get("max_pairs") != 2
                or capability.get("atomic") is not True
                or capability.get("two_bundle_cas") is not True
                or capability.get("sealed_transfer_package") is not False
                or capability.get("replacement_source_bundle_cardinality")
                != "EXACTLY_ONE_ACTIVE_MEMBER"
                or capability.get("multi_member_source_policy")
                != "REJECT_STALE_PHYSICAL_LABEL"
                or capability.get("multi_member_source_error_code")
                != "REPLACEMENT_SOURCE_NOT_SINGLETON"
                or capability.get("target_label_action") != "RETAIN_IDENTITY_LABEL"
                or capability.get("target_label_identity_remains_valid") is not True
                or capability.get("target_label_membership_bound") is not False
            ):
                raise LogisticsRuntimeConfigurationError(
                    "authoritative logistics capability readiness is incomplete"
                )
        except LogisticsRuntimeConfigurationError:
            raise
        except TransferSealError as exc:
            raise LogisticsRuntimeConfigurationError(
                f"authoritative logistics readiness failed: {exc.code}"
            ) from exc
        except Exception as exc:
            raise LogisticsRuntimeConfigurationError(
                f"authoritative logistics readiness failed: {exc.__class__.__name__}"
            ) from exc
    return client


def transfer_seal_coordinator_from_env(
    db_path: str | os.PathLike[str],
    *,
    session: Any = None,
    probe_required: bool = True,
    profile_decryptor: Any = None,
) -> TransferSealCoordinator:
    store = TransferSealStore(db_path)
    client = logistics_transfer_client_from_env(
        session=session,
        probe_required=probe_required,
        profile_decryptor=profile_decryptor,
    )
    return TransferSealCoordinator(store, client)


__all__ = [
    "LogisticsTransferClient",
    "SealAttempt",
    "TransferSourcePreflight",
    "TransferSealCoordinator",
    "TransferSealError",
    "TransferSealStore",
    "membership_hash",
    "logistics_transfer_client_from_env",
    "normalize_barcode",
    "source_identity_from_label",
    "transfer_seal_coordinator_from_env",
    "validate_compact_phs2_fields",
    "validate_compact_phs2_preflight",
]
