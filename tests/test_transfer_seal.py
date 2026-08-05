import csv
import hashlib
import json
import sqlite3
from urllib.parse import parse_qs, urlsplit

import pytest

from Container_Audit import ContainerAudit
from transfer_seal import (
    LogisticsTransferClient,
    TransferSealCoordinator,
    TransferSealError,
    TransferSealStore,
    _deterministic_id,
    _sha256,
    membership_hash,
    source_identity_from_label,
    validate_compact_phs2_fields,
    validate_compact_phs2_preflight,
)


SCOPE = "PLANT-01"
ITEM = "AAA2270730100"
SOURCE = "PHS-SERVER-001"
PHS2_LABEL_HASH = "a" * 64
PHS2_CORE_HASH = "b" * 64
PHS2_HASH_PREFIX = PHS2_LABEL_HASH[:16]
SOURCE_PHS2_LABEL_HASH = "c" * 64
SOURCE_PHS2_CORE_HASH = "d" * 64
SOURCE_PHS2_HASH_PREFIX = SOURCE_PHS2_LABEL_HASH[:16]
ACTIVE_PHS2_HASH_PREFIX = "e" * 16


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class FakeSession:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, **kwargs):
        call = {"method": method, "url": url, **kwargs}
        self.calls.append(call)
        return self.handler(call)


def _bundle(barcodes=("BC-1", "BC-2", "BC-3")):
    members = [
        {"unit_id": f"unit-{index}", "normalized_barcode": barcode}
        for index, barcode in enumerate(barcodes, start=1)
    ]
    member_ids = [member["unit_id"] for member in members]
    normalized_barcodes = sorted(member["normalized_barcode"] for member in members)
    return {
        "authority_scope_id": SCOPE,
        "authority_epoch": 7,
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 3,
        "bundle_id": SOURCE,
        "bundle_role": "TRANSFER_SOURCE",
        "bundle_type": "PHS",
        "bundle_state": "AVAILABLE",
        "external_label": "WORK-001",
        "source_session_id": "ITAG-001",
        "item_id": ITEM,
        "uom": "EA",
        "source_iin": "IIN-001",
        "current_location": "PHS_GOOD",
        "member_ids": member_ids,
        "member_count": len(member_ids),
        "membership_hash": membership_hash(member_ids),
        "barcode_member_count": len(normalized_barcodes),
        "barcode_membership_hash": membership_hash(normalized_barcodes),
        "entity_version": 4,
        "entity_versions": {f"bundle:{SOURCE}": 4},
        "members": members,
    }


def _resolved_bundle(barcodes=("BC-1", "BC-2", "BC-3")):
    return {"candidate_count": 1, "bundle": _bundle(barcodes)}


def _compact_phs2_fields(**overrides):
    fields = {
        "PHS": "2",
        "SRC": "KMTECH_INPUT_TAG",
        "ITG": "ITAG-001",
        "CLC": ITEM,
        "LBL": "INPUT-LABEL-001",
        "HSH": PHS2_HASH_PREFIX,
    }
    fields.update(overrides)
    return fields


def _compact_phs2_qr(**overrides):
    fields = _compact_phs2_fields(**overrides)
    return "|".join(
        f"{key}={fields[key]}" for key in ("PHS", "SRC", "ITG", "CLC", "LBL", "HSH")
    )


def _resolved_compact_phs2(count=15):
    members = [
        {
            "unit_id": f"unit-{index:03d}",
            "normalized_barcode": f"{ITEM}-SERIAL-{index:03d}",
            "inbound_iin": f"ORIGIN-IIN-{index % 2}",
            "current_inbound_iin": "IIN-001",
            "item_id": ITEM,
            "uom": "EA",
            "unit_state": "AVAILABLE",
            "location_code": "PHS_GOOD",
        }
        for index in range(1, count + 1)
    ]
    member_ids = [member["unit_id"] for member in members]
    barcodes = [member["normalized_barcode"] for member in members]
    bundle = {
        "authority_scope_id": SCOPE,
        "authority_epoch": 7,
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 3,
        "bundle_id": SOURCE,
        "bundle_role": "TRANSFER_SOURCE",
        "bundle_type": "PHS",
        "bundle_state": "AVAILABLE",
        "external_label": _compact_phs2_qr(),
        "source_session_id": "ITAG-001",
        "item_id": ITEM,
        "uom": "EA",
        "source_iin": "IIN-001",
        "source_iins": ["ORIGIN-IIN-0", "ORIGIN-IIN-1"],
        "origin_inbound_iins": ["ORIGIN-IIN-0", "ORIGIN-IIN-1"],
        "current_location": "PHS_GOOD",
        "current_locations": ["PHS_GOOD"],
        "member_ids": member_ids,
        "member_count": count,
        "membership_hash": membership_hash(member_ids),
        "barcode_member_count": count,
        "barcode_membership_hash": membership_hash(barcodes),
        "entity_version": 4,
        "entity_versions": {f"bundle:{SOURCE}": 4},
        "members": members,
    }
    return {
        "candidate_count": 1,
        "bundle": bundle,
        "input_tag": {
            "input_tag_id": "ITAG-001",
            "label_id": "INPUT-LABEL-001",
            "item_id": ITEM,
            "tag_core_hash": PHS2_CORE_HASH,
            "label_instance_hash": PHS2_LABEL_HASH,
            "hash_prefix": PHS2_HASH_PREFIX,
            "lifecycle": "INSPECTION_COMPLETED",
            "qr_payload": _compact_phs2_qr(),
        },
    }


def _resolved_non_anchor_compact_phs2(count=3):
    resolved = json.loads(json.dumps(_resolved_compact_phs2(count=count)))
    source_qr = _compact_phs2_qr(
        ITG="ITAG-002",
        LBL="INPUT-LABEL-002",
        HSH=SOURCE_PHS2_HASH_PREFIX,
    )
    active_qr = _compact_phs2_qr(
        LBL="WORK-LABEL-002",
        HSH=ACTIVE_PHS2_HASH_PREFIX,
    )
    bundle = resolved["bundle"]
    bundle["source_session_id"] = "ITAG-002"
    bundle["external_label"] = source_qr
    active_label = {
        "group_id": "PHSG-WORK-002",
        "label_id": "WORK-LABEL-002",
        "qr_payload": active_qr,
        "hash_prefix": ACTIVE_PHS2_HASH_PREFIX,
        "scan_anchor_input_tag_id": "ITAG-001",
        "item_id": ITEM,
        "state": "ACTIVE",
        "member_ids": list(bundle["member_ids"]),
        "member_count": bundle["member_count"],
        "membership_hash": bundle["membership_hash"],
        "membership_version": 3,
        "label_version": 2,
        "entity_version": 2,
        "business_date": "2026-07-30",
        "worker_code": "2270730100-002",
    }
    resolved.update(
        {
            "source_resolution_basis": "PHS_WORK_GROUP_EXACT_MEMBERSHIP",
            "source_input_tag": {
                "input_tag_id": "ITAG-002",
                "label_id": "INPUT-LABEL-002",
                "item_id": ITEM,
                "uom": "EA",
                "tag_core_hash": SOURCE_PHS2_CORE_HASH,
                "label_instance_hash": SOURCE_PHS2_LABEL_HASH,
                "hash_prefix": SOURCE_PHS2_HASH_PREFIX,
                "lifecycle": "INSPECTION_COMPLETED",
                "qr_payload": source_qr,
                "session_id": "ITAG-002",
                "member_count": bundle["member_count"],
                "membership_hash": bundle["membership_hash"],
            },
            "phs_work_group": dict(active_label),
            "phs_label_resolution": {
                "status": "ACTIVE",
                "resolution": "OVERLAY_ACTIVE",
                "authority_scope_id": SCOPE,
                "ledger_plane": "AUTHORITATIVE",
                "plane_epoch": 3,
                "scanned_label": dict(active_label),
                "effective_labels": [dict(active_label)],
            },
        }
    )
    return resolved


def _completed_input_tag(
    *,
    input_tag_id,
    label_id,
    label_hash,
    core_hash,
    member_ids,
):
    qr = _compact_phs2_qr(
        ITG=input_tag_id,
        LBL=label_id,
        HSH=label_hash[:16],
    )
    return {
        "input_tag_id": input_tag_id,
        "label_id": label_id,
        "item_id": ITEM,
        "uom": "EA",
        "tag_core_hash": core_hash,
        "label_instance_hash": label_hash,
        "hash_prefix": label_hash[:16],
        "lifecycle": "INSPECTION_COMPLETED",
        "qr_payload": qr,
        "session_id": input_tag_id,
        "session_state": "COMPLETED",
        "entity_version": 4,
        "member_count": len(member_ids),
        "membership_hash": membership_hash(member_ids),
    }


def _resolved_work_group_phs2(*, mode="merge"):
    if mode not in {"merge", "split"}:
        raise ValueError(mode)
    rows = [
        {
            "unit_id": f"unit-{index:03d}",
            "normalized_barcode": f"{ITEM}-SERIAL-{index:03d}",
            "inbound_iin": f"ORIGIN-IIN-{index}",
            "current_inbound_iin": "IIN-001",
            "item_id": ITEM,
            "uom": "EA",
            "unit_state": "AVAILABLE",
            "location_code": "PHS_GOOD",
        }
        for index in range(1, 5)
    ]
    all_ids = [row["unit_id"] for row in rows]
    source_tags = [
        _completed_input_tag(
            input_tag_id="ITAG-001",
            label_id="INPUT-LABEL-001",
            label_hash=PHS2_LABEL_HASH,
            core_hash=PHS2_CORE_HASH,
            member_ids=all_ids if mode == "split" else all_ids[:2],
        )
    ]
    source_specs = []
    if mode == "merge":
        source_tags.append(
            _completed_input_tag(
                input_tag_id="ITAG-002",
                label_id="INPUT-LABEL-002",
                label_hash=SOURCE_PHS2_LABEL_HASH,
                core_hash=SOURCE_PHS2_CORE_HASH,
                member_ids=all_ids[2:],
            )
        )
        partitions = [
            (
                SOURCE,
                "ITAG-001",
                source_tags[0]["qr_payload"],
                all_ids[:2],
                all_ids[:2],
                [],
                4,
            ),
            (
                "PHS-SERVER-002",
                "ITAG-002",
                source_tags[1]["qr_payload"],
                all_ids[2:],
                all_ids[2:],
                [],
                6,
            ),
        ]
        group_ids = all_ids
        cover_groups = []
    else:
        remainder_ids = all_ids[2:]
        remainder_bundle_id = (
            "PHS-WORK-REMAINDER-"
            + _sha256(
                {
                    "source_bundle_id": SOURCE,
                    "member_ids": remainder_ids,
                }
            )[:24].upper()
        )
        partitions = [
            (
                SOURCE,
                "ITAG-001",
                source_tags[0]["qr_payload"],
                all_ids,
                all_ids[:2],
                remainder_ids,
                4,
            ),
        ]
        group_ids = all_ids[:2]
        cover_qr = _compact_phs2_qr(
            LBL="WORK-LABEL-COVER",
            HSH="f" * 16,
        )
        cover_groups = [
            {
                "group_id": "PHSG-WORK-COVER",
                "label_id": "WORK-LABEL-COVER",
                "scan_payload": cover_qr,
                "scan_anchor_input_tag_id": "ITAG-001",
                "item_id": ITEM,
                "uom": "EA",
                "member_ids": remainder_ids,
                "member_count": len(remainder_ids),
                "membership_hash": membership_hash(remainder_ids),
                "covered_member_ids": remainder_ids,
                "covered_member_count": len(remainder_ids),
                "covered_membership_hash": membership_hash(remainder_ids),
                "membership_version": 5,
                "label_version": 3,
                "group_entity_version": 7,
                "label_entity_version": 4,
            }
        ]
        assert remainder_bundle_id
    for (
        source_id,
        source_session_id,
        external_label,
        full,
        selected,
        remainder,
        version,
    ) in partitions:
        remainder_bundle_id = (
            "PHS-WORK-REMAINDER-"
            + _sha256(
                {
                    "source_bundle_id": source_id,
                    "member_ids": remainder,
                }
            )[:24].upper()
            if remainder
            else None
        )
        source_specs.append(
            {
                "bundle_id": source_id,
                "bundle_type": "PHS",
                "bundle_state": "AVAILABLE",
                "entity_version": version,
                "source_session_id": source_session_id,
                "external_label": external_label,
                "accounting_inbound_iin": "IIN-001",
                "source_member_ids": list(full),
                "source_member_count": len(full),
                "source_membership_hash": membership_hash(full),
                "selected_member_ids": list(selected),
                "selected_member_count": len(selected),
                "selected_membership_hash": membership_hash(selected),
                "remainder_member_ids": list(remainder),
                "remainder_member_count": len(remainder),
                "remainder_membership_hash": (
                    membership_hash(remainder) if remainder else None
                ),
                "remainder_bundle_id": remainder_bundle_id,
                "remainder_external_label": (
                    f"WORK-REMAINDER::{remainder_bundle_id}"
                    if remainder_bundle_id
                    else None
                ),
                "remainder_cover_group_ids": (
                    ["PHSG-WORK-COVER"] if remainder else []
                ),
            }
        )
    active_qr = _compact_phs2_qr(
        LBL="WORK-LABEL-002",
        HSH=ACTIVE_PHS2_HASH_PREFIX,
    )
    group = {
        "group_id": "PHSG-WORK-002",
        "label_id": "WORK-LABEL-002",
        "state": "ACTIVE",
        "scan_payload": active_qr,
        "scan_anchor_input_tag_id": "ITAG-001",
        "item_id": ITEM,
        "uom": "EA",
        "member_ids": list(group_ids),
        "member_count": len(group_ids),
        "membership_hash": membership_hash(group_ids),
        "membership_version": 3,
        "label_version": 2,
        "group_entity_version": 5,
        "label_entity_version": 2,
    }
    active_label = {
        **group,
        "qr_payload": group["scan_payload"],
        "hash_prefix": ACTIVE_PHS2_HASH_PREFIX,
        "entity_version": group["label_entity_version"],
        "business_date": "2026-07-30",
        "worker_code": "2270730100-002",
    }
    transfer_id = _deterministic_id(
        "TRANSFER",
        {
            "group_id": group["group_id"],
            "label_id": group["label_id"],
            "member_ids": list(group_ids),
        },
    )
    versions = {
        f"phs_work_group:{group['group_id']}": group[
            "group_entity_version"
        ],
        f"phs_work_membership:{group['group_id']}": group[
            "membership_version"
        ],
        f"phs_work_label_version:{group['group_id']}": group[
            "label_version"
        ],
        f"phs_label:{group['label_id']}": group[
            "label_entity_version"
        ],
        **{
            f"bundle:{source['bundle_id']}": source["entity_version"]
            for source in source_specs
        },
        f"bundle:{transfer_id}": 0,
    }
    for cover in cover_groups:
        versions.update(
            {
                f"phs_work_group:{cover['group_id']}": cover[
                    "group_entity_version"
                ],
                f"phs_work_membership:{cover['group_id']}": cover[
                    "membership_version"
                ],
                f"phs_work_label_version:{cover['group_id']}": cover[
                    "label_version"
                ],
                f"phs_label:{cover['label_id']}": cover[
                    "label_entity_version"
                ],
            }
        )
    selected_rows = [
        row for row in rows if row["unit_id"] in set(group_ids)
    ]
    barcodes = [row["normalized_barcode"] for row in selected_rows]
    work_source = {
        "authority_scope_id": SCOPE,
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 3,
        "item_id": ITEM,
        "uom": "EA",
        "source_iin": "IIN-001",
        "member_ids": list(group_ids),
        "member_count": len(group_ids),
        "membership_hash": membership_hash(group_ids),
        "barcode_member_count": len(barcodes),
        "barcode_membership_hash": membership_hash(barcodes),
        "members": selected_rows,
        "source_bundles": source_specs,
        "source_bundle_count": len(source_specs),
        "source_bundle_ids": [
            source["bundle_id"] for source in source_specs
        ],
        "source_session_ids": sorted(
            {source["source_session_id"] for source in source_specs}
        ),
        "transfer_bundle_id": transfer_id,
        "transfer_external_label": transfer_id,
        "remainder_cover_groups": cover_groups,
        "entity_versions": versions,
    }
    topology_hash = _sha256(
        {
            "phs_work_group": group,
            "source_bundles": source_specs,
            "remainder_cover_groups": cover_groups,
            "source_iin": "IIN-001",
            "barcode_membership_hash": membership_hash(barcodes),
            "transfer_bundle_id": transfer_id,
        }
    )
    work_source["topology_hash"] = topology_hash
    return {
        "candidate_count": 1,
        "source_resolution_basis": "PHS_WORK_GROUP_EXACT_MEMBERSHIP",
        "authority_scope_id": SCOPE,
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 3,
        "input_tag": source_tags[0],
        "source_input_tags": source_tags,
        "phs_label_resolution": {
            "status": "ACTIVE",
            "resolution": "OVERLAY_ACTIVE",
            "authority_scope_id": SCOPE,
            "ledger_plane": "AUTHORITATIVE",
            "plane_epoch": 3,
            "scanned_label": dict(active_label),
            "effective_labels": [dict(active_label)],
        },
        "phs_work_group": group,
        "work_group_source": work_source,
        "topology_hash": topology_hash,
        "entity_versions": versions,
    }


def _work_group_receipt(context):
    payload = context["payload"]
    receipt_id = "receipt-work-group-seal-1"
    source_specs = payload["source_bundles"]
    source_ids = [source["bundle_id"] for source in source_specs]
    source_sessions = sorted(
        {source["source_session_id"] for source in source_specs}
    )
    evidence = context["client_exact_evidence"]
    pairs = list(evidence["member_barcode_pairs"])
    normalized_barcodes = sorted(
        value.upper() for value in payload["scanned_barcodes"]
    )
    source_transitions = []
    remainders = []
    remainder_by_source = {}
    for source in source_specs:
        remainder_id = source.get("remainder_bundle_id")
        if remainder_id:
            remainder_by_source[source["bundle_id"]] = remainder_id
            remainders.append(
                {
                    "source_bundle_id": source["bundle_id"],
                    "remainder_bundle_id": remainder_id,
                    "remainder_external_label": (
                        f"WORK-REMAINDER::{remainder_id}"
                    ),
                    "remainder_external_label_kind": (
                        "INTERNAL_LOGISTICS_ALIAS_NOT_PHYSICAL"
                    ),
                    "member_ids": source["remainder_member_ids"],
                    "member_count": source["remainder_member_count"],
                    "membership_hash": source[
                        "remainder_membership_hash"
                    ],
                }
            )
        source_transitions.append(
            {
                "source_bundle_id": source["bundle_id"],
                "entity_version_before": source["entity_version"],
                "entity_version_after": source["entity_version"] + 1,
                "state_before": "AVAILABLE",
                "state_after": "CONSUMED",
                "source_member_ids": source["source_member_ids"],
                "source_member_count": source["source_member_count"],
                "source_membership_hash": source[
                    "source_membership_hash"
                ],
                "selected_member_ids": source["selected_member_ids"],
                "selected_member_count": source[
                    "selected_member_count"
                ],
                "selected_membership_hash": source[
                    "selected_membership_hash"
                ],
                "remainder_bundle_id": remainder_id,
            }
        )
    root_specs = {
        (
            payload["phs_work_group"]["group_id"],
            "TRANSFER_BUNDLE",
            payload["transfer_bundle_id"],
        )
    }
    for source in source_specs:
        remainder_id = remainder_by_source.get(source["bundle_id"])
        if not remainder_id:
            continue
        for cover_group_id in source["remainder_cover_group_ids"]:
            root_specs.add(
                (cover_group_id, "PHS_BUNDLE", remainder_id)
            )
    root_proof = [
        {
            "group_id": group_id,
            "root_type": root_type,
            "root_id": root_id,
            "root_role": "SOURCE",
            "added_receipt_id": receipt_id,
        }
        for group_id, root_type, root_id in sorted(root_specs)
    ]
    group_versions_after = {
        payload["phs_work_group"]["group_id"]: payload[
            "phs_work_group"
        ]["group_entity_version"]
        + 1,
        **{
            cover["group_id"]: cover["group_entity_version"] + 1
            for cover in payload["remainder_cover_groups"]
        },
    }
    versions = {}
    for key, value in context["expected_versions"].items():
        if key in {f"bundle:{source_id}" for source_id in source_ids}:
            versions[key] = value + 1
        elif key == f"bundle:{payload['transfer_bundle_id']}":
            versions[key] = 1
        elif key.startswith("phs_work_group:"):
            versions[key] = value + 1
        else:
            versions[key] = value
    for remainder in remainders:
        versions[f"bundle:{remainder['remainder_bundle_id']}"] = 1
    seal_id = "transfer-seal-work-group-1"
    seal_token = "transfer-seal-work-group-token-1"
    seal_qr_payload = "|".join(
        (
            "TRF=1",
            f"BND={payload['transfer_bundle_id']}",
            f"AUTH_SCOPE={context['authority_scope_id']}",
            f"CLC={payload['item_id']}",
            f"QT={len(payload['member_ids'])}",
            f"HSH={payload['membership_hash']}",
            f"EPOCH={context['authority_epoch']}",
            f"PLANE={context['ledger_plane']}",
            f"PE={context['plane_epoch']}",
            f"SID={seal_id}",
            "SREV=1",
            f"STK={seal_token}",
        )
    )
    remainder_ids = [
        remainder["remainder_bundle_id"] for remainder in remainders
    ]
    topology_hash_after = _sha256(
        {
            "topology_hash_before": payload["topology_hash"],
            "transfer_bundle_id": payload["transfer_bundle_id"],
            "remainder_bundle_ids": remainder_ids,
            "root_proof": root_proof,
            "group_entity_versions": group_versions_after,
        }
    )
    data = {
        "source_bundle_id": (
            source_ids[0] if len(source_ids) == 1 else None
        ),
        "source_bundle_ids": source_ids,
        "source_bundle_count": len(source_ids),
        "source_session_ids": source_sessions,
        "scan_anchor_input_tag_id": payload["phs_work_group"][
            "scan_anchor_input_tag_id"
        ],
        "transfer_bundle_id": payload["transfer_bundle_id"],
        "transfer_external_label": payload["external_label"],
        "member_ids": payload["member_ids"],
        "members": pairs,
        "member_count": len(payload["member_ids"]),
        "membership_hash": payload["membership_hash"],
        "scanned_barcodes": normalized_barcodes,
        "scanned_barcode_count": len(normalized_barcodes),
        "scanned_barcode_hash": membership_hash(normalized_barcodes),
        "inbound_iin": "IIN-001",
        "origin_inbound_iins": ["ORIGIN-IIN-1", "ORIGIN-IIN-2"],
        "item_id": payload["item_id"],
        "uom": payload["uom"],
        "movement_id": "movement-work-group-1",
        "source_transitions": source_transitions,
        "remainder_bundles": remainders,
        "remainder_bundle_ids": remainder_ids,
        "post_seal_exchange_policy": (
            "BLOCKED_REQUIRES_TWO_BUNDLE_CAS"
        ),
        "atomic": True,
        "receipt_contract_version": "PHS_WORK_GROUP_TRANSFER_V1",
        "source_resolution_basis": (
            "PHS_WORK_GROUP_EXACT_MEMBERSHIP"
        ),
        "phs_work_group": payload["phs_work_group"],
        "remainder_cover_groups": payload["remainder_cover_groups"],
        "source_bundles": payload["source_bundles"],
        "topology_hash_before": payload["topology_hash"],
        "topology_hash_after": topology_hash_after,
        "root_proof": root_proof,
        "group_entity_versions_after": group_versions_after,
        "seal_contract_version": "transfer-seal-qr-v1",
        "seal_state": "ACTIVE",
        "seal_id": seal_id,
        "seal_revision": 1,
        "seal_token": seal_token,
        "seal_qr_payload": seal_qr_payload,
        "sealed_bundle_id": payload["transfer_bundle_id"],
        "sealed_bundle_version": 1,
        "sealed_member_ids": payload["member_ids"],
        "sealed_members": pairs,
        "sealed_member_count": len(payload["member_ids"]),
        "sealed_membership_hash": payload["membership_hash"],
        "sealed_normalized_barcodes": normalized_barcodes,
        "sealed_barcode_membership_hash": membership_hash(
            normalized_barcodes
        ),
    }
    return {
        "receipt_id": receipt_id,
        "contract_version": "logistics-v1",
        "command_type": "SEAL_TRANSFER_BUNDLE",
        "status": "COMMITTED",
        "authority_scope_id": context["authority_scope_id"],
        "authority_epoch": context["authority_epoch"],
        "resolved_ledger_plane": context["ledger_plane"],
        "resolved_plane_epoch": context["plane_epoch"],
        "committed_at": "2026-07-30T00:00:00Z",
        "event_ids": ["event-work-group-1"],
        "outbox_ids": ["outbox-work-group-1"],
        "entity_versions": versions,
        "data": data,
    }


def _fields_from_compact_qr(qr_payload):
    return {
        segment.split("=", 1)[0]: segment.split("=", 1)[1]
        for segment in qr_payload.split("|")
    }


def _receipt(context):
    payload = context["payload"]
    normalized_barcodes = sorted(value.upper() for value in payload["scanned_barcodes"])
    remainder_ids = list(context["client_exact_evidence"]["remainder_member_ids"])
    seal_id = "transfer-seal-1"
    seal_token = "transfer-seal-token-1"
    seal_qr_payload = "|".join(
        (
            "TRF=1",
            f"BND={payload['transfer_bundle_id']}",
            f"AUTH_SCOPE={context['authority_scope_id']}",
            f"CLC={payload['item_id']}",
            f"QT={len(payload['member_ids'])}",
            f"HSH={payload['membership_hash']}",
            f"EPOCH={context['authority_epoch']}",
            f"PLANE={context['ledger_plane']}",
            f"PE={context['plane_epoch']}",
            f"SID={seal_id}",
            "SREV=1",
            f"STK={seal_token}",
        )
    )
    data = {
        "source_bundle_id": payload["source_bundle_id"],
        "transfer_bundle_id": payload["transfer_bundle_id"],
        "item_id": payload["item_id"],
        "member_ids": payload["member_ids"],
        "members": [
            {"unit_id": unit_id, "normalized_barcode": barcode}
            for unit_id, barcode in zip(
                payload["member_ids"], normalized_barcodes, strict=True
            )
        ],
        "member_count": len(payload["member_ids"]),
        "membership_hash": payload["membership_hash"],
        "scanned_barcodes": normalized_barcodes,
        "scanned_barcode_count": len(normalized_barcodes),
        "scanned_barcode_hash": membership_hash(normalized_barcodes),
        "inbound_iin": "IIN-001",
        "uom": "EA",
        "remainder_bundle_id": payload.get("remainder_bundle_id"),
        "remainder_member_ids": remainder_ids,
        "remainder_member_count": len(remainder_ids),
        "remainder_membership_hash": membership_hash(remainder_ids) if remainder_ids else None,
        "post_seal_exchange_policy": "BLOCKED_REQUIRES_TWO_BUNDLE_CAS",
        "seal_contract_version": "transfer-seal-qr-v1",
        "seal_state": "ACTIVE",
        "seal_id": seal_id,
        "seal_revision": 1,
        "seal_token": seal_token,
        "seal_qr_payload": seal_qr_payload,
        "sealed_bundle_id": payload["transfer_bundle_id"],
        "sealed_bundle_version": 1,
        "sealed_member_ids": payload["member_ids"],
        "sealed_members": [
            {"unit_id": unit_id, "normalized_barcode": barcode}
            for unit_id, barcode in zip(
                payload["member_ids"], normalized_barcodes, strict=True
            )
        ],
        "sealed_member_count": len(payload["member_ids"]),
        "sealed_membership_hash": payload["membership_hash"],
        "sealed_normalized_barcodes": normalized_barcodes,
        "sealed_barcode_membership_hash": membership_hash(normalized_barcodes),
        "entity_versions": {
            f"bundle:{payload['source_bundle_id']}": 5,
            f"bundle:{payload['transfer_bundle_id']}": 1,
        },
    }
    if payload.get("remainder_bundle_id"):
        data["entity_versions"][f"bundle:{payload['remainder_bundle_id']}"] = 1
    return {
        "receipt_id": "receipt-seal-1",
        "contract_version": "logistics-v1",
        "command_type": "SEAL_TRANSFER_BUNDLE",
        "status": "COMMITTED",
        "authority_scope_id": context["authority_scope_id"],
        "authority_epoch": context["authority_epoch"],
        "resolved_ledger_plane": context["ledger_plane"],
        "resolved_plane_epoch": context["plane_epoch"],
        "committed_at": "2026-07-21T00:00:00Z",
        "event_ids": ["event-seal-1"],
        "outbox_ids": ["outbox-seal-1"],
        "entity_versions": dict(data["entity_versions"]),
        "data": data,
    }


def _client(handler):
    session = FakeSession(handler)
    return LogisticsTransferClient(
        "https://server.example",
        "secret-token",
        "PC-01",
        session=session,
    ), session


def _work_group_client(handler):
    session = FakeSession(handler)
    return LogisticsTransferClient(
        "https://server.example",
        "secret-token",
        "PC-01",
        session=session,
        authority_scope_id=SCOPE,
        authority_epoch=7,
        authority_plane="AUTHORITATIVE",
        ledger_plane="AUTHORITATIVE",
        plane_epoch=3,
        authoritative_required=True,
    ), session


def _prepare(coordinator, barcodes=("BC-1", "BC-2", "BC-3"), *, include_bundle=True):
    fields = {
        "ITG": "ITAG-001",
        "LBL": "INPUT-LABEL-001",
        "WID": "WORK-001",
        "CLC": ITEM,
        "QT": "3",
    }
    if include_bundle:
        fields["BND"] = SOURCE
    return coordinator.prepare(
        master_label="PHS=1|BND=PHS-SERVER-001|ITG=ITAG-001|CLC=AAA2270730100|QT=3",
        master_label_fields=fields,
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=barcodes,
    )


def test_source_identity_keeps_input_label_as_evidence_not_external_identity():
    identity = source_identity_from_label(
        {"ITG": "ITAG-1", "LBL": "INPUT-LABEL", "WID": "WORK-1", "CLC": ITEM}
    )

    assert identity == {
        "source_bundle_id": "",
        "input_tag_id": "ITAG-1",
        "input_tag_label_id": "INPUT-LABEL",
        "input_tag_hash_prefix": "",
        "compat_work_order_id": "WORK-1",
        "source_kind": "",
        "external_label": "",
        "authority_scope_id": "",
        "item_id": ITEM,
    }

    inspection_identity = source_identity_from_label(
        {
            "ITG": "ITAG-2",
            "WID": "COMPAT-MUST-NOT-BECOME-IDENTITY",
            "AUTH_SCOPE": SCOPE,
            "CLC": "INSPECTION",
            "ITEM": ITEM,
        }
    )
    assert inspection_identity["item_id"] == ITEM
    assert inspection_identity["external_label"] == ""
    assert inspection_identity["authority_scope_id"] == SCOPE

    regular_phs = source_identity_from_label({"WID": "WORK-REGULAR", "CLC": ITEM})
    assert regular_phs["external_label"] == "WORK-REGULAR"

    phs1_membership_hash = source_identity_from_label(
        {"PHS": "1", "ITG": "ITAG-3", "HSH": "f" * 64, "CLC": ITEM}
    )
    assert phs1_membership_hash["input_tag_hash_prefix"] == ""


def test_compact_phs2_requires_canonical_registry_identity_without_qt():
    fields = validate_compact_phs2_fields(_compact_phs2_fields())

    assert fields == _compact_phs2_fields()
    assert "QT" not in fields

    with pytest.raises(TransferSealError) as exc_info:
        validate_compact_phs2_fields({"PHS": "2", "CLC": ITEM, "QT": "60"})

    assert exc_info.value.code == "PHS2_CANONICAL_EVIDENCE_REQUIRED"


def test_compact_phs2_preflight_uses_completed_exact_member_count_without_qr_qt():
    fields = _compact_phs2_fields()
    result = validate_compact_phs2_preflight(fields, _resolved_compact_phs2(count=15))

    assert result.member_count == 15
    assert result.item_id == ITEM
    assert result.source_session_id == fields["ITG"]
    assert result.input_tag_label_id == fields["LBL"]
    assert result.input_tag_hash_prefix == fields["HSH"]
    assert result.audit_detail()["quantity_basis"] == "CENTRAL_EXACT_MEMBERSHIP"


def test_compact_phs2_preflight_accepts_exact_non_anchor_work_group_source():
    resolved = _resolved_non_anchor_compact_phs2(count=3)
    fields = _compact_phs2_fields(
        LBL="WORK-LABEL-002",
        HSH=ACTIVE_PHS2_HASH_PREFIX,
    )

    result = validate_compact_phs2_preflight(fields, resolved)

    assert result.input_tag_id == "ITAG-001"
    assert result.source_session_id == "ITAG-002"
    assert result.active_label_id == "WORK-LABEL-002"
    assert result.member_ids == tuple(sorted(resolved["bundle"]["member_ids"]))


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (
            lambda value: value.pop("source_input_tag"),
            "PHS2_SOURCE_REGISTRY_EVIDENCE_REQUIRED",
        ),
        (
            lambda value: value["phs_label_resolution"]["effective_labels"][
                0
            ].update(
                {
                    "member_ids": ["unit-foreign"],
                    "member_count": 1,
                    "membership_hash": membership_hash(["unit-foreign"]),
                }
            ),
            "PHS2_WORK_GROUP_MEMBERSHIP_MISMATCH",
        ),
        (
            lambda value: value["source_input_tag"].update(
                {"membership_hash": membership_hash(["unit-foreign"])}
            ),
            "PHS2_SOURCE_REGISTRY_MEMBERSHIP_MISMATCH",
        ),
    ],
)
def test_compact_phs2_non_anchor_source_fails_closed_for_inexact_proof(
    mutate,
    expected_code,
):
    resolved = _resolved_non_anchor_compact_phs2(count=3)
    mutate(resolved)

    with pytest.raises(TransferSealError) as exc_info:
        validate_compact_phs2_preflight(
            _compact_phs2_fields(
                LBL="WORK-LABEL-002",
                HSH=ACTIVE_PHS2_HASH_PREFIX,
            ),
            resolved,
        )

    assert exc_info.value.code == expected_code


@pytest.mark.parametrize("mode", ["merge", "split"])
def test_work_group_preflight_validates_all_current_sources_and_topology(mode):
    resolved = _resolved_work_group_phs2(mode=mode)
    fields = _fields_from_compact_qr(
        resolved["phs_work_group"]["scan_payload"]
    )

    result = validate_compact_phs2_preflight(fields, resolved)

    source = resolved["work_group_source"]
    assert result.source_resolution_basis == (
        "PHS_WORK_GROUP_EXACT_MEMBERSHIP"
    )
    assert result.source_bundle_ids == tuple(source["source_bundle_ids"])
    assert result.source_session_ids == tuple(source["source_session_ids"])
    assert result.member_ids == tuple(source["member_ids"])
    assert result.entity_versions == source["entity_versions"]
    assert result.topology_hash == source["topology_hash"]
    assert result.transfer_bundle_id == source["transfer_bundle_id"]
    assert result.canonical_input_tag_qr == resolved["input_tag"][
        "qr_payload"
    ]
    if mode == "merge":
        assert result.source_bundle_id == ""
        assert len(result.source_bundle_ids) == 2
    else:
        assert result.source_bundle_id == SOURCE
        assert len(result.remainder_cover_groups) == 1
        assert resolved["source_input_tags"][0]["member_count"] == 4
        assert result.member_count == 2


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (
            lambda value: value["work_group_source"].update(
                {"topology_hash": "0" * 64}
            ),
            "PHS2_WORK_GROUP_TOPOLOGY_HASH_MISMATCH",
        ),
        (
            lambda value: value.pop("source_input_tags"),
            "PHS2_SOURCE_REGISTRY_EVIDENCE_REQUIRED",
        ),
        (
            lambda value: value["work_group_source"][
                "source_bundles"
            ][0]["selected_member_ids"].append("unit-001"),
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
        ),
        (
            lambda value: value["work_group_source"][
                "remainder_cover_groups"
            ][0].update(
                {
                    "covered_member_ids": ["unit-004"],
                    "covered_member_count": 1,
                    "covered_membership_hash": membership_hash(
                        ["unit-004"]
                    ),
                }
            ),
            "PHS2_WORK_GROUP_REMAINDER_COVER_MISMATCH",
        ),
        (
            lambda value: (
                value["work_group_source"]["entity_versions"].update(
                    {
                        f"phs_work_group:{value['phs_work_group']['group_id']}": 99
                    }
                ),
                value["entity_versions"].update(
                    {
                        f"phs_work_group:{value['phs_work_group']['group_id']}": 99
                    }
                ),
            ),
            "PHS2_WORK_GROUP_TOPOLOGY_INVALID",
        ),
    ],
)
def test_work_group_preflight_fails_closed_for_malformed_topology(
    mutate,
    expected_code,
):
    resolved = _resolved_work_group_phs2(mode="split")
    mutate(resolved)

    with pytest.raises(TransferSealError) as exc_info:
        validate_compact_phs2_preflight(
            _fields_from_compact_qr(
                resolved["phs_work_group"]["scan_payload"]
            ),
            resolved,
        )

    assert exc_info.value.code == expected_code


def test_compact_phs2_rejects_qt_even_when_registry_identity_fields_are_present():
    with pytest.raises(TransferSealError) as exc_info:
        validate_compact_phs2_fields(_compact_phs2_fields(QT="60"))

    assert exc_info.value.code == "PHS2_COMPACT_FORMAT_REQUIRED"


@pytest.mark.parametrize(
    ("mutate", "expected_code"),
    [
        (
            lambda value: value["input_tag"].update({"lifecycle": "ISSUED"}),
            "PHS2_REGISTRY_IDENTITY_MISMATCH",
        ),
        (
            lambda value: value["bundle"].update({"bundle_state": "CONSUMED"}),
            "PHS2_SOURCE_IDENTITY_MISMATCH",
        ),
        (
            lambda value: value["bundle"]["members"][0].update({"item_id": "OTHER"}),
            "PHS2_MIXED_MEMBERSHIP",
        ),
        (
            lambda value: value["bundle"]["members"][0].update(
                {"current_inbound_iin": "OTHER-IIN"}
            ),
            "PHS2_MIXED_MEMBERSHIP",
        ),
        (
            lambda value: value["bundle"]["members"][0].update(
                {"unit_state": "CLAIMED"}
            ),
            "PHS2_MEMBER_NOT_AVAILABLE",
        ),
    ],
)
def test_compact_phs2_preflight_fails_closed_for_incomplete_or_mixed_source(
    mutate,
    expected_code,
):
    resolved = json.loads(json.dumps(_resolved_compact_phs2(count=3)))
    mutate(resolved)

    with pytest.raises(TransferSealError) as exc_info:
        validate_compact_phs2_preflight(_compact_phs2_fields(), resolved)

    assert exc_info.value.code == expected_code


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["input_tag"].update(
            {"qr_payload": _compact_phs2_qr(LBL="OTHER-LABEL")}
        ),
        lambda value: value["bundle"].update(
            {"external_label": _compact_phs2_qr(ITG="OTHER-INPUT-TAG")}
        ),
    ],
)
def test_compact_phs2_preflight_rejects_registry_or_bundle_qr_identity_drift(mutate):
    resolved = json.loads(json.dumps(_resolved_compact_phs2(count=3)))
    mutate(resolved)

    with pytest.raises(TransferSealError) as exc_info:
        validate_compact_phs2_preflight(_compact_phs2_fields(), resolved)

    assert exc_info.value.code == "PHS2_REGISTRY_IDENTITY_MISMATCH"


def test_compact_phs2_preflight_accepts_completed_consumed_member_state():
    resolved = _resolved_compact_phs2(count=2)
    for member in resolved["bundle"]["members"]:
        member["unit_state"] = "CONSUMED"

    result = validate_compact_phs2_preflight(_compact_phs2_fields(), resolved)

    assert result.member_count == 2


def test_compact_phs2_resolver_sends_itg_label_and_hash_prefix():
    observed_query = {}

    def handler(call):
        observed_query.update(parse_qs(urlsplit(call["url"]).query))
        return FakeResponse(200, {"ok": True, "data": _resolved_compact_phs2(count=2)})

    client, _session = _client(handler)
    identity = source_identity_from_label(_compact_phs2_fields())

    client.resolve_source(identity)

    assert observed_query["bundle_role"] == ["TRANSFER_SOURCE"]
    assert observed_query["input_tag_id"] == ["ITAG-001"]
    assert observed_query["input_tag_label_id"] == ["INPUT-LABEL-001"]
    assert observed_query["input_tag_hash_prefix"] == [PHS2_HASH_PREFIX]
    assert observed_query["item_id"] == [ITEM]
    assert "external_label" not in observed_query


def test_store_prepare_is_idempotent_and_rejects_normalized_duplicate(tmp_path):
    store = TransferSealStore(tmp_path / "seal.db")
    first = store.prepare(
        master_label="MASTER-1",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["bc-1", "bc-2"],
    )
    replay = store.prepare(
        master_label="MASTER-1",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["bc-1", "bc-2"],
    )

    assert first["intent_id"] == replay["intent_id"]
    assert first["idempotency_key"] == replay["idempotency_key"]
    with store._connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM transfer_seal_intents"
        ).fetchone()[0] == 1
        linked = conn.execute(
            "SELECT event_type,idempotency_key FROM transfer_completion_ledger"
        ).fetchall()
    assert len(linked) == 1
    assert linked[0]["event_type"] == "LINKED"
    assert linked[0]["idempotency_key"] == first["idempotency_key"]
    with pytest.raises(ValueError, match="unique"):
        store.prepare(
            master_label="MASTER-2",
            source_identity={"source_bundle_id": SOURCE},
            item_id=ITEM,
            operator="tester",
            scanned_barcodes=["bc-1", "BC-1"],
        )


def test_offline_multi_event_keeps_linked_ledger_and_fifo_outbox(tmp_path):
    coordinator = TransferSealCoordinator(
        TransferSealStore(tmp_path / "offline.db"),
        None,
    )
    first = coordinator.prepare(
        master_label="MASTER-OFFLINE-1",
        master_label_fields={"BND": SOURCE, "CLC": ITEM},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
    )
    second = coordinator.prepare(
        master_label="MASTER-OFFLINE-2",
        master_label_fields={"BND": SOURCE, "CLC": ITEM},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-2"],
    )

    assert coordinator.store.pending_ids() == [first.intent_id, second.intent_id]
    attempts = coordinator.drain_pending()

    assert [attempt.intent_id for attempt in attempts] == [
        first.intent_id,
        second.intent_id,
    ]
    assert [attempt.status for attempt in attempts] == [
        "RETRY_WAIT",
        "RETRY_WAIT",
    ]
    assert [attempt.command_id for attempt in attempts] == [
        first.command_id,
        second.command_id,
    ]
    with coordinator.store._connect() as conn:
        linked = conn.execute(
            """SELECT intent_id,event_type,idempotency_key
                 FROM transfer_completion_ledger
                 ORDER BY ledger_sequence"""
        ).fetchall()
    assert [row["intent_id"] for row in linked] == [
        first.intent_id,
        second.intent_id,
    ]
    assert all(row["event_type"] == "LINKED" for row in linked)


def test_restart_replays_fifo_with_original_idempotency_keys(tmp_path):
    db_path = tmp_path / "restart-fifo.db"
    offline = TransferSealCoordinator(TransferSealStore(db_path), None)
    first = _prepare(offline)
    second = offline.prepare(
        master_label=(
            "PHS=1|BND=PHS-SERVER-001|ITG=ITAG-001|"
            "CLC=AAA2270730100|QT=3|LOCAL=SECOND"
        ),
        master_label_fields={
            "BND": SOURCE,
            "ITG": "ITAG-001",
            "LBL": "INPUT-LABEL-001",
            "CLC": ITEM,
        },
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1", "BC-2", "BC-3"],
    )
    expected_keys = [first.command_id, second.command_id]
    posted_keys = []

    def handler(call):
        if call["method"] == "GET" and "/bundles/resolve?" in call["url"]:
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        if call["method"] == "POST":
            posted_keys.append(call["headers"]["Idempotency-Key"])
            return FakeResponse(200, {"ok": True, "data": _receipt(call["json"])})
        raise AssertionError(call)

    client, _session = _client(handler)
    restarted = TransferSealCoordinator(TransferSealStore(db_path), client)

    assert [result.status for result in restarted.drain_pending()] == [
        "ACKED",
        "ACKED",
    ]
    assert posted_keys == expected_keys


def test_linked_ledger_and_outbox_roll_back_together_on_durable_write_failure(
    tmp_path,
):
    store = TransferSealStore(tmp_path / "atomic-failure.db")
    with store._connect() as conn:
        conn.executescript(
            """
            CREATE TRIGGER fail_local_completion_ledger
            BEFORE INSERT ON transfer_completion_ledger
            BEGIN SELECT RAISE(ABORT, 'forced local ledger failure'); END;
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="forced local ledger failure"):
        store.prepare(
            master_label="MASTER-ATOMIC-FAIL",
            source_identity={"source_bundle_id": SOURCE},
            item_id=ITEM,
            operator="tester",
            scanned_barcodes=["BC-1"],
        )

    with store._connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM transfer_seal_intents"
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM transfer_completion_ledger"
        ).fetchone()[0] == 0


def test_linked_completion_ledger_is_append_only(tmp_path):
    store = TransferSealStore(tmp_path / "append-only.db")
    prepared = store.prepare(
        master_label="MASTER-APPEND-ONLY",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
    )

    with store._connect() as conn:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(
                "UPDATE transfer_completion_ledger SET event_type='LINKED'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM transfer_completion_ledger")
        linked = conn.execute(
            "SELECT intent_id,idempotency_key FROM transfer_completion_ledger"
        ).fetchone()

    assert linked["intent_id"] == prepared["intent_id"]
    assert linked["idempotency_key"] == prepared["idempotency_key"]


def test_existing_outbox_is_migrated_to_stable_key_and_linked_ledger(tmp_path):
    db_path = tmp_path / "legacy-outbox.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE transfer_seal_intents (
                intent_id TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                status TEXT NOT NULL,
                master_label TEXT NOT NULL,
                source_identity_json TEXT NOT NULL,
                item_id TEXT NOT NULL,
                operator TEXT NOT NULL,
                scanned_barcodes_json TEXT NOT NULL,
                scan_count INTEGER NOT NULL,
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
                updated_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """INSERT INTO transfer_seal_intents (
                   intent_id,schema_version,status,master_label,source_identity_json,
                   item_id,operator,scanned_barcodes_json,scan_count,intent_hash,
                   created_at,updated_at
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "legacy-intent-1",
                "container-audit-transfer-seal-v1",
                "RETRY_WAIT",
                "MASTER-LEGACY",
                json.dumps({"source_bundle_id": SOURCE}),
                ITEM,
                "tester",
                json.dumps(["BC-1"]),
                1,
                "f" * 64,
                "2026-07-01T00:00:00Z",
                "2026-07-01T00:00:00Z",
            ),
        )

    store = TransferSealStore(db_path)
    migrated = store.load("legacy-intent-1")

    assert migrated["idempotency_key"] == f"container-seal:{'f' * 64}"
    assert migrated["local_completion_id"].startswith("TRANSFER-LINKED-")
    assert store.pending_ids() == ["legacy-intent-1"]


def test_replacement_waiting_mark_is_atomic_append_only_and_deduped(tmp_path):
    store = TransferSealStore(tmp_path / "replacement-wait.db")
    event_log_path = tmp_path / "events.csv"
    values = {
        "session_id": "ITAG-WAIT-001",
        "old_label_id": "LBL-OLD-001",
        "new_label_id": "LBL-NEW-001",
        "process_context": "transfer",
        "location_codes": ["PHS_GOOD"],
        "operator": "tester",
        "master_label": "PHS=2|ITG=ITAG-WAIT-001",
        "projection_log_file_path": str(event_log_path),
    }

    first = store.mark_phs_replacement_waiting(**values)
    replay = store.mark_phs_replacement_waiting(**values)
    old_hash = hashlib.sha256(b"LBL-OLD-001").hexdigest()
    new_hash = hashlib.sha256(b"LBL-NEW-001").hexdigest()
    expected_key = (
        f"replacement-wait:ITAG-WAIT-001:{old_hash}:{new_hash}"
    )

    assert first["intent_id"] == replay["intent_id"]
    assert first["idempotency_key"] == expected_key
    assert json.loads(first["location_codes_json"]) == ["PHS_GOOD"]
    assert first["projection_log_file_path"] == str(event_log_path)
    with store._connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM phs_replacement_waiting_ledger"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM phs_replacement_waiting_outbox"
        ).fetchone()[0] == 1
        for table in (
            "phs_replacement_waiting_ledger",
            "phs_replacement_waiting_outbox",
        ):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                conn.execute(f"UPDATE {table} SET event_type=event_type")
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                conn.execute(f"DELETE FROM {table}")


def test_replacement_waiting_outbox_restarts_in_fifo_with_session_pair_dedupe(
    tmp_path,
):
    db_path = tmp_path / "replacement-restart.db"
    store = TransferSealStore(db_path)
    first = store.mark_phs_replacement_waiting(
        session_id="ITAG-WAIT-001",
        old_label_id="LBL-OLD",
        new_label_id="LBL-NEW",
        process_context="transfer",
        location_codes=["PHS_GOOD"],
        operator="tester",
        master_label="MASTER-1",
        projection_log_file_path=str(tmp_path / "worker-1.csv"),
    )
    store.mark_phs_replacement_waiting(
        session_id="ITAG-WAIT-001",
        old_label_id="LBL-OLD",
        new_label_id="LBL-NEW",
        process_context="transfer",
        location_codes=["PHS_GOOD"],
        operator="other-observer",
        master_label="MASTER-1",
        projection_log_file_path=str(tmp_path / "ignored-replay.csv"),
    )
    second = store.mark_phs_replacement_waiting(
        session_id="ITAG-WAIT-002",
        old_label_id="LBL-OLD",
        new_label_id="LBL-NEW",
        process_context="transfer",
        location_codes=["PHS_GOOD"],
        operator="tester",
        master_label="MASTER-2",
        projection_log_file_path=str(tmp_path / "worker-2.csv"),
    )

    restarted = TransferSealStore(db_path)
    pending = restarted.replacement_waiting_outbox()

    assert [row["intent_id"] for row in pending] == [
        first["intent_id"],
        second["intent_id"],
    ]
    assert [row["idempotency_key"] for row in pending] == [
        first["idempotency_key"],
        second["idempotency_key"],
    ]


def test_replacement_waiting_ledger_and_outbox_roll_back_together(tmp_path):
    store = TransferSealStore(tmp_path / "replacement-atomic-failure.db")
    with store._connect() as conn:
        conn.executescript(
            """
            CREATE TRIGGER fail_replacement_waiting_outbox
            BEFORE INSERT ON phs_replacement_waiting_outbox
            BEGIN SELECT RAISE(ABORT, 'forced replacement outbox failure'); END;
            """
        )

    with pytest.raises(
        sqlite3.IntegrityError,
        match="forced replacement outbox failure",
    ):
        store.mark_phs_replacement_waiting(
            session_id="ITAG-WAIT-FAIL",
            old_label_id="LBL-OLD",
            new_label_id="LBL-NEW",
            process_context="transfer",
            location_codes=["PHS_GOOD"],
            operator="tester",
            master_label="MASTER-FAIL",
            projection_log_file_path=str(tmp_path / "failure.csv"),
        )

    with store._connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM phs_replacement_waiting_ledger"
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM phs_replacement_waiting_outbox"
        ).fetchone()[0] == 0


def test_replacement_waiting_projection_receipt_is_append_only_and_restart_safe(
    tmp_path,
):
    db_path = tmp_path / "replacement-projection.db"
    event_log_path = tmp_path / "events.csv"
    store = TransferSealStore(db_path)
    marked = store.mark_phs_replacement_waiting(
        session_id="ITAG-PROJECTION-001",
        old_label_id="LBL-OLD",
        new_label_id="LBL-NEW",
        process_context="transfer",
        location_codes=["PHS_GOOD"],
        operator="tester",
        master_label="MASTER-PROJECTION",
        projection_log_file_path=str(event_log_path),
    )

    pending = TransferSealStore(db_path).pending_replacement_waiting_projections()
    assert [row["intent_id"] for row in pending] == [marked["intent_id"]]
    receipt = store.record_replacement_waiting_projection(
        marked["intent_id"],
        projection_log_file_path=str(event_log_path),
    )
    replay = store.record_replacement_waiting_projection(
        marked["intent_id"],
        projection_log_file_path=str(event_log_path),
    )

    assert receipt["projection_id"] == replay["projection_id"]
    assert TransferSealStore(db_path).pending_replacement_waiting_projections() == []
    with store._connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM phs_replacement_waiting_projection_receipts"
        ).fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(
                "UPDATE phs_replacement_waiting_projection_receipts "
                "SET event_type=event_type"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM phs_replacement_waiting_projection_receipts")


def test_store_methods_release_windows_db_and_wal_handles_without_gc(tmp_path):
    db_path = tmp_path / "container-seal.db"
    store = TransferSealStore(db_path)
    row = store.prepare(
        master_label="MASTER-WINDOWS-CLOSE",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
    )
    context = {
        "contract_version": "logistics-v1",
        "command_type": "SEAL_TRANSFER_BUNDLE",
        "authority_scope_id": SCOPE,
        "authority_epoch": 1,
        "ledger_plane": "AUTHORITATIVE",
        "plane_epoch": 1,
        "idempotency_key": row["idempotency_key"],
        "expected_versions": {f"bundle:{SOURCE}": 1},
        "payload": {
            "source_bundle_id": SOURCE,
            "transfer_bundle_id": "TRANSFER-CLOSE-1",
            "item_id": ITEM,
            "member_ids": ["unit-1"],
            "membership_hash": membership_hash(["unit-1"]),
            "scanned_barcodes": ["BC-1"],
        },
    }
    store.bind_command(row["intent_id"], context)
    store.load(row["intent_id"])
    store.pending_ids()
    store.has_exact_history()
    store.record_error(
        row["intent_id"],
        TransferSealError("TRANSPORT_ERROR", "retry", retryable=True),
    )
    store.record_exchange_block(reason_code="TEST_BLOCK", details={"test": True})

    # Windows refuses these operations if even one sqlite connection remains
    # open. The store object intentionally stays alive so this does not depend
    # on garbage collection or a destructor.
    moved_paths = []
    for suffix in ("", "-wal", "-shm"):
        source = tmp_path / f"container-seal.db{suffix}"
        if not source.exists():
            continue
        moved = tmp_path / f"moved-container-seal.db{suffix}"
        source.rename(moved)
        moved_paths.append(moved)
    assert moved_paths
    for moved in moved_paths:
        moved.unlink()
        assert not moved.exists()


def test_full_transfer_seal_sends_exact_server_units_and_builds_memberless_qr(tmp_path):
    def handler(call):
        if call["method"] == "GET" and "/bundles/resolve?" in call["url"]:
            query = parse_qs(urlsplit(call["url"]).query)
            assert query["bundle_id"] == [SOURCE]
            assert query["input_tag_id"] == ["ITAG-001"]
            assert "external_label" not in query
            assert query["bundle_role"] == ["TRANSFER_SOURCE"]
            assert "INPUT-LABEL-001" not in call["url"]
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        if call["method"] == "POST" and call["url"].endswith("/transfers/seal"):
            context = call["json"]
            assert context["payload"]["member_ids"] == ["unit-1", "unit-2", "unit-3"]
            assert context["expected_versions"] == {f"bundle:{SOURCE}": 4}
            assert "remainder_bundle_id" not in context["payload"]
            assert call["headers"]["Idempotency-Key"] == context["idempotency_key"]
            return FakeResponse(200, {"ok": True, "status": "committed", "data": _receipt(context)})
        raise AssertionError(call)

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator)
    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "ACKED"
    assert result.member_count == 3
    assert result.membership_hash == membership_hash(["unit-1", "unit-2", "unit-3"])
    assert f"BND={result.transfer_bundle_id}" in result.seal_qr_payload
    assert f"CLC={ITEM}" in result.seal_qr_payload
    assert "unit-1" not in result.seal_qr_payload
    assert "BC-1" not in result.seal_qr_payload


def test_non_anchor_work_group_seals_actual_source_once(tmp_path):
    resolved = _resolved_non_anchor_compact_phs2(count=3)
    posted = []

    def handler(call):
        if call["method"] == "GET" and "/bundles/resolve?" in call["url"]:
            return FakeResponse(200, {"ok": True, "data": resolved})
        if call["method"] == "POST" and call["url"].endswith("/transfers/seal"):
            posted.append(call)
            context = call["json"]
            assert context["payload"]["source_bundle_id"] == SOURCE
            assert context["expected_versions"] == {f"bundle:{SOURCE}": 4}
            return FakeResponse(
                200,
                {"ok": True, "status": "committed", "data": _receipt(context)},
            )
        raise AssertionError(call)

    client, session = _client(handler)
    coordinator = TransferSealCoordinator(
        TransferSealStore(tmp_path / "non-anchor.db"),
        client,
    )
    fields = _compact_phs2_fields(
        LBL="WORK-LABEL-002",
        HSH=ACTIVE_PHS2_HASH_PREFIX,
    )
    prepared = coordinator.prepare(
        master_label=_compact_phs2_qr(
            LBL="WORK-LABEL-002",
            HSH=ACTIVE_PHS2_HASH_PREFIX,
        ),
        master_label_fields=fields,
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=[
            member["normalized_barcode"]
            for member in resolved["bundle"]["members"]
        ],
    )

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "ACKED"
    assert len(posted) == 1
    assert [call["method"] for call in session.calls] == ["GET", "POST"]


@pytest.mark.parametrize("mode", ["merge", "split"])
def test_work_group_command_seals_exact_topology_once(tmp_path, mode):
    resolved = _resolved_work_group_phs2(mode=mode)
    posted = []

    def handler(call):
        if call["method"] == "GET" and "/bundles/resolve?" in call["url"]:
            return FakeResponse(200, {"ok": True, "data": resolved})
        if call["method"] == "POST" and call["url"].endswith(
            "/transfers/seal"
        ):
            posted.append(call)
            context = call["json"]
            source = resolved["work_group_source"]
            assert context["payload"]["source_resolution_basis"] == (
                "PHS_WORK_GROUP_EXACT_MEMBERSHIP"
            )
            assert context["payload"]["source_bundles"] == source[
                "source_bundles"
            ]
            assert context["payload"]["remainder_cover_groups"] == source[
                "remainder_cover_groups"
            ]
            assert context["payload"]["uom"] == "EA"
            assert context["expected_versions"] == source[
                "entity_versions"
            ]
            assert context["expected_versions"][
                f"bundle:{source['transfer_bundle_id']}"
            ] == 0
            return FakeResponse(
                200,
                {
                    "ok": True,
                    "status": "committed",
                    "data": _work_group_receipt(context),
                },
            )
        raise AssertionError(call)

    client, session = _work_group_client(handler)
    coordinator = TransferSealCoordinator(
        TransferSealStore(tmp_path / f"work-group-{mode}.db"),
        client,
    )
    master_label = resolved["phs_work_group"]["scan_payload"]
    fields = _fields_from_compact_qr(master_label)
    prepared = coordinator.prepare(
        master_label=master_label,
        master_label_fields=fields,
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=[
            member["normalized_barcode"]
            for member in resolved["work_group_source"]["members"]
        ],
    )

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "ACKED"
    assert result.transfer_bundle_id == resolved["work_group_source"][
        "transfer_bundle_id"
    ]
    assert len(posted) == 1
    assert [call["method"] for call in session.calls] == ["GET", "POST"]
    if mode == "merge":
        assert result.source_bundle_id == ""
        assert result.remainder_bundle_id == ""
    else:
        assert result.source_bundle_id == SOURCE
        assert result.remainder_bundle_id == resolved[
            "work_group_source"
        ]["source_bundles"][0]["remainder_bundle_id"]


def test_work_group_bound_command_retry_does_not_resolve_again(tmp_path):
    resolved = _resolved_work_group_phs2(mode="merge")
    post_count = 0

    def handler(call):
        nonlocal post_count
        if call["method"] == "GET" and "/bundles/resolve?" in call["url"]:
            return FakeResponse(200, {"ok": True, "data": resolved})
        if call["method"] == "POST" and call["url"].endswith(
            "/transfers/seal"
        ):
            post_count += 1
            if post_count == 1:
                return FakeResponse(
                    503,
                    {
                        "ok": False,
                        "retryable": True,
                        "committed": False,
                        "error": {
                            "code": "TEMPORARY_UNAVAILABLE",
                            "message": "retry",
                        },
                    },
                )
            return FakeResponse(
                200,
                {
                    "ok": True,
                    "data": _work_group_receipt(call["json"]),
                },
            )
        raise AssertionError(call)

    client, session = _work_group_client(handler)
    coordinator = TransferSealCoordinator(
        TransferSealStore(tmp_path / "work-group-retry.db"),
        client,
    )
    master_label = resolved["phs_work_group"]["scan_payload"]
    prepared = coordinator.prepare(
        master_label=master_label,
        master_label_fields=_fields_from_compact_qr(master_label),
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=[
            member["normalized_barcode"]
            for member in resolved["work_group_source"]["members"]
        ],
    )

    waiting = coordinator.attempt(prepared.intent_id)
    recovered = coordinator.attempt(prepared.intent_id)

    assert waiting.status == "RETRY_WAIT"
    assert recovered.status == "ACKED"
    assert [call["method"] for call in session.calls] == [
        "GET",
        "POST",
        "POST",
    ]


def test_work_group_lost_ack_recovers_receipt_without_second_write(tmp_path):
    resolved = _resolved_work_group_phs2(mode="merge")
    committed_receipt = None
    post_count = 0

    def handler(call):
        nonlocal committed_receipt, post_count
        if call["method"] == "GET" and "/bundles/resolve?" in call["url"]:
            return FakeResponse(200, {"ok": True, "data": resolved})
        if call["method"] == "POST" and call["url"].endswith(
            "/transfers/seal"
        ):
            post_count += 1
            committed_receipt = _work_group_receipt(call["json"])
            raise ConnectionError("lost ack")
        if call["method"] == "GET" and "/receipts/" in call["url"]:
            assert committed_receipt is not None
            return FakeResponse(
                200,
                {"ok": True, "data": committed_receipt},
            )
        raise AssertionError(call)

    client, session = _work_group_client(handler)
    coordinator = TransferSealCoordinator(
        TransferSealStore(tmp_path / "work-group-lost-ack.db"),
        client,
    )
    master_label = resolved["phs_work_group"]["scan_payload"]
    prepared = coordinator.prepare(
        master_label=master_label,
        master_label_fields=_fields_from_compact_qr(master_label),
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=[
            member["normalized_barcode"]
            for member in resolved["work_group_source"]["members"]
        ],
    )

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "ACKED"
    assert post_count == 1
    assert [call["method"] for call in session.calls] == [
        "GET",
        "POST",
        "GET",
    ]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda receipt: receipt["data"]["phs_work_group"].update(
            {"group_id": "PHSG-WRONG"}
        ),
        lambda receipt: receipt["data"]["source_transitions"][0].update(
            {"selected_membership_hash": "0" * 64}
        ),
        lambda receipt: receipt["data"].update(
            {"topology_hash_after": "0" * 64}
        ),
        lambda receipt: receipt["data"]["root_proof"][0].update(
            {"root_id": "PHS-WRONG"}
        ),
    ],
)
def test_work_group_receipt_drift_is_never_acked(tmp_path, mutate):
    resolved = _resolved_work_group_phs2(mode="split")

    def handler(call):
        if call["method"] == "GET" and "/bundles/resolve?" in call["url"]:
            return FakeResponse(200, {"ok": True, "data": resolved})
        if call["method"] == "POST" and call["url"].endswith(
            "/transfers/seal"
        ):
            receipt = json.loads(
                json.dumps(_work_group_receipt(call["json"]))
            )
            mutate(receipt)
            return FakeResponse(200, {"ok": True, "data": receipt})
        raise AssertionError(call)

    client, _session = _work_group_client(handler)
    coordinator = TransferSealCoordinator(
        TransferSealStore(tmp_path / "work-group-bad-receipt.db"),
        client,
    )
    master_label = resolved["phs_work_group"]["scan_payload"]
    prepared = coordinator.prepare(
        master_label=master_label,
        master_label_fields=_fields_from_compact_qr(master_label),
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=[
            member["normalized_barcode"]
            for member in resolved["work_group_source"]["members"]
        ],
    )

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RECEIPT_MEMBERSHIP_MISMATCH"
    assert not result.receipt_id


def test_partial_phs_seal_is_blocked_before_post(tmp_path):
    posted = []

    def handler(call):
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        posted.append(call["json"])
        raise AssertionError("partial PHS transfer must not be posted")

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator, ("BC-1", "BC-3"))
    result = coordinator.attempt(prepared.intent_id)
    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "PARTIAL_PHS_TRANSFER_FORBIDDEN"
    assert "이름·시간·품목·수량·수기 코드" in result.error_message
    assert "RSL1은 업그레이드 전에 시작한 예전 작업 복구에만 사용합니다" in result.error_message
    assert "잔량은 RSL1을 사용" not in result.error_message
    assert posted == []


def test_precommand_review_lookup_requires_exact_commandless_row(tmp_path):
    store = TransferSealStore(tmp_path / "precommand-review.db")
    prepared = store.prepare(
        master_label="PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-RETRY|"
        f"CLC={ITEM}|LBL=LBL-OLD|HSH=oldhash",
        source_identity={
            "input_tag_id": "ITAG-RETRY",
            "input_tag_label_id": "LBL-OLD",
            "item_id": ITEM,
        },
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1", "BC-2"],
    )
    store.record_error(
        prepared["intent_id"],
        TransferSealError(
            "PHS_LABEL_REPLACEMENT_AMBIGUOUS",
            "scan one active replacement",
            status_code=400,
        ),
    )

    matched = store.precommand_operator_review(
        master_label=prepared["master_label"],
        scanned_barcodes=["BC-1", "BC-2"],
        error_code="PHS_LABEL_REPLACEMENT_AMBIGUOUS",
    )

    assert matched is not None
    assert matched["intent_id"] == prepared["intent_id"]
    assert matched["command_json"] is None
    assert matched["receipt_json"] is None
    assert (
        store.precommand_operator_review(
            master_label=prepared["master_label"],
            scanned_barcodes=["BC-2", "BC-1"],
            error_code="PHS_LABEL_REPLACEMENT_AMBIGUOUS",
        )
        is None
    )

    command_bound = store.prepare(
        master_label="PHS=2|SRC=KMTECH_INPUT_TAG|ITG=ITAG-BOUND|"
        f"CLC={ITEM}|LBL=LBL-BOUND|HSH=boundhash",
        source_identity={
            "input_tag_id": "ITAG-BOUND",
            "input_tag_label_id": "LBL-BOUND",
            "item_id": ITEM,
        },
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-3"],
    )
    store.bind_command(
        command_bound["intent_id"],
        {"idempotency_key": command_bound["idempotency_key"]},
    )
    store.record_error(
        command_bound["intent_id"],
        TransferSealError(
            "PHS_LABEL_REPLACEMENT_AMBIGUOUS",
            "review after durable command",
            status_code=400,
        ),
    )
    assert (
        store.precommand_operator_review(
            master_label=command_bound["master_label"],
            scanned_barcodes=["BC-3"],
            error_code="PHS_LABEL_REPLACEMENT_AMBIGUOUS",
        )
        is None
    )


def test_restart_reuses_immutable_command_and_recovers_lost_ack(tmp_path):
    db_path = tmp_path / "seal.db"
    first_post = []

    def first_handler(call):
        if call["method"] == "GET" and "/bundles/resolve?" in call["url"]:
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        if call["method"] == "POST":
            first_post.append(call)
            raise ConnectionError("lost ack")
        if call["method"] == "GET" and "/receipts/" in call["url"]:
            return FakeResponse(404, {"ok": False, "error": {"code": "RECEIPT_NOT_FOUND"}})
        raise AssertionError(call)

    client1, _session1 = _client(first_handler)
    coordinator1 = TransferSealCoordinator(TransferSealStore(db_path), client1)
    prepared = _prepare(coordinator1)
    waiting = coordinator1.attempt(prepared.intent_id)
    durable_before = coordinator1.store.load(prepared.intent_id)

    assert waiting.status == "RETRY_WAIT"
    assert durable_before["command_json"]
    assert waiting.command_id == prepared.command_id
    assert durable_before["idempotency_key"] == prepared.command_id
    with coordinator1.store._connect() as conn:
        linked_before = conn.execute(
            "SELECT event_type,idempotency_key FROM transfer_completion_ledger"
        ).fetchone()
    assert linked_before["event_type"] == "LINKED"
    assert linked_before["idempotency_key"] == prepared.command_id

    second_post = []

    def second_handler(call):
        if call["method"] == "POST":
            second_post.append(call)
            return FakeResponse(200, {"ok": True, "data": _receipt(call["json"])})
        raise AssertionError(call)

    client2, _session2 = _client(second_handler)
    coordinator2 = TransferSealCoordinator(TransferSealStore(db_path), client2)
    recovered = coordinator2.attempt(prepared.intent_id)
    durable_after = coordinator2.store.load(prepared.intent_id)

    assert recovered.status == "ACKED"
    assert second_post[0]["json"] == first_post[0]["json"]
    assert second_post[0]["headers"]["Idempotency-Key"] == first_post[0]["headers"]["Idempotency-Key"]
    assert durable_after["command_json"] == durable_before["command_json"]
    assert durable_after["command_hash"] == durable_before["command_hash"]


def test_barcode_outside_source_membership_requires_operator_review_without_post(tmp_path):
    calls = []

    def handler(call):
        calls.append(call)
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        raise AssertionError("invalid membership must not be posted")

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator, ("BC-1", "OUTSIDE"))
    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "BARCODE_NOT_IN_SOURCE_BUNDLE"
    assert [call["method"] for call in calls] == ["GET"]


def test_resolver_requires_nested_canonical_bundle_before_command_is_saved(tmp_path):
    calls = []

    def handler(call):
        calls.append(call)
        if call["method"] == "GET":
            # A top-level projection omits resolver ambiguity/lineage context.
            return FakeResponse(200, {"ok": True, "data": _bundle()})
        raise AssertionError("invalid resolver response must not be posted")

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator)

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RESOLVER_CONTRACT_INVALID"
    assert [call["method"] for call in calls] == ["GET"]


def test_resolver_requires_explicit_unique_candidate_count(tmp_path):
    calls = []

    def handler(call):
        calls.append(call)
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": {"bundle": _bundle()}})
        raise AssertionError("ambiguous resolver response must not be posted")

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "count.db"), client)
    prepared = _prepare(coordinator)

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "AMBIGUOUS_BUNDLE"
    assert [call["method"] for call in calls] == ["GET"]


def test_partial_or_ambiguous_source_member_mapping_is_fail_closed(tmp_path):
    for mutation in ("partial", "duplicate_barcode", "foreign_unit"):
        calls = []
        source = _bundle()
        if mutation == "partial":
            source["members"] = source["members"][:-1]
        elif mutation == "duplicate_barcode":
            source["members"][1]["normalized_barcode"] = source["members"][0][
                "normalized_barcode"
            ]
        else:
            source["members"][1]["unit_id"] = "unit-outside"

        def handler(call, response=source):
            calls.append(call)
            if call["method"] == "GET":
                return FakeResponse(
                    200,
                    {"ok": True, "data": {"candidate_count": 1, "bundle": response}},
                )
            raise AssertionError("inexact membership must not be posted")

        client, _session = _client(handler)
        coordinator = TransferSealCoordinator(
            TransferSealStore(tmp_path / f"{mutation}.db"), client
        )
        prepared = _prepare(coordinator)

        result = coordinator.attempt(prepared.intent_id)

        assert result.status == "OPERATOR_REVIEW"
        assert result.error_code == "MEMBERSHIP_CONFLICT"
        assert [call["method"] for call in calls] == ["GET"]


def test_receipt_barcode_membership_mismatch_is_not_acked(tmp_path):
    def handler(call):
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        receipt = _receipt(call["json"])
        receipt["data"]["scanned_barcodes"] = ["BC-1", "WRONG"]
        return FakeResponse(200, {"ok": True, "data": receipt})

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = _prepare(coordinator)
    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RECEIPT_MEMBERSHIP_MISMATCH"


def test_receipt_without_server_seal_identity_is_not_acked(tmp_path):
    def handler(call):
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        receipt = _receipt(call["json"])
        receipt["data"].pop("seal_token")
        receipt["data"].pop("seal_qr_payload")
        return FakeResponse(200, {"ok": True, "data": receipt})

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    result = coordinator.attempt(_prepare(coordinator).intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RECEIPT_MEMBERSHIP_MISMATCH"


def test_receipt_sealed_unit_barcode_mapping_mismatch_is_not_acked(tmp_path):
    def handler(call):
        if call["method"] == "GET":
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        receipt = _receipt(call["json"])
        receipt["data"]["sealed_members"][0]["normalized_barcode"] = "WRONG"
        return FakeResponse(200, {"ok": True, "data": receipt})

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    result = coordinator.attempt(_prepare(coordinator).intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert result.error_code == "RECEIPT_MEMBERSHIP_MISMATCH"


def test_input_tag_resolver_excludes_compat_wid_from_identity_intersection(tmp_path):
    observed_query = {}

    def handler(call):
        if call["method"] == "GET":
            observed_query.update(parse_qs(urlsplit(call["url"]).query))
            return FakeResponse(200, {"ok": True, "data": _resolved_bundle()})
        return FakeResponse(200, {"ok": True, "data": _receipt(call["json"])})

    client, _session = _client(handler)
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "seal.db"), client)
    prepared = coordinator.prepare(
        master_label=(
            "SRC=KMTECH_INPUT_TAG|ITG=ITAG-001|LBL=INPUT-LABEL-001|"
            "WID=COMPAT-WID-MUST-NOT-QUERY|CLC=AAA2270730100|QT=3"
        ),
        master_label_fields={
            "SRC": "KMTECH_INPUT_TAG",
            "ITG": "ITAG-001",
            "LBL": "INPUT-LABEL-001",
            "WID": "COMPAT-WID-MUST-NOT-QUERY",
            "AUTH_SCOPE": SCOPE,
            "CLC": ITEM,
        },
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1", "BC-2", "BC-3"],
    )

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "ACKED"
    assert observed_query["input_tag_id"] == ["ITAG-001"]
    assert observed_query["item_id"] == [ITEM]
    assert observed_query["authority_scope_id"] == [SCOPE]
    assert "external_label" not in observed_query
    assert "COMPAT-WID-MUST-NOT-QUERY" not in json.dumps(observed_query)


def test_test_environment_disables_operator_audio(monkeypatch):
    app = ContainerAudit.__new__(ContainerAudit)
    monkeypatch.setenv("KMTECH_TEST_SILENT_AUDIO", "1")

    assert app._audio_feedback_enabled() is False


def test_exact_history_blocks_unsafe_exchange_and_writes_restriction_receipt(tmp_path, monkeypatch):
    store = TransferSealStore(tmp_path / "seal.db")
    store.prepare(
        master_label="MASTER-EXACT",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
    )
    app = ContainerAudit.__new__(ContainerAudit)
    app.transfer_seal_coordinator = TransferSealCoordinator(store, None)
    app.current_tray = type("Tray", (), {"master_label_code": ""})()
    app.worker_name = ""
    app.log_file_path = ""
    warnings = []
    monkeypatch.setattr("Container_Audit.messagebox.showwarning", lambda *args: warnings.append(args))
    monkeypatch.setattr(
        "Container_Audit.tk.Toplevel",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("blocked exact exchange must not open a dialog")
        ),
    )

    app.show_exchange_dialog()

    assert warnings and warnings[0][0] == "관리자 교체 절차 필요"
    worker_copy = " ".join(warnings[0]).lower()
    assert "중앙 교환" not in worker_copy
    assert "bundle" not in worker_copy
    assert "cas" not in worker_copy
    with store._connect() as conn:
        receipt = conn.execute(
            "SELECT reason_code,details_json FROM transfer_exchange_block_receipts"
        ).fetchone()
    assert receipt["reason_code"] == "BLOCKED_REQUIRES_TWO_BUNDLE_CAS"
    assert json.loads(receipt["details_json"])["operator"] == ""


def test_exact_history_blocks_local_master_label_replacement(tmp_path, monkeypatch):
    store = TransferSealStore(tmp_path / "replacement-block.db")
    store.prepare(
        master_label="MASTER-EXACT-REPLACEMENT",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
    )
    app = ContainerAudit.__new__(ContainerAudit)
    app.transfer_seal_coordinator = TransferSealCoordinator(store, None)
    app.current_tray = type("Tray", (), {"master_label_code": ""})()
    app.master_label_replace_state = None
    app.replacement_context = {}
    app.worker_name = ""
    app.log_file_path = ""
    app._operator_review_blocks_mutation = lambda: False
    app._update_action_button_states = lambda: None
    warnings = []
    monkeypatch.setattr(
        "Container_Audit.messagebox.showwarning", lambda *args: warnings.append(args)
    )

    app.initiate_master_label_replacement()

    assert app.master_label_replace_state is None
    assert warnings and warnings[0][0] == "관리자 교체 절차 필요"
    worker_copy = " ".join(warnings[0]).lower()
    assert "중앙 교체" not in worker_copy
    assert "bundle" not in worker_copy
    assert "cas" not in worker_copy
    with store._connect() as conn:
        receipt = conn.execute(
            """SELECT reason_code,details_json
                 FROM transfer_exchange_block_receipts
                WHERE reason_code='BLOCKED_REQUIRES_REPLACE_BUNDLE_MEMBERS_CAS'"""
        ).fetchone()
    assert receipt is not None
    details = json.loads(receipt["details_json"])
    assert details["operation"] == "completed_master_label_replacement"
    assert "open_reseal" in details["policy"]


@pytest.mark.parametrize("status_code", [409, 412])
def test_server_cas_conflict_is_terminal_even_when_marked_retryable(tmp_path, status_code):
    store = TransferSealStore(tmp_path / f"cas-{status_code}.db")
    prepared = store.prepare(
        master_label="MASTER-CAS",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
    )
    row = store.record_error(
        prepared["intent_id"],
        TransferSealError(
            "VERSION_CONFLICT",
            "source changed concurrently",
            status_code=status_code,
            retryable=True,
        ),
    )

    assert row["status"] == "OPERATOR_REVIEW"
    with store._connect() as conn:
        linked = conn.execute(
            "SELECT event_type,idempotency_key FROM transfer_completion_ledger"
        ).fetchone()
    assert linked["event_type"] == "LINKED"
    assert linked["idempotency_key"] == prepared["idempotency_key"]


def test_post_local_operator_review_case_and_outbox_are_atomic_and_exact_once(
    tmp_path,
):
    event_log_path = tmp_path / "events.csv"
    store = TransferSealStore(tmp_path / "post-review.db")
    prepared = store.prepare(
        master_label="MASTER-POST-REVIEW",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
        relay_log_file_path=str(event_log_path),
    )
    error = TransferSealError(
        "VERSION_CONFLICT",
        "source changed concurrently",
        status_code=409,
    )

    first = store.record_error(prepared["intent_id"], error)
    replay = store.record_error(prepared["intent_id"], error)
    case = store.post_review_case_for_intent(prepared["intent_id"])
    pending = store.pending_post_review_projections()

    assert first["status"] == replay["status"] == "OPERATOR_REVIEW"
    assert first["local_completion_id"] == prepared["local_completion_id"]
    assert case["event_type"] == "POST_REVIEW_REQUIRED"
    assert case["local_completion_id"] == prepared["local_completion_id"]
    assert case["projection_log_file_path"] == str(event_log_path)
    assert [row["review_case_id"] for row in pending] == [
        case["review_case_id"]
    ]
    with store._connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM transfer_post_review_cases"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM transfer_post_review_outbox"
        ).fetchone()[0] == 1
        linked = conn.execute(
            "SELECT event_type FROM transfer_completion_ledger"
        ).fetchone()
    assert linked["event_type"] == "LINKED"


def test_post_review_outbox_failure_rolls_back_terminal_status_in_same_tx(
    tmp_path,
):
    store = TransferSealStore(tmp_path / "post-review-rollback.db")
    prepared = store.prepare(
        master_label="MASTER-POST-REVIEW-ROLLBACK",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
        relay_log_file_path=str(tmp_path / "events.csv"),
    )
    with store._connect() as conn:
        conn.executescript(
            """
            CREATE TRIGGER fail_post_review_outbox
            BEFORE INSERT ON transfer_post_review_outbox
            BEGIN SELECT RAISE(ABORT, 'forced post review outbox failure'); END;
            """
        )

    with pytest.raises(
        sqlite3.IntegrityError,
        match="forced post review outbox failure",
    ):
        store.record_error(
            prepared["intent_id"],
            TransferSealError(
                "VERSION_CONFLICT",
                "source changed concurrently",
                status_code=409,
            ),
        )

    assert store.load(prepared["intent_id"])["status"] == "PREPARED"
    with store._connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM transfer_post_review_cases"
        ).fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM transfer_post_review_outbox"
        ).fetchone()[0] == 0


def test_post_review_projection_receipt_is_append_only_and_restart_safe(
    tmp_path,
):
    event_log_path = tmp_path / "events.csv"
    db_path = tmp_path / "post-review-projection.db"
    store = TransferSealStore(db_path)
    prepared = store.prepare(
        master_label="MASTER-POST-REVIEW-PROJECTION",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
        relay_log_file_path=str(event_log_path),
    )
    store.record_error(
        prepared["intent_id"],
        TransferSealError(
            "VERSION_CONFLICT",
            "source changed concurrently",
            status_code=409,
        ),
    )
    case = store.post_review_case_for_intent(prepared["intent_id"])

    receipt = store.record_post_review_projection(
        case["review_case_id"],
        projection_log_file_path=str(event_log_path),
    )
    replay = store.record_post_review_projection(
        case["review_case_id"],
        projection_log_file_path=str(event_log_path),
    )

    assert receipt["projection_id"] == replay["projection_id"]
    assert TransferSealStore(db_path).pending_post_review_projections() == []
    with store._connect() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM transfer_post_review_projection_receipts"
        ).fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(
                "UPDATE transfer_post_review_projection_receipts "
                "SET event_type=event_type"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM transfer_post_review_projection_receipts")


def test_post_review_projection_recovers_csv_append_crash_without_duplicate(
    tmp_path,
):
    event_log_path = tmp_path / "events.csv"
    store = TransferSealStore(tmp_path / "post-review-crash.db")
    prepared = store.prepare(
        master_label="MASTER-POST-REVIEW-CRASH",
        source_identity={"source_bundle_id": SOURCE},
        item_id=ITEM,
        operator="tester",
        scanned_barcodes=["BC-1"],
        relay_log_file_path=str(event_log_path),
    )
    store.record_error(
        prepared["intent_id"],
        TransferSealError(
            "VERSION_CONFLICT",
            "source changed concurrently",
            status_code=409,
        ),
    )
    original_record = store.record_post_review_projection
    record_calls = 0

    def crash_once(*args, **kwargs):
        nonlocal record_calls
        record_calls += 1
        if record_calls == 1:
            raise OSError("crash after CSV append")
        return original_record(*args, **kwargs)

    store.record_post_review_projection = crash_once
    sync_reasons = []
    app = ContainerAudit.__new__(ContainerAudit)
    app.worker_name = "tester"
    app.transfer_seal_coordinator = type(
        "Coordinator",
        (),
        {"store": store},
    )()
    app._trigger_session_direct_sync = sync_reasons.append

    with pytest.raises(OSError, match="crash after CSV append"):
        app._project_transfer_post_review_for_intent(prepared["intent_id"])

    restarted = ContainerAudit.__new__(ContainerAudit)
    restarted.worker_name = "tester"
    restarted.transfer_seal_coordinator = app.transfer_seal_coordinator
    restarted._trigger_session_direct_sync = sync_reasons.append
    assert restarted._drain_transfer_post_review_projections() == 1

    with open(event_log_path, newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["event"] for row in rows] == ["POST_REVIEW_REQUIRED"]
    detail = json.loads(rows[0]["details"])
    assert detail["idempotency_key"].startswith("post-review:")
    assert store.pending_post_review_projections() == []
    assert sync_reasons == ["POST_REVIEW_REQUIRED"]


def test_legacy_without_exact_configuration_keeps_exchange_available(tmp_path):
    app = ContainerAudit.__new__(ContainerAudit)
    app.transfer_seal_coordinator = TransferSealCoordinator(
        TransferSealStore(tmp_path / "legacy.db"), None
    )

    assert app._exact_transfer_exchange_blocked() is False


def test_configured_exact_client_blocks_exchange_before_first_history(tmp_path):
    coordinator = TransferSealCoordinator(TransferSealStore(tmp_path / "configured.db"), object())
    app = ContainerAudit.__new__(ContainerAudit)
    app.transfer_seal_coordinator = coordinator

    assert app._exact_transfer_exchange_blocked() is True
