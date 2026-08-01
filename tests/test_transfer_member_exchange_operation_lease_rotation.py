from __future__ import annotations

import json
import sqlite3
from copy import deepcopy

import pytest

from Container_Audit import ContainerAudit, TraySession
from operation_lease_fixtures import signed_transfer_artifact
from terminal_operation_lease import (
    OperationLeaseError,
    OperationLeaseManager,
    OperationLeaseStore,
    PinnedOperationLeaseKeyring,
    ROTATION_REQUEST_CONTRACT_VERSION,
    ROTATION_RESULT_CONTRACT_VERSION,
    TRANSFER_OPERATION,
    utc_text,
)
from test_transfer_seal import (
    ITEM,
    SCOPE,
    _fields_from_compact_qr,
    _resolved_work_group_phs2,
)
from transfer_member_exchange import (
    CENTRAL_ACKED_ROTATION_PENDING,
    EXCHANGE_CAPABILITY_ID,
    GOOD_SOURCE_CONTRACT_VERSION,
    GOOD_SOURCE_RESOLVER_PATH,
    ROTATION_CAPABILITY_ID,
    TransferMemberExchangeCoordinator,
    TransferMemberExchangeStore,
    _empty_membership_hash,
    _matches_exact_member_map,
)
from transfer_seal import (
    CONTRACT_VERSION,
    TransferSealError,
    _deterministic_id,
    _sha256,
    membership_hash,
    transfer_operation_lease_binding,
    validate_compact_phs2_preflight,
)


OLD_UNIT = "unit-001"
NEW_UNIT = "unit-new-001"
OLD_BARCODE = f"{ITEM}-SERIAL-001"
NEW_BARCODE = f"{ITEM}-SERIAL-NEW"
TARGET_BUNDLE = "PHS-SERVER-001"
DONOR_BUNDLE = "PHS-DONOR-ROTATION"
L1 = "operation-lease-rotation-l1"
L2 = "operation-lease-rotation-l2"


def test_two_pair_successor_member_map_rejects_swapped_new_barcodes():
    expected = {
        "unit-new-001": f"{ITEM}-SERIAL-NEW-001",
        "unit-new-002": f"{ITEM}-SERIAL-NEW-002",
    }
    swapped = [
        {
            "unit_id": "unit-new-001",
            "normalized_barcode": expected["unit-new-002"],
        },
        {
            "unit_id": "unit-new-002",
            "normalized_barcode": expected["unit-new-001"],
        },
    ]

    assert not _matches_exact_member_map(swapped, expected)


def test_two_pair_successor_member_map_accepts_exact_new_barcodes():
    expected = {
        "unit-new-001": f"{ITEM}-SERIAL-NEW-001",
        "unit-new-002": f"{ITEM}-SERIAL-NEW-002",
    }
    exact = [
        {
            "unit_id": unit_id,
            "normalized_barcode": barcode,
        }
        for unit_id, barcode in reversed(expected.items())
    ]

    assert _matches_exact_member_map(exact, expected)


def _replace_exact(value):
    if isinstance(value, dict):
        return {key: _replace_exact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_exact(item) for item in value]
    return {OLD_UNIT: NEW_UNIT, OLD_BARCODE: NEW_BARCODE}.get(value, value)


def _updated_snapshot(before):
    snapshot = _replace_exact(deepcopy(before))
    source = snapshot["work_group_source"]
    for member in source["members"]:
        if member["unit_id"] == NEW_UNIT:
            member["inbound_iin"] = "ORIGIN-IIN-NEW"
            member["current_inbound_iin"] = source["source_iin"]
    member_ids = list(source["member_ids"])
    barcodes = [row["normalized_barcode"] for row in source["members"]]
    group_proofs = [
        snapshot["phs_work_group"],
        snapshot["phs_label_resolution"]["scanned_label"],
        *snapshot["phs_label_resolution"]["effective_labels"],
    ]
    for group in group_proofs:
        group["membership_hash"] = membership_hash(member_ids)
        group["group_entity_version"] += 1
        group["membership_version"] += 1
    source["membership_hash"] = membership_hash(member_ids)
    source["barcode_membership_hash"] = membership_hash(barcodes)
    for bundle in source["source_bundles"]:
        bundle["source_membership_hash"] = membership_hash(
            bundle["source_member_ids"]
        )
        bundle["selected_membership_hash"] = membership_hash(
            bundle["selected_member_ids"]
        )
        if bundle["bundle_id"] == TARGET_BUNDLE:
            bundle["entity_version"] += 1

    group = snapshot["phs_work_group"]
    versions = dict(source["entity_versions"])
    versions[f"phs_work_group:{group['group_id']}"] += 1
    versions[f"phs_work_membership:{group['group_id']}"] += 1
    versions[f"bundle:{TARGET_BUNDLE}"] += 1
    old_transfer_id = source["transfer_bundle_id"]
    versions.pop(f"bundle:{old_transfer_id}")
    transfer_id = _deterministic_id(
        "TRANSFER",
        {
            "group_id": group["group_id"],
            "label_id": group["label_id"],
            "member_ids": sorted(member_ids),
        },
    )
    source["transfer_bundle_id"] = transfer_id
    source["transfer_external_label"] = transfer_id
    versions[f"bundle:{transfer_id}"] = 0
    source["entity_versions"] = versions
    snapshot["entity_versions"] = dict(versions)
    topology_hash = _sha256(
        {
            "phs_work_group": group,
            "source_bundles": source["source_bundles"],
            "remainder_cover_groups": source["remainder_cover_groups"],
            "source_iin": source["source_iin"],
            "barcode_membership_hash": membership_hash(barcodes),
            "transfer_bundle_id": transfer_id,
        }
    )
    source["topology_hash"] = topology_hash
    snapshot["topology_hash"] = topology_hash
    return snapshot


def _refresh_topology(snapshot):
    source = snapshot["work_group_source"]
    barcodes = [row["normalized_barcode"] for row in source["members"]]
    topology_hash = _sha256(
        {
            "phs_work_group": snapshot["phs_work_group"],
            "source_bundles": source["source_bundles"],
            "remainder_cover_groups": source["remainder_cover_groups"],
            "source_iin": source["source_iin"],
            "barcode_membership_hash": membership_hash(barcodes),
            "transfer_bundle_id": source["transfer_bundle_id"],
        }
    )
    source["topology_hash"] = topology_hash
    snapshot["topology_hash"] = topology_hash
    return snapshot


def _mismatch_target_bundle_version(snapshot):
    key = f"bundle:{TARGET_BUNDLE}"
    snapshot["entity_versions"][key] += 1
    snapshot["work_group_source"]["entity_versions"][key] += 1
    for source in snapshot["work_group_source"]["source_bundles"]:
        if source["bundle_id"] == TARGET_BUNDLE:
            source["entity_version"] += 1
    return _refresh_topology(snapshot)


def _mismatch_unaffected_source_version(snapshot):
    source_id = "PHS-SERVER-002"
    key = f"bundle:{source_id}"
    snapshot["entity_versions"][key] += 1
    snapshot["work_group_source"]["entity_versions"][key] += 1
    for source in snapshot["work_group_source"]["source_bundles"]:
        if source["bundle_id"] == source_id:
            source["entity_version"] += 1
    return _refresh_topology(snapshot)


def _mismatch_work_group_version(snapshot):
    group_id = snapshot["phs_work_group"]["group_id"]
    key = f"phs_work_group:{group_id}"
    snapshot["entity_versions"][key] += 1
    snapshot["work_group_source"]["entity_versions"][key] += 1
    for group in (
        snapshot["phs_work_group"],
        snapshot["phs_label_resolution"]["scanned_label"],
        *snapshot["phs_label_resolution"]["effective_labels"],
    ):
        group["group_entity_version"] += 1
    return _refresh_topology(snapshot)


def _mismatch_source_partitions(snapshot):
    sources = {
        source["bundle_id"]: source
        for source in snapshot["work_group_source"]["source_bundles"]
    }
    partitions = {
        TARGET_BUNDLE: ["unit-002", "unit-003"],
        "PHS-SERVER-002": [NEW_UNIT, "unit-004"],
    }
    for bundle_id, member_ids in partitions.items():
        source = sources[bundle_id]
        for prefix in ("source", "selected"):
            source[f"{prefix}_member_ids"] = list(member_ids)
            source[f"{prefix}_member_count"] = len(member_ids)
            source[f"{prefix}_membership_hash"] = membership_hash(member_ids)
    return _refresh_topology(snapshot)


def _mismatch_accounting_iin(snapshot):
    source = snapshot["work_group_source"]
    source["source_iin"] = "IIN-ALTERED"
    for member in source["members"]:
        member["current_inbound_iin"] = "IIN-ALTERED"
    for bundle in source["source_bundles"]:
        bundle["accounting_inbound_iin"] = "IIN-ALTERED"
    return _refresh_topology(snapshot)


def _mismatch_retained_member_provenance(snapshot):
    for member in snapshot["work_group_source"]["members"]:
        if member["unit_id"] == "unit-002":
            member["inbound_iin"] = "ORIGIN-ALTERED"
    return _refresh_topology(snapshot)


def _mismatch_new_member_provenance(snapshot):
    for member in snapshot["work_group_source"]["members"]:
        if member["unit_id"] == NEW_UNIT:
            member["inbound_iin"] = "ORIGIN-ALTERED"
    return _refresh_topology(snapshot)


def _target_response(snapshot):
    result = deepcopy(snapshot)
    source = snapshot["work_group_source"]
    selected = source["members"][:2]
    member_ids = [row["unit_id"] for row in selected]
    barcodes = [row["normalized_barcode"] for row in selected]
    result["bundle"] = {
        "authority_scope_id": SCOPE,
        "authority_epoch": 4,
        "ledger_plane": snapshot["ledger_plane"],
        "plane_epoch": snapshot["plane_epoch"],
        "bundle_id": TARGET_BUNDLE,
        "bundle_role": "TRANSFER_SOURCE",
        "bundle_type": "PHS",
        "bundle_state": "AVAILABLE",
        "item_id": ITEM,
        "uom": "EA",
        "source_iin": source["source_iin"],
        "current_location": "PHS_GOOD",
        "entity_version": 4,
        "member_ids": member_ids,
        "member_count": len(member_ids),
        "membership_hash": membership_hash(member_ids),
        "barcode_member_count": len(barcodes),
        "barcode_membership_hash": membership_hash(barcodes),
        "members": [
            {
                **row,
                "unit_state": "CONSUMED",
                "location_code": "PHS_GOOD",
            }
            for row in selected
        ],
    }
    return result


def _good_response(snapshot):
    source_iin = snapshot["work_group_source"]["source_iin"]
    member = {
        "unit_id": NEW_UNIT,
        "normalized_barcode": NEW_BARCODE,
        "inbound_iin": "ORIGIN-IIN-NEW",
        "current_inbound_iin": source_iin,
        "item_id": ITEM,
        "uom": "EA",
        "unit_state": "CONSUMED",
        "location_code": "PHS_GOOD",
    }
    bundle = {
        "bundle_id": DONOR_BUNDLE,
        "bundle_type": "PHS",
        "bundle_state": "AVAILABLE",
        "inbound_iin": source_iin,
        "item_id": ITEM,
        "uom": "EA",
        "current_location": "PHS_GOOD",
        "entity_version": 7,
        "member_ids": [NEW_UNIT],
        "member_count": 1,
        "membership_hash": membership_hash([NEW_UNIT]),
        "members": [member],
    }
    return {
        "contract_version": GOOD_SOURCE_CONTRACT_VERSION,
        "candidate_count": 1,
        "authority_scope_id": SCOPE,
        "authority_epoch": 4,
        "ledger_plane": snapshot["ledger_plane"],
        "plane_epoch": snapshot["plane_epoch"],
        "unit_id": NEW_UNIT,
        "normalized_barcode": NEW_BARCODE,
        "inbound_iin": source_iin,
        "item_id": ITEM,
        "uom": "EA",
        "unit": {
            **member,
            "state": "CONSUMED",
            "current_location": "PHS_GOOD",
            "entity_version": 3,
        },
        "source_bundle_id": DONOR_BUNDLE,
        "source_bundle_entity_version": 7,
        "source_bundle": bundle,
        "replacement_evidence": {
            "new_unit_id": NEW_UNIT,
            "new_source_bundle_id": DONOR_BUNDLE,
            "expected_source_bundle_version": 7,
            "source_member_ids": [NEW_UNIT],
            "source_membership_hash": membership_hash([NEW_UNIT]),
            "inbound_iin": source_iin,
            "item_id": ITEM,
            "uom": "EA",
        },
    }


def _capabilities():
    replacement = {
        "enabled": True,
        "command_type": "REPLACE_BUNDLE_MEMBERS",
        "resolver_contract_version": GOOD_SOURCE_CONTRACT_VERSION,
        "resolver_path": GOOD_SOURCE_RESOLVER_PATH,
        "max_pairs": 2,
        "atomic": True,
        "two_bundle_cas": True,
        "sealed_transfer_package": False,
        "replacement_source_bundle_cardinality": "EXACTLY_ONE_ACTIVE_MEMBER",
        "multi_member_source_policy": "REJECT_STALE_PHYSICAL_LABEL",
        "multi_member_source_error_code": "REPLACEMENT_SOURCE_NOT_SINGLETON",
        "target_label_action": "RETAIN_IDENTITY_LABEL",
        "target_label_identity_remains_valid": True,
        "target_label_membership_bound": False,
    }
    rotation = {
        "enabled": True,
        "command_type": "REPLACE_BUNDLE_MEMBERS",
        "request_contract_version": ROTATION_REQUEST_CONTRACT_VERSION,
        "result_contract_version": ROTATION_RESULT_CONTRACT_VERSION,
        "predecessor_operation": TRANSFER_OPERATION,
        "successor_operation": TRANSFER_OPERATION,
        "atomic": True,
        "lost_ack_replay": "STORED_COMMAND_RECEIPT",
    }
    return {
        "capability_ids": [EXCHANGE_CAPABILITY_ID, ROTATION_CAPABILITY_ID],
        "capabilities": {
            EXCHANGE_CAPABILITY_ID: replacement,
            ROTATION_CAPABILITY_ID: rotation,
        },
    }


class _RotationClient:
    def __init__(self, before, after, *, lose_first_response=False, device_id="DEVICE-01"):
        self.before = before
        self.after = after
        self.device_id = device_id
        self.source_host_id = "HOST-01"
        self.authority_scope_id = SCOPE
        self.lose_first_response = lose_first_response
        self.calls = []
        self.posts = 0
        self.posted_commands = []
        self.receipt = None

    def get_capabilities(self):
        self.calls.append("capabilities")
        return _capabilities()

    def resolve_source(self, _identity):
        self.calls.append("resolve_source")
        return _target_response(self.before)

    def resolve_good_source(self, *, authority_scope_id, barcode):
        self.calls.append("resolve_good_source")
        assert (authority_scope_id, barcode) == (SCOPE, NEW_BARCODE)
        return _good_response(self.before)

    def _receipt(self, command):
        payload = command["payload"]
        rotation_request = payload["operation_lease_rotation"]
        successor_artifact, _claims = signed_transfer_artifact(
            self.after,
            scan_payload=self.before["phs_work_group"]["scan_payload"],
            device_id=self.device_id,
            source_host_id=self.source_host_id,
            authority_scope_id=SCOPE,
            fence=2,
            lease_id=L2,
        )
        expected_after = _updated_snapshot(self.before)
        before_group = self.before["phs_work_group"]
        after_group = expected_after["phs_work_group"]
        members = [NEW_UNIT, "unit-002"]
        barcodes = [NEW_BARCODE, f"{ITEM}-SERIAL-002"]
        receipt_id = "receipt-rotation-1"
        return {
            "receipt_id": receipt_id,
            "contract_version": CONTRACT_VERSION,
            "command_type": "REPLACE_BUNDLE_MEMBERS",
            "status": "COMMITTED",
            "authority_scope_id": SCOPE,
            "authority_epoch": 4,
            "resolved_ledger_plane": self.before["ledger_plane"],
            "resolved_plane_epoch": self.before["plane_epoch"],
            "committed_at": utc_text(),
            "event_ids": ["event-rotation-1"],
            "outbox_ids": ["outbox-rotation-1"],
            "entity_versions": {
                f"bundle:{TARGET_BUNDLE}": 5,
                f"bundle:{DONOR_BUNDLE}": 8,
                f"bundle:{payload['damage_bundle_id']}": 1,
            },
            "data": {
                "idempotency_key": command["idempotency_key"],
                "target_bundle_id": TARGET_BUNDLE,
                "target_bundle_type": "PHS",
                "target_location": "PHS_GOOD",
                "member_ids": members,
                "members": [
                    {"unit_id": NEW_UNIT, "normalized_barcode": NEW_BARCODE},
                    {
                        "unit_id": "unit-002",
                        "normalized_barcode": f"{ITEM}-SERIAL-002",
                    },
                ],
                "member_count": 2,
                "membership_hash": membership_hash(members),
                "normalized_barcodes": barcodes,
                "barcode_membership_hash": membership_hash(barcodes),
                "pairs": payload["pairs"],
                "pair_count": 1,
                "sources": [
                    {
                        "source_bundle_id": DONOR_BUNDLE,
                        "source_version_before": 7,
                        "source_version_after": 8,
                        "source_member_ids_before": [NEW_UNIT],
                        "source_members_before": [
                            {
                                "unit_id": NEW_UNIT,
                                "normalized_barcode": NEW_BARCODE,
                            }
                        ],
                        "source_member_count_before": 1,
                        "source_membership_hash_before": membership_hash([NEW_UNIT]),
                        "source_normalized_barcodes_before": [NEW_BARCODE],
                        "source_barcode_membership_hash_before": membership_hash(
                            [NEW_BARCODE]
                        ),
                        "selected_member_ids": [NEW_UNIT],
                        "selected_members": [
                            {
                                "unit_id": NEW_UNIT,
                                "normalized_barcode": NEW_BARCODE,
                            }
                        ],
                        "remainder_member_ids": [],
                        "remainder_members": [],
                        "remainder_member_count": 0,
                        "remainder_membership_hash": _empty_membership_hash(),
                        "remainder_normalized_barcodes": [],
                        "remainder_barcode_membership_hash": _empty_membership_hash(),
                        "source_bundle_state_after": "CONSUMED",
                    }
                ],
                "damage_bundle_id": payload["damage_bundle_id"],
                "damage_member_ids": [OLD_UNIT],
                "damage_members": [
                    {"unit_id": OLD_UNIT, "normalized_barcode": OLD_BARCODE}
                ],
                "damage_membership_hash": membership_hash([OLD_UNIT]),
                "damage_location": "PROCESS_DAMAGE_HOLD",
                "movement_ids": ["movement-old", "movement-new"],
                "requires_reseal": False,
                "target_label_action": "RETAIN_IDENTITY_LABEL",
                "target_label_identity_remains_valid": True,
                "target_label_membership_bound": False,
                "replacement_source_bundle_cardinality": "EXACTLY_ONE_ACTIVE_MEMBER",
                "multi_member_source_policy": "REJECT_STALE_PHYSICAL_LABEL",
                "phs_work_group_replacement": {
                    "installed": True,
                    "target_group": {
                        "role": "TARGET",
                        "bundle_id": TARGET_BUNDLE,
                        "group_id": before_group["group_id"],
                        "member_count_before": before_group["member_count"],
                        "member_count_after": after_group["member_count"],
                        "membership_hash_before": before_group[
                            "membership_hash"
                        ],
                        "membership_hash_after": after_group["membership_hash"],
                        "membership_version_before": before_group[
                            "membership_version"
                        ],
                        "membership_version_after": after_group[
                            "membership_version"
                        ],
                        "entity_version_before": before_group[
                            "group_entity_version"
                        ],
                        "entity_version_after": after_group[
                            "group_entity_version"
                        ],
                    },
                    "donor_groups": [
                        {
                            "role": "DONOR",
                            "bundle_id": DONOR_BUNDLE,
                            "group_id": "PHSG-DONOR-ROTATION",
                            "state_after": "CANCELLED",
                        }
                    ],
                },
                "atomic": True,
                "operation_lease_rotation": {
                    "contract_version": ROTATION_RESULT_CONTRACT_VERSION,
                    "predecessor": {
                        "lease_id": L1,
                        "status": "CONSUMED",
                        "fence": 1,
                        "operation_result_id": receipt_id,
                        "consumed_at": utc_text(),
                    },
                    "successor": {
                        "issue_idempotency_key": rotation_request[
                            "successor_issue_idempotency_key"
                        ],
                        "artifact": successor_artifact,
                    },
                },
            },
        }

    def replace_bundle_members(self, command):
        self.calls.append("replace_bundle_members")
        self.posts += 1
        self.posted_commands.append(deepcopy(command))
        if self.receipt is None:
            self.receipt = self._receipt(command)
        if self.lose_first_response and self.posts == 1:
            raise TransferSealError(
                "HTTP_500",
                "response lost after commit",
                status_code=500,
                retryable=True,
                committed=None,
            )
        return deepcopy(self.receipt)

    def get_receipt(self, authority_scope_id, idempotency_key):
        raise AssertionError(
            "rotation recovery must use the same machine-authenticated POST"
        )


def _runtime(
    tmp_path,
    *,
    lose_first_response=False,
    device_id="DEVICE-01",
    successor_snapshot_mutator=None,
    source_mode="merge",
):
    before = _resolved_work_group_phs2(mode=source_mode)
    after = _updated_snapshot(before)
    if successor_snapshot_mutator is not None:
        after = successor_snapshot_mutator(after)
    scan_payload = before["phs_work_group"]["scan_payload"]
    client = _RotationClient(
        before,
        after,
        lose_first_response=lose_first_response,
        device_id=device_id,
    )
    db_path = tmp_path / "transfer-seal.db"
    manager = OperationLeaseManager(
        OperationLeaseStore(db_path),
        PinnedOperationLeaseKeyring(tmp_path / "operation-lease-keyring.json"),
    )
    preflight = validate_compact_phs2_preflight(
        _fields_from_compact_qr(scan_payload), before
    )
    artifact, _claims = signed_transfer_artifact(
        before,
        scan_payload=scan_payload,
        device_id="DEVICE-01",
        source_host_id="HOST-01",
        authority_scope_id=SCOPE,
        fence=1,
        lease_id=L1,
    )
    issue_request = {
        "authority_scope_id": SCOPE,
        "operation": TRANSFER_OPERATION,
        "scan_payload": scan_payload,
    }
    issue_key = manager.issue_idempotency_key(
        device_id="DEVICE-01",
        source_host_id="HOST-01",
        authority_scope_id=SCOPE,
        scan_payload=scan_payload,
    )
    binding = transfer_operation_lease_binding(
        client=_RotationClient(before, after),
        scan_payload=scan_payload,
        preflight=preflight,
        operation_snapshot=before,
        site_id="SITE-01",
    )
    manager.accept_authenticated(
        artifact=artifact,
        expected=binding,
        issue_request=issue_request,
        issue_idempotency_key=issue_key,
    )
    coordinator = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(db_path), client, manager
    )
    return coordinator, client, manager, before


def _prepare(coordinator, before):
    scan_payload = before["phs_work_group"]["scan_payload"]
    return coordinator.prepare(
        master_label=scan_payload,
        master_label_fields=_fields_from_compact_qr(scan_payload),
        item_id=ITEM,
        operator="tester",
        old_barcodes=[OLD_BARCODE],
        new_barcodes=[NEW_BARCODE],
        operation_lease_id=L1,
    )


def test_rotation_key_and_signed_predecessor_are_durable_before_network(tmp_path):
    coordinator, client, _manager, before = _runtime(tmp_path)

    prepared = _prepare(coordinator, before)

    assert client.calls == []
    row = coordinator.store.load(prepared.intent_id)
    key = str(row["successor_issue_idempotency_key"])
    predecessor = json.loads(row["predecessor_evidence_json"])
    assert key.startswith("container-operation-lease-rotation:")
    assert predecessor["lease_id"] == L1
    assert predecessor["fence"] == 1
    replay = _prepare(coordinator, before)
    assert replay.intent_id == prepared.intent_id
    assert coordinator.store.load(prepared.intent_id)[
        "successor_issue_idempotency_key"
    ] == key
    assert client.calls == []


def test_lost_ack_restart_reposts_same_command_and_atomically_rotates_l1_to_l2(
    tmp_path,
):
    coordinator, client, manager, before = _runtime(
        tmp_path, lose_first_response=True
    )
    prepared = _prepare(coordinator, before)

    first = coordinator.attempt(prepared.intent_id)

    assert first.status == "RETRY_WAIT"
    assert client.posts == 1
    command = json.loads(coordinator.store.load(prepared.intent_id)["command_json"])
    rotation_request = command["payload"]["operation_lease_rotation"]
    assert set(rotation_request) == {
        "contract_version",
        "predecessor",
        "successor_issue_idempotency_key",
    }
    restarted = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(coordinator.store.db_path), client, manager
    )

    recovered = restarted.attempt(prepared.intent_id)

    assert recovered.status == "ACKED"
    assert recovered.local_apply_status == "PENDING"
    assert (
        recovered.operation_lease_rotation_state
        == CENTRAL_ACKED_ROTATION_PENDING
    )
    assert client.posts == 2
    assert client.posted_commands[0] == client.posted_commands[1]
    assert json.loads(
        restarted.store.load(prepared.intent_id)["receipt_json"]
    ) == client.receipt
    assert recovered.predecessor_operation_lease_id == L1
    assert recovered.successor_operation_lease_id == L2
    assert restarted.ensure_local_rotation(prepared.intent_id) == L2
    assert restarted.ensure_local_rotation(prepared.intent_id) == L2
    assert manager.store.state(L1) == "ROTATED"
    assert manager.store.state(L2) == "PREFETCHED"
    rotation = manager.store.rotation(prepared.intent_id)
    assert rotation is not None
    assert rotation["predecessor_lease_id"] == L1
    assert rotation["successor_lease_id"] == L2
    with manager.store._connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM terminal_operation_lease_rotations"
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT COUNT(*) FROM terminal_operation_lease_artifacts"
        ).fetchone()[0] == 2


@pytest.mark.parametrize(
    "mutator",
    (
        _mismatch_target_bundle_version,
        _mismatch_unaffected_source_version,
        _mismatch_work_group_version,
        _mismatch_source_partitions,
        _mismatch_accounting_iin,
        _mismatch_retained_member_provenance,
        _mismatch_new_member_provenance,
    ),
    ids=(
        "target-bundle",
        "unaffected-source",
        "work-group",
        "source-partition",
        "accounting-iin",
        "retained-member-provenance",
        "new-member-provenance",
    ),
)
def test_signed_successor_version_mismatch_is_fail_closed(tmp_path, mutator):
    coordinator, client, manager, before = _runtime(
        tmp_path,
        successor_snapshot_mutator=mutator,
    )
    prepared = _prepare(coordinator, before)

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert (
        result.error_code
        == "OPERATION_LEASE_ROTATION_SUCCESSOR_VERSION_MISMATCH"
    )
    assert client.posts == 1
    row = coordinator.store.load(prepared.intent_id)
    assert row["receipt_json"] is None
    assert manager.store.state(L1) == "PREFETCHED"
    with pytest.raises(OperationLeaseError):
        manager.store.load(L2)
    assert manager.store.rotation(prepared.intent_id) is None

    coordinator.attempt(prepared.intent_id)
    assert client.posts == 1


def test_rotation_rejects_command_target_cas_newer_than_signed_predecessor(
    tmp_path,
):
    coordinator, client, manager, signed_before = _runtime(tmp_path)
    current = deepcopy(signed_before)
    target_key = f"bundle:{TARGET_BUNDLE}"
    current_versions = dict(current["entity_versions"])
    current_versions[target_key] += 1
    current["entity_versions"] = dict(current_versions)
    current["work_group_source"]["entity_versions"] = dict(current_versions)
    for source in current["work_group_source"]["source_bundles"]:
        if source["bundle_id"] == TARGET_BUNDLE:
            source["entity_version"] += 1
    current = _refresh_topology(current)
    client.before = current
    client.after = _updated_snapshot(current)

    def resolve_current(_identity):
        response = _target_response(current)
        response["bundle"]["entity_version"] = current["entity_versions"][target_key]
        return response

    client.resolve_source = resolve_current
    original_receipt = client._receipt

    def receipt_with_current_cas(command):
        receipt = original_receipt(command)
        receipt["entity_versions"][target_key] = (
            current["entity_versions"][target_key] + 1
        )
        return receipt

    client._receipt = receipt_with_current_cas
    prepared = _prepare(coordinator, signed_before)

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "OPERATOR_REVIEW"
    assert (
        result.error_code
        == "OPERATION_LEASE_ROTATION_SUCCESSOR_VERSION_MISMATCH"
    )
    assert coordinator.store.load(prepared.intent_id)["receipt_json"] is None
    assert manager.store.state(L1) == "PREFETCHED"
    with pytest.raises(OperationLeaseError):
        manager.store.load(L2)


def test_rotation_accepts_exact_split_source_partition(tmp_path):
    coordinator, client, manager, before = _runtime(tmp_path, source_mode="split")
    target_source = next(
        source
        for source in before["work_group_source"]["source_bundles"]
        if source["bundle_id"] == TARGET_BUNDLE
    )
    before_member_ids = list(target_source["source_member_ids"])

    def barcode_for(unit_id):
        if unit_id == NEW_UNIT:
            return NEW_BARCODE
        return f"{ITEM}-SERIAL-{unit_id.rsplit('-', 1)[-1]}"

    def resolve_split_source(_identity):
        response = _target_response(before)
        barcodes = [barcode_for(unit_id) for unit_id in before_member_ids]
        prototype = dict(before["work_group_source"]["members"][0])
        response["bundle"].update(
            {
                "entity_version": target_source["entity_version"],
                "member_ids": before_member_ids,
                "member_count": len(before_member_ids),
                "membership_hash": membership_hash(before_member_ids),
                "barcode_member_count": len(barcodes),
                "barcode_membership_hash": membership_hash(barcodes),
                "members": [
                    {
                        **prototype,
                        "unit_id": unit_id,
                        "normalized_barcode": barcode,
                        "unit_state": "CONSUMED",
                        "location_code": "PHS_GOOD",
                    }
                    for unit_id, barcode in zip(
                        before_member_ids, barcodes, strict=True
                    )
                ],
            }
        )
        return response

    client.resolve_source = resolve_split_source
    original_receipt = client._receipt

    def receipt_with_full_split_target(command):
        receipt = original_receipt(command)
        member_ids = [
            NEW_UNIT if unit_id == OLD_UNIT else unit_id
            for unit_id in before_member_ids
        ]
        barcodes = [barcode_for(unit_id) for unit_id in member_ids]
        receipt["data"].update(
            {
                "member_ids": member_ids,
                "members": [
                    {"unit_id": unit_id, "normalized_barcode": barcode}
                    for unit_id, barcode in zip(member_ids, barcodes, strict=True)
                ],
                "member_count": len(member_ids),
                "membership_hash": membership_hash(member_ids),
                "normalized_barcodes": barcodes,
                "barcode_membership_hash": membership_hash(barcodes),
            }
        )
        return receipt

    client._receipt = receipt_with_full_split_target
    prepared = _prepare(coordinator, before)

    result = coordinator.attempt(prepared.intent_id)

    assert result.status == "ACKED"
    assert coordinator.ensure_local_rotation(prepared.intent_id) == L2
    assert manager.store.state(L1) == "ROTATED"
    assert manager.store.state(L2) == "PREFETCHED"


def test_rotation_sql_failure_rolls_back_both_lease_transitions(tmp_path):
    coordinator, _client, manager, before = _runtime(tmp_path)
    prepared = _prepare(coordinator, before)
    acked = coordinator.attempt(prepared.intent_id)
    assert acked.status == "ACKED"
    with manager.store._connect() as connection:
        connection.execute(
            """CREATE TRIGGER fail_rotation_insert
               BEFORE INSERT ON terminal_operation_lease_rotations
               BEGIN SELECT RAISE(ABORT, 'injected rotation failure'); END"""
        )
        connection.commit()

    with pytest.raises(sqlite3.IntegrityError):
        coordinator.ensure_local_rotation(prepared.intent_id)

    assert manager.store.state(L1) == "PREFETCHED"
    with pytest.raises(OperationLeaseError):
        manager.store.load(L2)
    assert manager.store.rotation(prepared.intent_id) is None


def test_tray_apply_waits_for_rotation_and_recovers_after_save_failure(tmp_path):
    coordinator, _client, manager, before = _runtime(tmp_path)
    prepared = _prepare(coordinator, before)
    attempt = coordinator.attempt(prepared.intent_id)
    assert attempt.status == "ACKED"
    scan_payload = before["phs_work_group"]["scan_payload"]
    old_barcodes = [
        row["normalized_barcode"] for row in before["work_group_source"]["members"]
    ]
    app = ContainerAudit.__new__(ContainerAudit)
    app.transfer_member_exchange_coordinator = coordinator
    app.current_tray = TraySession(
        master_label_code=scan_payload,
        item_code=ITEM,
        tray_size=len(old_barcodes),
        scanned_barcodes=list(old_barcodes),
        scan_times=[],
        operation_lease_id=L1,
    )
    app._active_transfer_exchange_master_label = scan_payload
    app._save_current_tray_state = lambda: False
    app._log_event = lambda *args, **kwargs: True
    app._redraw_active_tray_scans = lambda: None

    assert app._apply_acked_member_exchange(attempt) is False
    assert app.current_tray.operation_lease_id == L1
    assert app.current_tray.scanned_barcodes == old_barcodes
    assert manager.store.state(L1) == "ROTATED"
    assert manager.store.state(L2) == "PREFETCHED"
    assert coordinator.store.load(prepared.intent_id)["local_apply_status"] == "PENDING"

    app._save_current_tray_state = lambda: True
    app._reconcile_pending_local_member_exchanges()

    assert app.current_tray.operation_lease_id == L2
    assert NEW_BARCODE in app.current_tray.scanned_barcodes
    assert OLD_BARCODE not in app.current_tray.scanned_barcodes
    assert coordinator.store.load(prepared.intent_id)["local_apply_status"] == "APPLIED"


def test_different_terminal_cannot_prepare_rotation_or_make_network_call(tmp_path):
    coordinator, original_client, manager, before = _runtime(tmp_path)
    other_client = _RotationClient(before, _updated_snapshot(before), device_id="DEVICE-OTHER")
    other = TransferMemberExchangeCoordinator(
        TransferMemberExchangeStore(coordinator.store.db_path),
        other_client,
        manager,
    )

    with pytest.raises(TransferSealError) as exc_info:
        _prepare(other, before)

    assert exc_info.value.code == "OPERATION_LEASE_MACHINE_SCOPE_FORBIDDEN"
    assert other_client.calls == []
    assert original_client.calls == []
